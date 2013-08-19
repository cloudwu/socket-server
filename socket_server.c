#include "socket_server.h"
#include "socket_poll.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#define MAX_INFO 128
// MAX_SOCKET will be 2^MAX_SOCKET_P
#define MAX_SOCKET_P 16
#define MAX_EVENT 64
#define MIN_READ_BUFFER 64

#define SOCKET_TYPE_INVALID 0
#define SOCKET_TYPE_LISTEN 1
#define SOCKET_TYPE_CONNECTING 2
#define SOCKET_TYPE_CONNECTED 3
#define SOCKET_TYPE_HALFCLOSE 4
#define SOCKET_TYPE_BIND 5

#define MAX_SOCKET (1<<MAX_SOCKET_P)

struct write_buffer {
	struct write_buffer * next;
	char *ptr;
	int sz;
	void *buffer;
};

struct socket {
	int fd;
	int id;
	int open_session;
	int close_session;
	int type;
	int size;
	struct write_buffer * head;
	struct write_buffer * tail;
};

struct socket_server {
	int server_fd;
	int client_fd;
	poll_fd event_fd;
	int alloc_id;
	int event_n;
	int event_index;
	int session_id;
	struct event ev[MAX_EVENT];
	struct socket slot[MAX_SOCKET];
	char buffer[MAX_INFO];
};

struct request_open {
	int session;
	int port;
	char host[1];
};

struct request_send {
	int id;
	int sz;
	char * buffer;
};

struct request_close {
	int session;
	int id;
};

struct request_listen {
	int session;
	int port;
	int backlog;
	char host[1];
};

struct request_bind {
	int session;
	int fd;
};

struct request_package {
	uint8_t header[8];	// 6 bytes dummy
	union {
		char buffer[256];
		struct request_open open;
		struct request_send send;
		struct request_close close;
		struct request_listen listen;
		struct request_bind bind;
	} u;
};

union sockaddr_all {
	struct sockaddr s;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

#define MALLOC malloc
#define FREE free

struct socket_server * 
socket_server_create() {
	int i;
	int fd[2];
	poll_fd efd = sp_create();
	if (sp_invalid(efd)) {
		fprintf(stderr, "socket-server: create event pool failed.\n");
		return NULL;
	}
	if (socketpair(AF_UNIX,SOCK_STREAM,0,fd)) {
		sp_release(efd);
		fprintf(stderr, "socket-server: create socket pair failed.\n");
		return NULL;
	}
	if (sp_add(efd, fd[0], NULL)) {
		// add server_fd to event poll
		fprintf(stderr, "socket-server: can't add server fd to event pool.\n");
		close(fd[0]);
		close(fd[1]);
		sp_release(efd);
		return NULL;
	}

	struct socket_server *ss = MALLOC(sizeof(*ss));
	ss->event_fd = efd;
	ss->server_fd = fd[0];
	ss->client_fd = fd[1];

	for (i=0;i<MAX_SOCKET;i++) {
		struct socket *s = &ss->slot[i];
		s->type = SOCKET_TYPE_INVALID;
		s->head = NULL;
		s->tail = NULL;
	}
	ss->alloc_id = 0;
	ss->event_n = 0;
	ss->event_index = 0;
	ss->session_id = 0;

	return ss;
}

static void
force_close(struct socket_server *ss, struct socket *s) {
	if (s->type == SOCKET_TYPE_INVALID) {
		return;
	}
	struct write_buffer *wb = s->head;
	while (wb) {
		struct write_buffer *tmp = wb;
		wb = wb->next;
		FREE(tmp->buffer);
		FREE(tmp);
	}
	s->head = s->tail = NULL;
	sp_del(ss->event_fd, s->fd);
	if (s->type != SOCKET_TYPE_BIND) {
		close(s->fd);
	}
	s->type = SOCKET_TYPE_INVALID;
}

void 
socket_server_release(struct socket_server *ss) {
	int i;
	for (i=0;i<MAX_SOCKET;i++) {
		force_close(ss, &ss->slot[i]);
	}
	close(ss->client_fd);
	close(ss->server_fd);
	sp_release(ss->event_fd);
	FREE(ss);
}

static void
block_read(int fd, void * buffer, int sz) {
	char * buf = (char *)buffer;
	for (;;) {
		int n = read(fd, buf, sz);
		if (n < 0) {
			switch (errno) {
			case EINTR:
				continue;
			default:
				fprintf(stderr, "socket-server: ctrl fd error : %d.\n", errno);
				exit(1);
			}
		}
		if (n < sz) {
			buf+=n;
			sz-=n;
		} else {
			return;
		}
	}
}

static struct socket *
new_fd(struct socket_server *ss, int fd) {
	int i;
	for (i=0;i<MAX_SOCKET;i++) {
		int id = ss->alloc_id + i + 1;
		struct socket * s = &ss->slot[id % MAX_SOCKET];
		if (s->type == SOCKET_TYPE_INVALID) {
			if (sp_add(ss->event_fd, fd, s)) {
				return NULL;
			}
			s->id = id;
			s->fd = fd;
			s->size = MIN_READ_BUFFER;
			s->open_session = 0;
			s->close_session = 0;
			assert(s->head == NULL);
			assert(s->tail == NULL);
			ss->alloc_id = id;
			return s;
		}
	}
	return NULL;
}

// return -1 when connecting
static int
open_socket(struct socket_server *ss, struct request_open * request, union socket_message *result) {
	struct socket *ns;
	int status;
	struct addrinfo ai_hints;
	struct addrinfo *ai_list = NULL;
	struct addrinfo *ai_ptr = NULL;
	char port[16];
	sprintf(port, "%d", request->port);
	memset( &ai_hints, 0, sizeof( ai_hints ) );
	ai_hints.ai_family = AF_UNSPEC;
	ai_hints.ai_socktype = SOCK_STREAM;
	ai_hints.ai_protocol = IPPROTO_TCP;

	status = getaddrinfo( request->host, port, &ai_hints, &ai_list );
	if ( status != 0 ) {
		goto _failed;
	}
	int sock= -1;
	for	( ai_ptr = ai_list;	ai_ptr != NULL;	ai_ptr = ai_ptr->ai_next ) {
		sock = socket( ai_ptr->ai_family, ai_ptr->ai_socktype, ai_ptr->ai_protocol );
		if ( sock < 0 ) {
			continue;
		}
		sp_nonblocking(sock);
		status = connect( sock,	ai_ptr->ai_addr, ai_ptr->ai_addrlen	);
		if ( status	!= 0 && errno != EINPROGRESS) {
			close(sock);
			sock = -1;
			continue;
		}
		break;
	}

	if (sock < 0) {
		goto _failed;
	}

	ns = new_fd(ss, sock);
	if (ns == NULL) {
		close(sock);
		goto _failed;
	}

	if(status == 0) {
		ns->type = SOCKET_TYPE_CONNECTED;
		result->open.id = ns->id;
		result->open.session = request->session;
		result->open.fd = sock;
		struct sockaddr * addr = ai_ptr->ai_addr;
		void * sin_addr = (ai_ptr->ai_family == AF_INET) ? (void*)&((struct sockaddr_in *)addr)->sin_addr : (void*)&((struct sockaddr_in6 *)addr)->sin6_addr;
		if (inet_ntop(ai_ptr->ai_family, sin_addr, ss->buffer, sizeof(ss->buffer))) {
			result->open.addr = ss->buffer;
		} else {
			result->open.addr = NULL;
		}
		freeaddrinfo( ai_list );
		return SOCKET_OPEN;
	} else {
		ns->type = SOCKET_TYPE_CONNECTING;
		ns->open_session = request->session;
		sp_write(ss->event_fd, ns->fd, ns, true);
	}

	freeaddrinfo( ai_list );
	return -1;
_failed:
	freeaddrinfo( ai_list );
	result->error.id = 0;
	result->error.session = request->session;
	return SOCKET_ERROR;
}

static int
send_buffer(struct socket_server *ss, struct socket *s, union socket_message *result) {
	while (s->head) {
		struct write_buffer * tmp = s->head;
		for (;;) {
			int sz = write(s->fd, tmp->ptr, tmp->sz);
			if (sz < 0) {
				switch(errno) {
				case EINTR:
					continue;
				case EAGAIN:
					return 0;
				}
				result->close.id = s->id;
				result->close.session = s->close_session;
				force_close(ss,s);
				return SOCKET_CLOSE;
			}
			if (sz != tmp->sz) {
				tmp->ptr += sz;
				tmp->sz -= sz;
				return -1;
			}
			break;
		}
		s->head = tmp->next;
		FREE(tmp->buffer);
		FREE(tmp);
	}
	s->tail = NULL;
	sp_write(ss->event_fd, s->fd, s, false);

	return -1;
}

static int
send_socket(struct socket_server *ss, struct request_send * request, union socket_message *result) {
	int id = request->id;
	struct socket * s = &ss->slot[id % MAX_SOCKET];
	if (s->type == SOCKET_TYPE_INVALID || s->id != id || s->type == SOCKET_TYPE_HALFCLOSE) {
		FREE(request->buffer);
		return -1;
	}
	if (s->head == NULL) {
		int n = write(s->fd, request->buffer, request->sz);
		if (n<0) {
			switch(errno) {
			case EINTR:
			case EAGAIN:
				n = 0;
				break;
			default:
				fprintf(stderr, "socket-server: write to %d (fd=%d) error.",id,s->fd);
				result->close.id = id;
				result->close.session = s->close_session;
				return SOCKET_CLOSE;
			}
		}
		if (n == request->sz) {
			FREE(request->buffer);
			return -1;
		}

		struct write_buffer * buf = MALLOC(sizeof(*buf));
		buf->next = NULL;
		buf->ptr = request->buffer+n;
		buf->sz = request->sz - n;
		buf->buffer = request->buffer;
		s->head = s->tail = buf;

		sp_write(ss->event_fd, s->fd, s, true);
	} else {
		struct write_buffer * buf = MALLOC(sizeof(*buf));
		buf->ptr = request->buffer;
		buf->buffer = request->buffer;
		buf->sz = request->sz;
		assert(s->tail != NULL);
		assert(s->tail->next == NULL);
		buf->next = s->tail->next;
		s->tail->next = buf;
		s->tail = buf;
	}
	return -1;
}

static int
listen_socket(struct socket_server *ss, struct request_listen * request, union socket_message *result) {
	// only support ipv4
	// todo: support ipv6 by getaddrinfo
	uint32_t addr = INADDR_ANY;
	if (request->host[0]) {
		addr=inet_addr(request->host);
	}
	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		result->error.id = 0;
		result->error.session = request->session;

		return SOCKET_ERROR;
	}
	int reuse = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(int))==-1) {
		goto _failed;
	}

	struct sockaddr_in my_addr;
	memset(&my_addr, 0, sizeof(struct sockaddr_in));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(request->port);
	my_addr.sin_addr.s_addr = addr;
	if (bind(listen_fd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
		goto _failed;
	}
	if (listen(listen_fd, request->backlog) == -1) {
		goto _failed;
	}
	struct socket *s = new_fd(ss, listen_fd);
	if (s == NULL) {
		goto _failed;
	}
	s->type = SOCKET_TYPE_LISTEN;
	s->open_session = request->session;
	return -1;
_failed:
	close(listen_fd);
	result->error.id = 0;
	result->error.session = request->session;

	return SOCKET_ERROR;
}

static int
close_socket(struct socket_server *ss, struct request_close *request, union socket_message *result) {
	int id = request->id;
	struct socket * s = &ss->slot[id % MAX_SOCKET];
	if (s->type == SOCKET_TYPE_INVALID || s->id != id) {
		result->close.id = id;
		result->close.session = request->session;
		return SOCKET_CLOSE;
	}
	s->close_session = request->session;
	if (s->head) { 
		int type = send_buffer(ss,s,result);
		if (type != -1)
			return type;
	}
	if (s->head == NULL) {
		force_close(ss,s);
		result->close.id = id;
		result->close.session = request->session;
		return SOCKET_CLOSE;
	}
	s->type = SOCKET_TYPE_HALFCLOSE;

	return -1;
}

static int
bind_socket(struct socket_server *ss, struct request_bind *request, union socket_message *result) {
	struct socket *s = new_fd(ss, request->fd);
	if (s == NULL) {
		result->error.session = request->session;
		result->error.id = 0;
		return SOCKET_ERROR;
	}
	sp_nonblocking(request->fd);
	s->type = SOCKET_TYPE_BIND;
	result->open.id = s->id;
	result->open.session = request->session;
	result->open.fd = request->fd;
	return SOCKET_OPEN;
}

// return type
static int
ctrl_cmd(struct socket_server *ss, union socket_message *result) {
	int fd = ss->server_fd;
	uint8_t header[2];
	block_read(fd, header, sizeof(header));
	int type = header[0];
	int len = header[1];
	char buffer[256];
	// ctrl command only exist in local fd, so don't worry about endian.
	block_read(fd, buffer, len);
	switch (type) {
	case 'B':
		return bind_socket(ss,(struct request_bind *)buffer, result);
	case 'L':
		return listen_socket(ss,(struct request_listen *)buffer, result);
	case 'K':
		return close_socket(ss,(struct request_close *)buffer, result);
	case 'O':
		return open_socket(ss, (struct request_open *)buffer, result);
	case 'X':
		return SOCKET_EXIT;
	case 'D':
		return send_socket(ss, (struct request_send *)buffer, result);
	default:
		fprintf(stderr, "socket-server: Unknown ctrl %c.\n",type);
		return -1;
	};

	return -1;
}

// return -1 (ignore) when error
static int
forward_message(struct socket_server *ss, struct socket *s, union socket_message * result) {
	int sz = s->size;
	char * buffer = MALLOC(sz);
	int n = (int)read(s->fd, buffer, sz);
	if (n<0) {
		FREE(buffer);
		switch(errno) {
		case EINTR:
			break;
		case EAGAIN:
			fprintf(stderr, "socket-server: EAGAIN capture.\n");
			break;
		default:
			// close when error
			result->error.id = s->id;
			result->error.session = 0;
			force_close(ss, s);
			return SOCKET_ERROR;
		}
		return -1;
	}
	if (n==0) {
		FREE(buffer);
		result->close.id = s->id;
		result->close.session = s->close_session;
		force_close(ss, s);
		return SOCKET_CLOSE;
	}

	if (s->type == SOCKET_TYPE_HALFCLOSE) {
		// discard recv data
		return -1;
	}

	if (n == sz) {
		s->size *= 2;
	} else if (sz > MIN_READ_BUFFER && n*2 < sz) {
		s->size /= 2;
	}

	result->data.id = s->id;
	result->data.size = n;
	result->data.data = buffer;
	return SOCKET_DATA;
}

static int
report_connect(struct socket_server *ss, struct socket *s, union socket_message *result) {
	int error;
	socklen_t len = sizeof(error);  
	int code = getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &error, &len);  
	if (code < 0 || error) {  
		result->error.id = s->id;
		result->error.session = s->open_session;
		force_close(ss,s);
		return SOCKET_ERROR;
	} else {
		s->type = SOCKET_TYPE_CONNECTED;
		result->open.session = s->open_session;
		result->open.id = s->id;
		result->open.fd = s->fd;
		sp_write(ss->event_fd, s->fd, s, false);
		union sockaddr_all u;
		socklen_t slen = sizeof(u);
		if (getpeername(s->fd, &u.s, &slen) == 0) {
			void * sin_addr = (u.s.sa_family == AF_INET) ? (void*)&u.v4.sin_addr : (void *)&u.v6.sin6_addr;
			if (inet_ntop(u.s.sa_family, sin_addr, ss->buffer, sizeof(ss->buffer))) {
				result->open.addr = ss->buffer;
				return SOCKET_OPEN;
			}
		}
		result->open.addr = NULL;
		return SOCKET_OPEN;
	}
}

// return 0 when failed
static int
report_accept(struct socket_server *ss, struct socket *s, union socket_message *result) {
	union sockaddr_all u;
	socklen_t len = sizeof(u);
	int client_fd = accept(s->fd, &u.s, &len);
	if (client_fd < 0) {
		return 0;
	}
	sp_nonblocking(client_fd);
	struct socket *ns = new_fd(ss, client_fd);
	if (ns == NULL) {
		close(client_fd);
		return 0;
	}
	ns->type = SOCKET_TYPE_CONNECTED;
	result->open.id = ns->id;
	result->open.session = s->open_session;
	result->open.fd = s->fd;
	result->open.addr = NULL;

	void * sin_addr = (u.s.sa_family == AF_INET) ? (void*)&u.v4.sin_addr : (void *)&u.v6.sin6_addr;
	if (inet_ntop(u.s.sa_family, sin_addr, ss->buffer, sizeof(ss->buffer))) {
		result->open.addr = ss->buffer;
	}

	return 1;
}

// return type
int 
socket_server_poll(struct socket_server *ss, union socket_message * result) {
	for (;;) {
		if (ss->event_index == ss->event_n) {
			ss->event_n = sp_wait(ss->event_fd, ss->ev, MAX_EVENT);
			ss->event_index = 0;
			if (ss->event_n <= 0) {
				return -1;
			}
		}
		struct event *e = &ss->ev[ss->event_index++];
		struct socket *s = e->s;
		if (s == NULL) {
			int type = ctrl_cmd(ss, result);
			if (type != -1)
				return type;
			else
				continue;
		}
		switch (s->type) {
		case SOCKET_TYPE_CONNECTING:
			return report_connect(ss, s, result);
		case SOCKET_TYPE_LISTEN:
			if (report_accept(ss, s, result)) {
				return SOCKET_OPEN;
			} 
			break;
		case SOCKET_TYPE_INVALID:
			fprintf(stderr, "socket-server: invalid socket\n");
			break;
		default:
			if (e->write) {
				int type = send_buffer(ss, s, result);
				if (type == -1)
					break;
				return type;
			}
			if (e->read) {
				int type = forward_message(ss, s, result);
				if (type == -1)
					break;
				return type;
			}
			break;
		}
	}
}

static inline int
allocsession(struct socket_server *ss) {
	return __sync_add_and_fetch(&(ss->session_id), 1);
}

static void
send_request(struct socket_server *ss, struct request_package *request, char type, int len) {
	request->header[6] = (uint8_t)type;
	request->header[7] = (uint8_t)len;
	write(ss->client_fd, &request->header[6], len+2);
}

int 
socket_server_connect(struct socket_server *ss, const char * addr, int port) {
	struct request_package request;
	int len = strlen(addr);
	if (len + sizeof(request.u.open) > sizeof(request.u)) {
		fprintf(stderr, "socket-server : Invalid addr %s.\n",addr);
		return 0;
	}
	int session = allocsession(ss);
	request.u.open.session = session;
	request.u.open.port = port;
	strcpy(request.u.open.host, addr);
	send_request(ss, &request, 'O', sizeof(request.u.open) + len);
	return session;
}

// return -1 when error
int 
socket_server_send(struct socket_server *ss, int id, const void * buffer, int sz) {
	struct socket * s = &ss->slot[id % MAX_SOCKET];
	if (s->id != id || s->type == SOCKET_TYPE_INVALID) {
		return -1;
	}

	struct request_package request;
	request.u.send.id = id;
	request.u.send.sz = sz;
	request.u.send.buffer = (char *)buffer;

	send_request(ss, &request, 'D', sizeof(request.u.send));
	return 0;
}

void
socket_server_exit(struct socket_server *ss) {
	struct request_package request;
	send_request(ss, &request, 'X', 0);
}

int
socket_server_close(struct socket_server *ss, int id) {
	struct request_package request;
	int session = allocsession(ss);
	request.u.close.id = id;
	request.u.close.session = session;
	send_request(ss, &request, 'K', sizeof(request.u.close));
	return session;
}

int 
socket_server_listen(struct socket_server *ss, const char * addr, int port, int backlog) {
	struct request_package request;
	int len = (addr!=NULL) ? strlen(addr) : 0;
	if (len + sizeof(request.u.listen) > sizeof(request.u)) {
		fprintf(stderr, "socket-server : Invalid listen addr %s.\n",addr);
		return 0;
	}
	int session = allocsession(ss);
	request.u.listen.session = session;
	request.u.listen.port = port;
	request.u.listen.backlog = backlog;
	if (len == 0) {
		request.u.listen.host[0] = '\0';
	} else {
		strcpy(request.u.listen.host, addr);
	}
	send_request(ss, &request, 'L', sizeof(request.u.listen) + len);
	return session;
}

int
socket_server_bind(struct socket_server *ss, int fd) {
	struct request_package request;
	int session = allocsession(ss);
	request.u.bind.session = session;
	request.u.bind.fd = fd;
	send_request(ss, &request, 'B', sizeof(request.u.bind));
	return session;
}

