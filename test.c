#include "socket_server.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

static void *
_poll(void * ud) {
	struct socket_server *ss = ud;
	union socket_message result;
	for (;;) {
		int type = socket_server_poll(ss, &result);
		switch (type) {
		case SOCKET_EXIT:
			return NULL;
		case SOCKET_DATA:
			printf("message [id=%d] size=%d\n",result.data.id, result.data.size);
			free(result.data.data);
			break;
		case SOCKET_CLOSE:
			printf("close [id=%d]\n",result.close.id);
			break;
		case SOCKET_OPEN:
			printf("open [session=%d id=%d] %s\n",result.open.session,result.open.id,result.open.addr);
			break;
		case SOCKET_ERROR:
			printf("error [session=%d id=%d]\n",result.error.session,result.error.id);
			break;
		}
	}
}

static void
test(struct socket_server *ss) {
	pthread_t pid;
	pthread_create(&pid, NULL, _poll, ss);

	socket_server_connect(ss,"127.0.0.1",80);
	socket_server_listen(ss,"127.0.0.1",8888,32);
	socket_server_bind(ss,1);
	sleep(5);
	socket_server_exit(ss);

	pthread_join(pid, NULL); 
}

int
main() {
	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, 0);

	struct socket_server * ss = socket_server_create();
	test(ss);
	socket_server_release(ss);

	return 0;
}
