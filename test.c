#include "socket_server.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

static void *
_poll(void * ud) {
	struct socket_server *ss = ud;
	struct socket_message result;
	for (;;) {
		int type = socket_server_poll(ss, &result);
		switch (type) {
		case SOCKET_EXIT:
			return NULL;
		case SOCKET_DATA:
			printf("message [id=%d] size=%d\n",result.id, result.ud);
			free(result.data);
			break;
		case SOCKET_CLOSE:
			printf("close [id=%d]\n",result.id);
			break;
		case SOCKET_OPEN:
			printf("open [id=%d] %s\n",result.id,result.data);
			break;
		case SOCKET_ERROR:
			printf("error [id=%d]\n",result.id);
			break;
		case SOCKET_ACCEPT:
			printf("accept [id=%d %s] from [%d]\n",result.id, result.data, result.ud);
			break;
		}
	}
}

static void
test(struct socket_server *ss) {
	pthread_t pid;
	pthread_create(&pid, NULL, _poll, ss);

	int c = socket_server_connect(ss,"127.0.0.1",80);
	printf("connecting %d\n",c);
	int l = socket_server_listen(ss,"127.0.0.1",8888,32);
	printf("listening %d\n",l);
	int b = socket_server_bind(ss,1);
	printf("binding stdin %d\n",b);
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
