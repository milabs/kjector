#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <syscall.h>

long init(void) {
	struct utsname uts;
	uname(&uts);

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) return EINVAL;

	struct sockaddr_in sin = { 0 };
	sin.sin_family = AF_INET;
	sin.sin_port = htons(6666);
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");

	char cmdline[ 256 ], data[ 1024 ];
	FILE *f = fopen("/proc/self/cmdline", "r");
	if (f) {
		size_t n = fread(cmdline, 1, sizeof(cmdline), f);
		if (n) cmdline[n - 1] = 0;
		fclose(f);
	}

	snprintf(data, sizeof(data),
		"[+] injected -- %s -- pid:%d tid:%d cmdline:%s\n",
		 uts.release, getpid(), (int)syscall(SYS_gettid), cmdline);
	sendto(sock, data, strlen(data), 0, (void *)&sin, sizeof(sin));
	close(sock);

	return 0;
}
