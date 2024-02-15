#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#ifndef ISOLATE_CNAME
#define	ISOLATE_CNAME "www.example.com"
#endif

static char gai_buf[8192];
static struct sockaddr *gai_blocked[32];
static unsigned nblocked = 0;

#define SA4(x) ((struct sockaddr_in*)(x))
#define SADDR4(x) SA4(x)->sin_addr
#define SA6(x) ((struct sockaddr_in6*)(x))
#define SADDR6(x) SA6(x)->sin6_addr


static char*
sa2a(const struct sockaddr *sa, char *buf, size_t n)
{
	unsigned port, d;

	switch (sa->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &SADDR4(sa), buf, n);
		port = SA4(sa)->sin_port;
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &SADDR6(sa), buf, n);
		port = SA6(sa)->sin6_port;
		break;
	default:
		snprintf(buf, n, "AF<%d>", sa->sa_family);
		return buf;
	}

	d = strlen(buf);
	if (d + 2 < n)
		snprintf(buf + d, n - d, ":%u", htons(port));

	return buf;
}

static int is_6to4(const uint16_t *a)
{
	return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0 && a[4] == 0 && a[5] == 0xffff;
}

static int
lookup_addr(const struct sockaddr *sa)
{
	unsigned addrlen;
	const void *sa_addr;
	unsigned family;

	switch (sa->sa_family) {
	case AF_INET:
		family = AF_INET;
		sa_addr = &SADDR4(sa);
		addrlen = sizeof(struct in_addr);
		break;
	case AF_INET6:
		if (is_6to4(SA6(sa)->sin6_addr.s6_addr16)) {
			family = AF_INET;
			sa_addr = SADDR6(sa).s6_addr16 + 6;
			addrlen = sizeof(struct in_addr);
		} else {
			sa_addr = &SADDR6(sa);
			addrlen = sizeof(struct in6_addr);
		}
		break;
	default:
		return 0;
	}

	for (unsigned i = 0; i < nblocked; i++) {
		if (gai_blocked[i]->sa_family != family)
			continue;
		switch (gai_blocked[i]->sa_family) {
		case AF_INET:
			if (memcmp(sa_addr, &SADDR4(gai_blocked[i]), addrlen) == 0)
				return 1;
		case AF_INET6:
			if (memcmp(sa_addr, &SADDR6(gai_blocked[i]), addrlen) == 0)
				return 1;
		}
	}

	return 0;
}

typedef int (*fp_getaddrinfo)(const char *restrict node,
					const char *restrict service,
					const struct addrinfo *restrict hints,
					struct addrinfo **restrict res);

/** Store resolved addresses of the specific hosts */
int getaddrinfo(const char *restrict node,
				const char *restrict service,
				const struct addrinfo *restrict hints,
				struct addrinfo **restrict res)
{
	static fp_getaddrinfo libc_getaddrinfo;
	int gai_res;

	printf("* getaddrinfo \"%s\" / %s\n", node, service);

	if (libc_getaddrinfo == NULL)
		libc_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");

	if (strcmp(node, "account.jetbrains.com") != 0)
		return libc_getaddrinfo(node, service, hints, res);

	gai_res = libc_getaddrinfo(node, service, hints, res);
	if (gai_res != 0)
		return gai_res;

	/* Store addresses for later use */
	struct addrinfo *ai = *res;
	char *ap = gai_buf;
	unsigned i;
	for (i = 0; ai != NULL && i < sizeof(gai_blocked) / sizeof(*gai_blocked); i++, ai = ai->ai_next) {
		char buf[256];
		if (ap + ai->ai_addrlen > gai_buf + sizeof(gai_buf))
			break;
		printf("  ++ store %s\n", sa2a(ai->ai_addr, buf, sizeof(buf)));
		gai_blocked[i] = (struct sockaddr*)ap;
		memcpy(ap, ai->ai_addr, ai->ai_addrlen);
		ap += ai->ai_addrlen;
	}
	nblocked = i;

	return gai_res;
}

typedef struct hostent* (*fp_gethostbyname)(const char *name);

struct hostent *gethostbyname(const char *name)
{
	static fp_gethostbyname libc_gethostbyname;

	if (libc_gethostbyname == NULL)
		libc_gethostbyname = dlsym(RTLD_NEXT, "gethostbyname");
	printf("* gethostbyname \"%s\"\n", name);
	return libc_gethostbyname(name);
}

typedef int (*fp_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

/** Disallow connections to "forbidden" hosts */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	static fp_connect libc_connect;
	char buf[256];
	int is_blocked;

	if (libc_connect == NULL)
		libc_connect = dlsym(RTLD_NEXT, "connect");

	switch (addr->sa_family) {
	case AF_INET:
		puts("connect -> inet");
		break;
	case AF_INET6:
		puts("connect -> inet6");
		break;
	default:
		return libc_connect(sockfd, addr, addrlen);
	}

	is_blocked = lookup_addr(addr);
	printf("* connect %s%s\n", sa2a(addr, buf, sizeof(buf)), is_blocked ? " BLOCKED" : "");

	if (is_blocked) {
		errno = ENETUNREACH;
		return -1;
	}

	return libc_connect(sockfd, addr, addrlen);
}
