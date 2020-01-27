
#ifndef __GENERAL_NET_API_H
#define __GENERAL_NET_API_H

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

int trustwave_socket(sa_family_t family_type);
int trustwave_is_same_family_type(const struct sockaddr_storage *to, const struct sockaddr_storage *from);
void trustwave_set_port(struct sockaddr_storage *sa, uint16_t port);
uint16_t trustwave_get_port(struct sockaddr_storage *sa);
int trustwave_inet_pton(const char *src, void *dst);
const char *trustwave_inet_ntop(struct sockaddr_storage *sa, char *dst, socklen_t size);
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);
int trustwave_is_same_addr(const struct sockaddr *a1, const struct sockaddr *a2);
int trustwave_getaddrinfo(const char *node, const char *service, struct sockaddr_storage *sa);
int sockaddr_cmp_addr(struct sockaddr_storage *addr1, socklen_t len1, struct sockaddr_storage *addr2,
                      socklen_t len2);
int addr_is_any(struct sockaddr_storage *addr, socklen_t addrlen);
#endif
