#include "common.h"
#include "general_net_api.h"
#include <arpa/inet.h> // for inet_ntop, inet_pton
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>  // for fprintf
#include <string.h> // for memcpy memcmp
int trustwave_socket(sa_family_t family_type) {
  if (family_type == AF_INET6) {
    return socket(AF_INET6, SOCK_STREAM, 0);
  } else if (family_type == AF_INET) {
    return socket(AF_INET, SOCK_STREAM, 0);
  }
  return -1;
}

int trustwave_is_same_family_type(const struct sockaddr_storage *to, const struct sockaddr_storage *from) {
  return (to->ss_family == from->ss_family) ? 0 : -1;
}

void trustwave_set_port(struct sockaddr_storage *sa, uint16_t port) {
  if (sa->ss_family == AF_INET6) {
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)sa;
    addr6->sin6_port = htons(port);
  } else if (sa->ss_family == AF_INET) {
    struct sockaddr_in *addr4 = (struct sockaddr_in *)sa;
    addr4->sin_port = htons(port);
  }
}

uint16_t trustwave_get_port(struct sockaddr_storage *sa) {
  if (AF_INET6 == sa->ss_family) {
    struct sockaddr_in6 *p = (struct sockaddr_in6 *)sa;
    return ntohs(p->sin6_port);
  } else if (AF_INET == sa->ss_family) {
    struct sockaddr_in *p = (struct sockaddr_in *)sa;
    return ntohs(p->sin_port);
  }
  return ntohs(0u);
}

int trustwave_inet_pton(const char *src, void *dst) {
  int ec;
  // try to convert to IPV6
  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;
  sin = (struct sockaddr_in *)dst;
  sin6 = (struct sockaddr_in6 *)dst;

  ec = inet_pton(AF_INET, src, &sin->sin_addr);
  if (ec > 0) {
    sin->sin_family = AF_INET;
    return ec;
  }

  ec = inet_pton(AF_INET6, src, &sin6->sin6_addr);

  if (ec > 0) {
    sin6->sin6_family = AF_INET6;
    return ec;
  }

  return ec;
}

const char *trustwave_inet_ntop(struct sockaddr_storage *sa, char *dst, socklen_t size) {
  if (sa->ss_family == AF_INET6) {
    struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa;
    return (char *)inet_ntop(AF_INET6, &sin->sin6_addr, dst, size);
  } else if (sa->ss_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;
    return (char *)inet_ntop(AF_INET, &sin->sin_addr, dst, size);
  }
  return NULL;
}

int trustwave_is_same_addr(const struct sockaddr *a1, const struct sockaddr *a2) {

  if (trustwave_is_same_family_type((struct sockaddr_storage *)a1, (struct sockaddr_storage *)a2) == 0) {
    if (AF_INET6 == a1->sa_family) {
      const struct sockaddr_in6 *p1 = (struct sockaddr_in6 *)a1;
      const struct sockaddr_in6 *p2 = (struct sockaddr_in6 *)a2;

      return 0 == memcmp(&p1->sin6_addr, &p2->sin6_addr, sizeof(*p1)) &&
             p1->sin6_scope_id == p2->sin6_scope_id;

    } else if (AF_INET == a1->sa_family) {
      const struct sockaddr_in *p1 = (struct sockaddr_in *)a1;
      const struct sockaddr_in *p2 = (struct sockaddr_in *)a2;
      return 0 == memcmp(&p1->sin_addr, &p2->sin_addr, sizeof(*p1));
    }
  }
  return -1;
}

int trustwave_getaddrinfo(const char *node, const char *service, struct sockaddr_storage *sa) {

  int status;
  struct addrinfo hints, *res, *p;
  char ipstr[INET6_ADDRSTRLEN] = {0};

  memset(&hints, 0, sizeof hints);
  hints.ai_flags = 1 == config.listeners ? AF_INET : AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((status = getaddrinfo(node, NULL, &hints, &res)) != 0) {
    // fprintf(stderr, "getaddrinfo: %s\n\n", gai_strerror(status));
    return -1;
  }

  for (p = res; p != NULL; p = p->ai_next) {
    void *addr = 0;
    if (AF_INET == p->ai_family) {
      struct sockaddr_in *ip4 = (struct sockaddr_in *)p->ai_addr;
      addr = &(ip4->sin_addr);
    } else { //(AF_INET6 == p->ai_family){
      struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)p->ai_addr;
      addr = &(ip6->sin6_addr);
    }
    // NOTE: hints does not filter the ip address as expected via hints
    // validate that ip address is not from type 6 when we only listen to ipv4 in case listeners is set to 1
    if (1 == config.listeners && AF_INET != p->ai_family) {
      continue;
    }
    if (inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr)) {
      trustwave_inet_pton(ipstr, sa); // NOTE: we only extract the first address (
    }
  }
  freeaddrinfo(res); // free the linked list

  return 0;
}

int sockaddr_cmp_addr(struct sockaddr_storage *addr1, socklen_t len1, struct sockaddr_storage *addr2,
                      socklen_t len2) {
  struct sockaddr_in *p1_in = (struct sockaddr_in *)addr1;
  struct sockaddr_in *p2_in = (struct sockaddr_in *)addr2;
  struct sockaddr_in6 *p1_in6 = (struct sockaddr_in6 *)addr1;
  struct sockaddr_in6 *p2_in6 = (struct sockaddr_in6 *)addr2;

  if (len1 < len2)
    return -1;
  if (len1 > len2)
    return 1;
  if (p1_in->sin_family < p2_in->sin_family)
    return -1;
  if (p1_in->sin_family > p2_in->sin_family)
    return 1;

  if (AF_INET == p1_in->sin_family) {
    return memcmp(&p1_in->sin_addr, &p2_in->sin_addr, INET_ADDRSTRLEN);
  } else if (AF_INET6 == p1_in6->sin6_family) {
    return memcmp(&p1_in6->sin6_addr, &p2_in6->sin6_addr, INET6_ADDRSTRLEN);
  } else {
    /* eek unknown type, perform this comparison for sanity. */
    return memcmp(addr1, addr2, len1);
  }
}

int addr_is_any(struct sockaddr_storage *addr, socklen_t addrlen) {
  int af = (int)((struct sockaddr_in *)addr)->sin_family;
  int af6 = (int)((struct sockaddr_in6 *)addr)->sin6_family;
  const socklen_t sockaddr_in_size = sizeof(struct sockaddr_in);
  const socklen_t sockaddr_in6_size = sizeof(struct sockaddr_in6);
  void *sinaddr = &((struct sockaddr_in *)addr)->sin_addr;
  void *sin6addr = &((struct sockaddr_in6 *)addr)->sin6_addr;

  if (AF_INET == af && addrlen >= sockaddr_in_size && memcmp(sinaddr, "\000\000\000\000", 4) == 0) {
    return 1;
  }

  if (AF_INET6 == af6 && addrlen >= sockaddr_in6_size &&
      memcmp(sin6addr, "\000\000\000\000\000\000\000\000"
                       "\000\000\000\000\000\000\000\000",
             16) == 0) {
    return 1;
  }
  // on fail we return 0
  return 0;
}
