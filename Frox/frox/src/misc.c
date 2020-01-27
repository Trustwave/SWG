/***************************************

    This is part of frox: A simple transparent FTP proxy
    Copyright (C) 2000 James Hollingshead

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    misc.c - Miscellaneous stuff. Maybe this is getting unwieldy
             enough to want splitting...
  ***************************************/

#include <stdarg.h>
#include <syslog.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <ctype.h>
#include <string.h> // for memset

#include "common.h"
#include "control.h"
#include "transdata.h"
#include "misc.h"
#include "vscan.h"
#include "general_net_api.h"

// FINJAN_START
#include "FTP_EXT_Plugin_Common.hpp"
// FINJAN_END

/* ------------------------------------------------------------- **
** Listens on socket. If portrange != NULL then picks a port from the range
** in portrange, otherwises uses the value from listen_address.
** ------------------------------------------------------------- */
int listen_on_socket(struct sockaddr_storage *listen_address, int portrange[2]) {
  int sockfd, one = 1;
  sockfd = socket(listen_address->ss_family, SOCK_STREAM, 0);
  char ipstr[INET6_ADDRSTRLEN] = {0};
  trustwave_inet_ntop(listen_address, ipstr, sizeof(ipstr));
  write_log(VERBOSE, "[info] ip address %s\n", ipstr);
  if (!portrange) {
    write_log(VERBOSE, "[info] no portrange\n");
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one)) < 0) {
      close(sockfd);
      return -1;
    }
    if (1 < config.listeners && AF_INET6 == listen_address->ss_family &&
        setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&one, sizeof(one)) < 0) {
      write_log(VERBOSE, "[error]listen close sockfd = %d\n", sockfd);
      close(sockfd);
      return -1;
    }
    if (bind(sockfd, (const struct sockaddr *)listen_address, sizeof(*listen_address))) {
      close(sockfd);
      return -1;
    }
  } else {
    if (bind_me(sockfd, listen_address, portrange)) {
      close(sockfd);
      return -1;
    }
  }

  if (listen(sockfd, 5)) {
    close(sockfd);
    write_log(VERBOSE, "[error]listen close sockfd = %d\n", sockfd);
    return -1;
  }

  write_log(VERBOSE, "[info] listen on sockfd = %d\n", sockfd);
  return sockfd;
}

/* ------------------------------------------------------------- **
** Connects to address. Local port is picked from within portrange.
** ------------------------------------------------------------- */
int connect_to_socket(struct sockaddr_storage *to, const struct sockaddr_storage *from_addr,
                      int portrange[2]) {
  int sockfd = 0;
  struct sockaddr_storage from;
  write_log(VERBOSE, "get sockfd ...");
  sockfd = trustwave_socket(to->ss_family);
  if (sockfd < 0) {
    // debug_perr("socket");
    die(ERROR, "Socket error while making connection", 0, 0, -1);
  }

  memset(&from, 0, sizeof(from));
  if (from_addr)
    memcpy(&from, from_addr, sizeof(*from_addr));

  from.ss_family = to->ss_family;

  /* Allow address reuse. */
  /*
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &one,
          sizeof(one)) < 0) {
          //debug_perr("setsockopt");
          close(sockfd);
          return (-1);
  }
  */

  write_log(VERBOSE, "bind_me ...");
  if (bind_me(sockfd, &from, portrange)) {
    // debug_perr("connect_to_socket: bind_me");
    close(sockfd);
    return (-1);
  }

  write_log(VERBOSE, "connect ...");
  if (connect(sockfd, (struct sockaddr *)to, sizeof(*to))) {
    int i = errno;
    char ipstr[INET6_ADDRSTRLEN] = {0};
    trustwave_inet_ntop(to, ipstr, INET6_ADDRSTRLEN);
    write_log(ERROR, "%s when trying to connect to %s", strerror(i), ipstr);
    close(sockfd);
    return (-1);
  }

  return (sockfd);
}

/* ------------------------------------------------------------- **
** Try to bind socket "fd" to address "address", with a port picked
** at random from within portrange.
** ------------------------------------------------------------- */
int bind_me(int fd, struct sockaddr_storage *address, int portrange[2]) {
  int i, j, one = 1;

  for (i = 0; i <= portrange[1] - portrange[0]; i++) {
    j = (rand() % (portrange[1] - portrange[0])) + portrange[0];
    trustwave_set_port(address, j);

    /* Allow address reuse. */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one)) < 0) {
      return (-1);
    }
    if (1 < config.listeners && AF_INET6 == address->ss_family &&
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&one, sizeof(one)) < 0) {
      // debug_perr("setsockopt");
      close(fd);
      return (-1);
    }
    if (bind(fd, (struct sockaddr *)address, sizeof(*address)) == 0)
      break;

    if (errno != EADDRINUSE) {
      return (-1);
    }
  }

  return (i > (portrange[1] - portrange[0]) ? -1 : 0);
}

/* ------------------------------------------------------------- **
** Convert a comma separted values address:port to a sockaddr_in
** in network order
** ------------------------------------------------------------- */
struct sockaddr_in com2n(int a1, int a2, int a3, int a4, int p1, int p2) {
  struct sockaddr_in ret;

  ret.sin_addr.s_addr = htonl(a4 + (a3 << 8) + (a2 << 16) + (a1 << 24));
  ret.sin_port = htons((p1 << 8) + p2);
  ret.sin_family = AF_INET;

  return (ret);
}

/* ------------------------------------------------------------- **
** Convert network order address to comma separated values
** ------------------------------------------------------------- */
void n2com(struct sockaddr_in address, int *a1, int *a2, int *a3, int *a4, int *p1, int *p2) {
  address.sin_addr.s_addr = ntohl(address.sin_addr.s_addr);
  address.sin_port = ntohs(address.sin_port);
  *a1 = (address.sin_addr.s_addr & 0xFF000000) >> 24;
  *a2 = (address.sin_addr.s_addr & 0x00FF0000) >> 16;
  *a3 = (address.sin_addr.s_addr & 0x0000FF00) >> 8;
  *a4 = (address.sin_addr.s_addr & 0x000000FF);
  *p1 = (address.sin_port & 0xFF00) >> 8;
  *p2 = (address.sin_port & 0x00FF);
}

/* ------------------------------------------------------------- **
** Extract a comma delimited address/port from buf. buf is unchecked
** user input so make sure we don't do anything stupid here...
** ------------------------------------------------------------- */
struct sockaddr_in extract_address(const sstr *buf) {
  int i, a[6];
  struct sockaddr_in tmp;
  sstr *p = sstr_dup(buf);

  memset(&tmp, 0, sizeof(tmp));

  sstr_split(p, NULL, 0, sstr_pbrk2(p, "0123456789"));
  for (i = 0; i < 6; i++) {
    a[i] = sstr_atoi(p);
    if (a[i] < 0 || a[i] > 255) {
      sstr_free(p);
      write_log(ATTACK, "PORT/PASV command number out of range");
      return tmp;
    }
    if (i != 5 && sstr_token(p, NULL, ",", 0) == -1) {
      sstr_free(p);
      return (tmp);
    }
  }

  tmp = com2n(a[0], a[1], a[2], a[3], a[4], a[5]);
  sstr_free(p);
  return (tmp);
}
// pattern should be <d><net-prt><d><net-addr><d><tcp-port><d>
// where <net-prt> is AF type {1,2}
// where <net-addr> is the IPv4 or Ipv6 address string
// where <tcp-port> is the port number
// where <d> represent the character "|"
struct sockaddr_storage extract_address6(const sstr *buf) {
  struct sockaddr_storage tmp;
  int netprt;
  uint16_t port;
  char *token, *end;

  char netbuf[INET6_ADDRSTRLEN] = {0};
  sstr *p = sstr_dup(buf);
  const char delim[] = "(|)";

  // max length { net-prt(command) + ipv6 + tcpport, num_of_delimiter }
  static int proto_msg_size = 1 + INET6_ADDRSTRLEN + 5 + 4;
  char proto_msg[1 + INET6_ADDRSTRLEN + 5 + 4] = {0};
  const int len = sstr_len(p);

  memset(&tmp, 0, sizeof(tmp));

  if (len > proto_msg_size) {
    write_log(ERROR, "length mismatch...");
    return tmp;
  }
  memcpy(proto_msg, sstr_buf(p), len);
  sstr_free(p);
  // EPRT Command
  // commnd ex: |2|fc00:12::23|50100|
  // EPSV Command
  // Entering Extended Passive Mode (|||6446|)
  token = strtok(proto_msg, delim);
  if ('1' == *token || '2' == *token) {

    write_log(INFO, "EPRT parse");
    netprt = strtol(token, &end, 10);
    if (*end) {
      write_log(ERROR, "error parsing netprt");
      return (tmp);
    }
    token = strtok(NULL, delim); // address
    write_log(INFO, "%s", token);

    if (1 == netprt) {
      tmp.ss_family = AF_INET;

    } else if (2 == netprt) {
      tmp.ss_family = AF_INET6;
    } else {
      write_log(ERROR, "EPSV net-prt parse");
      return tmp;
    }

    trustwave_inet_pton(token, &tmp);

    token = strtok(NULL, delim); // port
    write_log(INFO, "%s", token);

    port = strtol(token, &end, 10);
    if (*end) {
      write_log(ERROR, "error parsing netprt");
      return (tmp);
    }

    trustwave_set_port(&tmp, port);
    trustwave_inet_ntop(&tmp, netbuf, INET6_ADDRSTRLEN);
    write_log(INFO, "{ipv4|ipv6} = {%s}, family type = %d, port = %u", netbuf, netprt, port);
    return (tmp);
  }

  token = strtok(NULL, delim);
  if (token) {

    write_log(INFO, "EPSV parse");
    port = strtol(token, &end, 10);
    if (!*end) {
      write_log(VERBOSE, "port: %s", token);
      tmp.ss_family = info->server_control.address.ss_family; // tmp defined af
      write_log(VERBOSE, "ss_family: %d", tmp.ss_family);
      trustwave_set_port(&tmp, port);
      port = trustwave_get_port(&tmp);
    } else {
      write_log(ERROR, "error parsing message %s", end);
    }
  } else {
    write_log(VERBOSE, "buffer not parsed = %s, %s", proto_msg, token);
  }

  return tmp;
}

/* Is u16 a valid port*/
int valid_uint16(int u16) { return ((u16 >= 0) && (u16 < 65536)); }

/* Close fd if it isn't -1, and reset it to -1 */
int rclose(int *fd) {
  int i;
  if (*fd == -1)
    return 0;
  i = close(*fd);
  *fd = -1;
  return i;
}

int do_chroot(void) {
  if (config.dontchroot)
    return (0);
  if (chroot(config.chroot) != 0 || chdir("/") != 0) {
    write_log(ERROR, "Failed to chroot.");
    return (-1);
  }

  write_log(IMPORT, "Chrooted to %s", config.chroot);

  strip_filenames();

  return (0);
}

int droppriv(void) {
  if (config.uid == 0) {
#ifdef ENFORCE_DROPPRIV
    write_log(ERROR, "Running frox as root is not allowed. "
                     "Set \"User\" to another value in the config file");
    write_log(ERROR, "Alternatively you may recompile giving "
                     "--enable-run-as-root to ./configure");
    exit(-1);
#else
    write_log(IMPORT, "WARNING! Frox is set to run as root");
#endif
  }

  if (config.gid != 0) {
    setgid(config.gid);
    setgid(config.gid);
  }
  if (config.uid != 0) {
    setuid(config.uid);
    setuid(config.uid);
    write_log(IMPORT, "Dropped privileges");
  }
  return (0);
}

/*Write a log of a file transfer. upload states whether an upload or
  download. virus is 1 (contains virus), 0 (clean), or -1 (not
  scanned) */
void xfer_log(void) {
  char client_control_ip[INET6_ADDRSTRLEN] = {0};
  if (!info->needs_logging)
    return;
  if (!config.xferlogging)
    return;
  // FINJAN_START
  // FINJAN - '-1' log level changed to ATTACK
  //	write_log(ATTACK, "%s %s ftp://%s@%s/%s%s %s%s",
  write_log(VERBOSE, "%s %s ftp://%s@%s%s %s%s",
            trustwave_inet_ntop(&info->client_control.address, client_control_ip, sizeof(client_control_ip)),
            info->upload ? "UPLOADED" : "DOWNLOADED", sstr_buf(info->username),
            //              sstr_buf(info->server_name),
            sstr_buf(info->server_hostname), get_absolute_path(info),
            //		      sstr_buf(info->strictpath),
            //  		  sstr_buf(info->filename),
            info->virus == -1 ? "" : (info->virus ? " VIRUS_INFECTED" : " VIRUS_CLEAN"),
            info->cached ? " CACHE_HIT" : "");
  // FINJAN_END

  info->needs_logging = FALSE;
}

void write_log(int priority, const char *msg, ...) {
  static char tsBuf[32];

  char *buf = NULL;
  int sz = MAX_LINE_LEN, n;
  va_list argptr;
  time_t tstamp;

  if (priority > config.loglevel)
    return;
  do { /* Modified from printf(3) man page */
    if ((buf = realloc(buf, sz)) == NULL)
      die(ERROR, "Out of memory.", 0, 0, -1);

    va_start(argptr, msg);
    n = vsnprintf(buf, sz, msg, argptr);
    va_end(argptr);

    if (n == -1)      /* glibc 2.0 */
      sz *= 2;        /* Try a bigger buffer */
    else if (n >= sz) /* C99 compliant / glibc 2.1 */
      sz = n + 1;     /* precisely what is needed */
    else
      break; /*It worked */
  } while (1);

  if (priority == ERROR || priority == ATTACK) {
    syslog(LOG_ERR | LOG_DAEMON, "%s\n", buf);
  }

  //    sstr *s;
  //    s = sstr_init(0);

  time(&tstamp);
  ctime_r(&tstamp, tsBuf);

  tsBuf[strlen(tsBuf) - 1] = '\0';

  fprintf(stderr, "%s frox[%5d]: %s\n", tsBuf, getpid(), buf);

  //    sstr_cpy2( s, ctime(&tstamp) );
  //    sstr_setchar( s, sstr_chr(s, '\n'), ' ' );
  //    sstr_apprintf( s, "frox[%d] %s\n", getpid(), buf );
  //    sstr_write( stderr, s, 0 );

  //    sstr_free(s);

  //	if(config.logfile) {
  //		sstr *s;
  //		s = sstr_init(0);
  //		time(&tstamp);
  //		sstr_cpy2(s, ctime(&tstamp));
  //		sstr_setchar(s, sstr_chr(s, '\n'), ' ');
  //		sstr_apprintf(s, "frox[%d] %s\n", getpid(), buf);
  //		sstr_write(2, s, 0);
  //		sstr_free(s);
  //	} else {
  //		if(priority == ERROR || priority == ATTACK) {
  //			syslog(LOG_ERR | LOG_DAEMON, "%s\n", buf);
  //		} else {
  //			syslog(LOG_NOTICE | LOG_DAEMON, "%s\n", buf);
  //		}
  //	}

  free(buf);
}

/* ------------------------------------------------------------- **
** Return hostname of address, or failing that the IP as a string
** ------------------------------------------------------------- */
sstr *addr2name(const struct sockaddr *address) {
  //	struct sockaddr_in6 sa;
  char ipstr[INET6_ADDRSTRLEN] = {0};
  char host[NI_MAXHOST] = {0};

  static sstr *buf = NULL;

  if (!buf)
    buf = sstr_init(MAX_LINE_LEN);

  trustwave_inet_ntop((struct sockaddr_storage *)address, ipstr, sizeof(ipstr));
  sstr_cpy2(buf, ipstr);

  // if (0 == getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD)){
  if (0 == getnameinfo(address, sizeof(address), host, sizeof(host), NULL, 0, NI_NAMEREQD)) {
    sstr_apprintf(buf, "(%s)", host);
  }
  return (buf);
}

int resolve_addr(const struct sockaddr_storage *address, sstr *fqdn) {
  struct sockaddr_in6 sa;
  char ipstr[INET6_ADDRSTRLEN] = {0};
  char host[NI_MAXHOST];

  memcpy(&sa, address, sizeof sa);

  trustwave_inet_ntop((struct sockaddr_storage *)address, ipstr, INET6_ADDRSTRLEN);
  if (0 == getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD)) {
    sstr_cpy2(fqdn, host);
  } else {
    write_log(ERROR, "The fqdn could not be determined");
    return 0;
  }

  sstr_cpy2(fqdn, ipstr);
  return -1;
}

/* Escape non printable characters, and any characters from extras in the url
 * with the %xx equivalent. If % must be escaped then include it in extras.
 */
int urlescape(sstr *url, char *extras) {
  int i;
  sstr *tmp = sstr_init(0);

  for (i = 0; i < sstr_len(url); i++) {
    char c = sstr_getchar(url, i);
    if (strchr(extras, c) || !isprint(c)) {
      sstr_ncat(tmp, url, i);
      sstr_apprintf(tmp, "%%%x", c);
      sstr_split(url, NULL, 0, i + 1);
      i = -1;
    }
  }
  sstr_cat(tmp, url);
  sstr_cpy(url, tmp);
  sstr_free(tmp);
  return 0;
}

int make_tmpdir(void) {
  sstr *name;
  struct stat tmp;

  name = sstr_init(0);
  sstr_apprintf(name, "%s/tmp", config.chroot);

  if (stat(sstr_buf(name), &tmp) == -1) {
    if (mkdir(sstr_buf(name), S_IRWXU) == -1) {
      write_log(ERROR, "Unable to make tmp dir %s", sstr_buf(name));
      sstr_free(name);
      return (-1);
    }
    chown(sstr_buf(name), config.uid, config.gid);
    sstr_free(name);
  }
  return 0;
}

/*
 * Quit the program.
 */
void die(int loglevel, const char *lmessage, int mcode, const char *message, int exitcode) {
  if (message)
    send_cmessage(mcode, message);
  if (lmessage)
    write_log(loglevel, lmessage);
  write_log(INFO, "Closing session");
  kill_procs();
  vscan_abort();
  exit(exitcode);
}

void kill_procs(void) {
  if (cmgrpid)
    kill(cmgrpid, SIGTERM);
  if (tdatapid)
    kill(tdatapid, SIGTERM);
}

// FINJAN_START
const char *get_absolute_path(session_info *si) {
  static char full_abspath[BUF_LEN + 1];
  static char full_relative_path[BUF_LEN + 1];

  full_abspath[0] = '\0';

  // sanity check:
  if (BUF_LEN < sstr_len(si->strictpath) + sstr_len(si->filename) + 1) {
    write_log(ERROR, "VS: path too long [%d bytes]. Temp buffer overflow.",
              sstr_len(si->strictpath) + sstr_len(si->filename) + 1);

    return full_abspath;
  }

  strcpy(full_relative_path, "/");
  strncat(full_relative_path, sstr_buf(info->strictpath), BUF_LEN - strlen(full_relative_path));
  strncat(full_relative_path, sstr_buf(info->filename), BUF_LEN - strlen(full_relative_path));

  write_log(VERBOSE, "VS: Convert relative path to absolute: %s", full_relative_path);

  if (rel_to_abs_path(full_relative_path, full_abspath) == NULL) {
    write_log(ERROR, "VS: Failed to build absolute path from relative, setting empty path");
    full_abspath[0] = '\0';
  } else {
    write_log(VERBOSE, "VS: Absolute path after converting: '%s'", full_abspath);
  }

  return full_abspath;
}

// FINJAN_END

void sstrerr(void) { die(ERROR, "sstr internal failure. Exiting", 0, 0, -1); }

#if defined(USE_LCACHE) || defined(TRANS_DATA)
/* Pinched from vsftpd. */
int send_fd(int sock_fd, int send_fd, char sendchar) {
  int retval;
  struct msghdr msg;
  struct cmsghdr *p_cmsg;
  struct iovec vec;
  char cmsgbuf[CMSG_SPACE(sizeof(send_fd))];
  int *p_fds;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  p_cmsg = CMSG_FIRSTHDR(&msg);
  p_cmsg->cmsg_level = SOL_SOCKET;
  p_cmsg->cmsg_type = SCM_RIGHTS;
  p_cmsg->cmsg_len = CMSG_LEN(sizeof(send_fd));
  p_fds = (int *)CMSG_DATA(p_cmsg);
  *p_fds = send_fd;
  msg.msg_controllen = p_cmsg->cmsg_len;

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;
  msg.msg_flags = 0;
  /* "To pass file descriptors or credentials you need to send/read at
   * least on byte" (man 7 unix)
   */
  vec.iov_base = &sendchar;
  vec.iov_len = sizeof(sendchar);
  retval = sendmsg(sock_fd, &msg, 0);
  if (retval != 1) {
    // debug_perr("sendmsg");
    return -1;
  }
  return 0;
}

char recv_fd(int sock_fd, int *recv_fd) {
  int retval;
  struct msghdr msg;
  char recvchar = 0;
  struct iovec vec;
  char cmsgbuf[CMSG_SPACE(sizeof(*recv_fd))];
  struct cmsghdr *p_cmsg;
  int *p_fd;
  vec.iov_base = &recvchar;
  vec.iov_len = sizeof(recvchar);
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  msg.msg_flags = 0;
  /* In case something goes wrong, set the fd to -1 before the syscall */
  p_fd = (int *)CMSG_DATA(CMSG_FIRSTHDR(&msg));
  *p_fd = -1;
  retval = recvmsg(sock_fd, &msg, 0);
  if (retval != 1) {
    // debug_perr("recvmsg");
    return (0);
  }

  p_cmsg = CMSG_FIRSTHDR(&msg);
  if (p_cmsg == NULL) {
    write_log(VERBOSE, "no passed fd");
    return (recvchar);
  }
  /* We used to verify the returned cmsg_level, cmsg_type and
   * cmsg_len here, but Linux 2.0 totally uselessly fails to
   * fill these in.  */
  p_fd = (int *)CMSG_DATA(p_cmsg);
  *recv_fd = *p_fd;
  if (*recv_fd == -1) {
    write_log(VERBOSE, "no passed fd");
  }
  return recvchar;
}
#endif /*LCACHE || TRANSDATA */

#ifdef USE_LCACHE

void set_write_lock(int fd) {
  struct flock lck;
  int i;

  lck.l_type = F_WRLCK;
  lck.l_whence = SEEK_SET;
  lck.l_start = 0;
  lck.l_len = 0;
  i = fcntl(fd, F_SETLK, &lck);

  if (i == -1) {
    // debug_perr("Setting file lock");
    die(ERROR, "Error setting file lock", 0, 0, -1);
  }
}

int set_read_lock(int fd) {
  struct flock lck;

  lck.l_type = F_RDLCK;
  lck.l_whence = SEEK_SET;
  lck.l_start = 0;
  lck.l_len = 0;
  return fcntl(fd, F_SETLK, &lck);
}

#endif /*USE_LCACHE */

#ifdef ENABLE_CHANGEPROC
/*Below is taken and altered slightly from proftpd. It is a bit of a hack
 *and therefore disabled by default. We move the environment variables
 *to another location so they are still availiable, and check how much
 *space we have. */
static char **Argv;
extern char *__progname, *__progname_full;
static char *LastArgv;

void init_set_proc_title(int argc, char *argv[], char *envp[]) {
  int i, envpsize;
  extern char **environ;
  char **p;

  for (i = envpsize = 0; envp[i] != NULL; i++)
    envpsize += strlen(envp[i]) + 1;

  if ((p = (char **)malloc((i + 1) * sizeof(char *))) != NULL) {
    environ = p;

    for (i = 0; envp[i] != NULL; i++) {
      if ((environ[i] = malloc(strlen(envp[i]) + 1)) != NULL)
        strcpy(environ[i], envp[i]);
    }

    environ[i] = NULL;
  }

  /* Run through argv[] and envp[] checking how much contiguous space we
   * have. This is the area we can overwrite - start stored in Argv,
   * and end in LastArgv */

  Argv = argv;
  for (i = 0; i < argc; i++)
    if (!i || (LastArgv + 1 == argv[i]))
      LastArgv = argv[i] + strlen(argv[i]);
  for (i = 0; envp[i] != NULL; i++)
    if ((LastArgv + 1) == envp[i])
      LastArgv = envp[i] + strlen(envp[i]);

  /* make glibc happy */
  __progname = strdup("frox");
  __progname_full = strdup(argv[0]);
}

void set_proc_title(char *fmt, ...) {
  va_list msg;
  static char statbuf[8192];
  char *p;
  int i, maxlen = (LastArgv - Argv[0]) - 2;

  va_start(msg, fmt);

  memset(statbuf, 0, sizeof(statbuf));
  vsnprintf(statbuf, sizeof(statbuf), fmt, msg);

  va_end(msg);

  i = strlen(statbuf);

  sprintf(Argv[0], "%s", statbuf);
  p = &Argv[0][i];

  while (p < LastArgv)
    *p++ = '\0';
  Argv[1] = ((void *)0);
}
#endif
