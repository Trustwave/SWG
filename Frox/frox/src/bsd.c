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

    bsd.c -- Bsd specific code. Should contain transparent proxy code, but currently only non transparent
proxying works. Thanks
             to Sergey Matveychuk for getting frox running on bsd.

***************************************/

#include "common.h"
#include "os.h"

#ifdef TRANS_DATA
#error--enable-transparent-data not supported under BSD
#endif

#ifdef IPFILTER
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip_compat.h>
#include <netinet/ip_fil.h>
#include <netinet/ip_nat.h>

static int natfd;
#endif

/* This is called before priveliges are dropped or we chroot(). For
 * ipfilter opening the fd for get_orig_dest is a priveliged operation
 * so we do it here. */
int os_init(void) {
#ifdef IPFILTER
  natfd = open(IPL_NAME, O_RDONLY, 0);
  if (natfd < 0)
    write_log(ERROR, "Unable to initialise IPFilter");
#endif
  return 0;
}

/* ------------------------------------------------------------- **
**  Get the address of the interface we connect to the client through
**  for putting in our 227 reply. We insist that the user has Listen
**  defined in his config file, and use that address.
**  ------------------------------------------------------------- */
int get_local_address(const int fd, struct sockaddr_in *addr) {
  socklen_t len;

  *addr = config.listen_address;

  if (addr->sin_addr.s_addr != 0) {
    addr->sin_port = 0;
    return (0);
  }

  len = sizeof(*addr);
  return (getsockname(fd, (struct sockaddr *)addr, &len));
}

int bindtodevice(int fd) {
  if (!config.device)
    return (0);

  write_log(ERROR, "Bind to device not supported in BSD");
  return (-1);
}
