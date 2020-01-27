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

ntp.c -- non transparent proxying stuff

Overview:

ntp_changedest gets called just before the proxy connects to the
remote server. If the connection is destined for a remote machine then
we assume that is the destination and that no ntp support is required.
Otherwise we send a welcome to the client and read a reply of the form
"USER username[@host[:port]]". If necessary we then change the
destination (in the global "info" structure), save the hostname, and
return. We also call set config.transdata=FALSE to stop NAT on data
connections for this session.

We also need get called(ntp_senduser) when the remote server sends us
a 220 welcome message. If we have already welcomed the client we send
the login name we got then to the server and return TRUE. Otherwise we
return FALSE and the main proxy code will forward the welcome on to
the client.

config.fakentp is set where other code in frox wishes to know the
username before it makes a connection - normally because there are
ACLs or config file subsections based on the username. In this case
we use the ntp code to do this, but don't parse the username to do
an address change.
***************************************/

#include <sys/ioctl.h>
#include <netdb.h>
#include <string.h> // memcpy
#include "common.h"
#include "cache.h"
#include "control.h"
#include "ntp.h"
#include "ccp.h"
#include "os.h"
#include "ftp-cmds.h"
#include "general_net_api.h"

// FINJAN_START
#include "FTP_EXT_Plugin_Common.hpp"
// FINJAN_END

void parseuser(sstr *arg);

static int working = FALSE;
static int faking = FALSE;

/* ------------------------------------------------------------- **
**  Called before the proxy connects to the server.
**
**  Send client "220 Send Login", read and parse reply.
**  ------------------------------------------------------------- */
void ntp_changedest(void) {
  sstr *cmd, *arg;
  struct sockaddr_storage tmp;
  char str[INET6_ADDRSTRLEN] = {0};
  if (!config.ntp) {
    if (config.fakentp)
      faking = TRUE;
    else
      return;
  }
  trustwave_inet_ntop(&config.ntpdest, str, INET6_ADDRSTRLEN);
  if (str[0]) {
    uint16_t p1, p2;
    /*Don't do ntp proxying unless the connection is to NTPDest. */
    get_orig_dest(info->client_control.fd, &tmp);
    p1 = trustwave_get_port(&tmp);
    p2 = trustwave_get_port(&config.ntpdest);

    if ((0 != trustwave_is_same_addr((struct sockaddr *)&tmp, (struct sockaddr *)&config.ntpdest)) ||
        (p1 != p2))
      faking = TRUE;
  }

  if (faking && !config.fakentp)
    return;
  working = TRUE;

  send_cmessage(
      220, faking
               ? "Frox. Please login."
               : "Frox transparent ftp proxy. Login with username[@host[:port]] [client_ip][/client_name]");
  info->greeting = FAKED;
  do {
    get_command(&cmd, &arg);
    if (!sstr_casecmp2(cmd, "QUIT"))
      die(INFO, "Client closed connecton", 0, 0, 0);
    if (sstr_casecmp2(cmd, "USER"))
      send_cmessage(530, "Please login with USER first");
  } while (sstr_casecmp2(cmd, "USER"));

  if (!faking)
    parseuser(arg);
  else
    sstr_cpy(info->username, arg);

  if (sstr_casecmp2(info->username, "ftp") && sstr_casecmp2(info->username, "anonymous"))
    info->anonymous = 0;
  else
    info->anonymous = 1;
}

/* ------------------------------------------------------------- **
**  If we have a username send it to the server.
**  ------------------------------------------------------------- */
void ntp_senduser(void) {
  int i;
  sstr *msg, *tmp;

  if (!working)
    return;

  if (info->greeting != DONE) {
    get_message(&i, &msg);
    if (i != 220) {
      die(INFO, "Unable to contact server in ntp", 421, "Server Unable to accept connection", 0);
    }
  }
  info->greeting = DONE;

  working = FALSE;

  tmp = sstr_dup2("USER");
  user_munge(tmp, NULL);
  sstr_free(tmp);
}

/* ------------------------------------------------------------- **
**  Parse the user command, resolve the hostname if present, and do
**  security checks. If all ok alter info->server_control.address.
**  We check for @ from the far end to allow usernames with @s in
**  them.
**  ------------------------------------------------------------- */
void parseuser(sstr *arg) {
  struct hostent *hostinfo;
  sstr *host = NULL;
  int sep, i;
  uint16_t port = 0u;
  sstr *tok;

  // FINJAN_START
  char hostname[256];
  // we should support next formats
  // 1. user_name@host_name
  // 2. user_name@host_name:port
  // 3. user_name@host_name: client_ip/client_name
  // 4. user_name@host_name:port client_ip/client_name

  int j, arglen;
  struct sockaddr_storage sa;
  if (arg)
    write_log(VERBOSE, "NTP: USER ARG: '%s'", sstr_buf(arg));

  // if received format 3 or 4 parse client_ip and/or client_name

  //
  // client username
  //

  write_log(VERBOSE, "NTP: Search for client_username ...");
  arglen = sstr_len(arg);
  for (j = arglen - 1; j >= 0; --j) {
    if (sstr_getchar(arg, j) == '/') {
      // client_name found
      sstr_cpy2(info->client_username, sstr_buf(arg) + j + 1);

      // delete client_name from arg
      sstr_ncpy2(arg, sstr_buf(arg), j);

      write_log(VERBOSE, "NTP: USER ARG after cutting client_username: '%s'", sstr_buf(arg));
    }
  }

  //
  // client ip
  //

  write_log(VERBOSE, "NTP: Search for client_ip ...");
  arglen = sstr_len(arg);
  for (j = arglen - 1; j >= 0; --j) {
    if (sstr_getchar(arg, j) == ' ') {
      // client_ip found
      sstr_cpy2(info->client_ip, sstr_buf(arg) + j + 1);

      hostinfo = gethostbyname(sstr_buf(info->client_ip));
      if (!hostinfo)
        die(INFO, "Invalid USER command arguments", 501,
            "Invalid USER command arguments: username[@host[:port]] [client_ip][/client_name]", 0);

      // delete client_ip form arg
      sstr_ncpy2(arg, sstr_buf(arg), j);

      write_log(VERBOSE, "NTP: USER ARG after cutting client_ip: '%s'", sstr_buf(arg));
    }
  }

  //    // set FTP server login username if not passed
  //    if ( strncmp(sstr_buf(info->client_username), "", 1) == 0 )
  //    {
  //        sstr_cpy(info->client_username, info->username); //
  //    }

  write_log(VERBOSE, "NTP: ClientUsername: '%s'", sstr_buf(info->client_username));

  // set real client ip if not passed
  if (strncmp(sstr_buf(info->client_ip), "", 1) == 0) {
    char client_control[INET6_ADDRSTRLEN] = {0};
    trustwave_inet_ntop(&info->client_control.address, client_control, INET6_ADDRSTRLEN);
    sstr_cpy2(info->client_ip, client_control);
  }

  write_log(VERBOSE, "NTP: ClientIP: [%s]", sstr_buf(info->client_ip));

  // FINJAN_END

  for (i = sstr_len(arg) - 1; i >= 0; i--)
    if (sstr_getchar(arg, i) == '@')
      break;

  // '@' not found -> 'user_name' only received
  if (i == -1) {
    char server_control[INET6_ADDRSTRLEN] = {0};
    sstr_cpy(info->username, arg);
    sstr_cpy(info->client_username, arg);
    // in this case, use server IP as server hostname
    trustwave_inet_ntop(&info->server_control.address, server_control, INET6_ADDRSTRLEN);
    sstr_cpy2(info->server_hostname, server_control);
    return;
  }

  // delete all after user_name@, leave only host_name+
  sstr_split(arg, info->username, 0, i);
  sstr_split(arg, NULL, 0, 1);

  // separate port from host_name
  tok = sstr_init(MAX_LINE_LEN);

  for (i = sstr_len(arg) - 1; i >= 0; i--)
    if (sstr_getchar(arg, i) == '[')
      break;

  if (-1 == i) {

    sep = sstr_token(arg, tok, ":", 0);
    host = (sep == -1 ? arg : tok);

    if (sep == ':')
      port = sstr_atoi(arg);
    else
      port = 21; // set default port if not specified

    write_log(VERBOSE, "length host = %d", sstr_len(host));
    memset(hostname, 0, 256);
    memcpy(hostname, sstr_buf(host), sstr_len(host));
    write_log(VERBOSE, "NTP:  Host=%s", sstr_buf(host));
    write_log(VERBOSE, "NTP:  Port=%d", port);
  } else {
    int j;
    for (j = sstr_len(arg) - 1; j >= 0; j--)
      if (sstr_getchar(arg, j) == ']')
        break;
    if (-1 == j) {

      write_log(ERROR, "NTP:  Bad hostname %s", sstr_buf(arg));
      return;
    }

    // delete all after user_name@, leave only host_name+
    sstr_split(arg, NULL, 0, 1);

    sep = sstr_token(arg, tok, "]", 0);
    host = sep == -1 ? arg : tok;

    write_log(VERBOSE, "host = %s", sstr_buf(host));
    write_log(VERBOSE, "length host = %d", sstr_len(host));
    memset(hostname, 0, 256);
    memcpy(hostname, sstr_buf(host), sstr_len(host));
    write_log(VERBOSE, "NTP:  Host=%s", sstr_buf(host));
    if (arg) { /*[note] some clients omit the default port [end of note]*/
      write_log(VERBOSE, "arg = %s", sstr_buf(arg));
      sep = sstr_token(arg, tok, ":", 0);
      write_log(VERBOSE, "[verbose] arg = %s, tok = %s, sep = %d", sstr_buf(arg), sstr_buf(tok), sep);
      port = sep == -1 ? sstr_atoi(arg) : 21;
    } else {
      port = 21;
    }
    if (port != 21)
      write_log(VERBOSE, "[verbose] selecting custom port");
    if (port == 0)
      port = 21;
    write_log(VERBOSE, "NTP:  Port=%d", port);
  }

  /*Turn off data connection NAT for this connection! */
  config.transdata = FALSE;
  if (-1 == trustwave_getaddrinfo(hostname, NULL, &sa)) {
    die(INFO, "Unable to find NTP host", 501, "Can't find that host", 0);
  }
  /*	if(hostinfo->h_addrtype != AF_INET)
                  die(INFO, "Invalid NTP host", 501, "Invalid host", 0);
  */

  trustwave_set_port(&sa, port);
  trustwave_inet_pton(sstr_buf(host), &info->server_control.address);
  memcpy(&info->server_control.address, &sa, sizeof(sa));

  /*We used to change apparent_server_address here, but I don't
     think that is right. Makes no difference as we have turned
     off TransparentData connections above and that is all it is
     used for. */

  sstr_cpy(info->server_name, host);

  sstr_free(tok);

  // FINJAN_START

  sstr_cat(info->server_hostname,
           info->server_name); // we should save it here as name, since frox resolve 'info->server_name' later
  info->server_hostname_resolved = 1;

  // set FTP server login username if not passed
  if (strncmp(sstr_buf(info->client_username), "", 1) == 0) {
    sstr_cpy(info->client_username, info->username); //
  }

  //    // set FTP server login username if not passed
  //    if ( strncmp(sstr_buf(info->client_username), "", 1) == 0 )
  //    {
  //        write_log(VERBOSE, "NTP: ClientUsername is empty !!!" );
  //        sstr_cpy(info->client_username, info->username); //
  //    }

  //    write_log(VERBOSE, "NTP: ClientUsername: '%s'", sstr_buf(info->client_username));

  // set real client ip if not passed
  //    if ( strncmp(sstr_buf(info->client_ip), "", 1) == 0 )
  //    {
  //        write_log(VERBOSE, "NTP: ClientIP is empty !!!" );
  //        sstr_cpy2(info->client_ip, inet_ntoa(info->client_control.address.sin_addr));
  //    }

  //    write_log(VERBOSE, "NTP: ClientIP: [%s]", sstr_buf(info->client_ip));

  //    // Check if URI is authorized by URLCat before connecting to server
  //    if ( config.vscanner )
  //    {
  //        strcpy(uri, "ftp://");
  //        strcat(uri, sstr_buf(info->server_hostname));

  //        write_log(VERBOSE, "NTP: Checking if HOST is authorized: %s", uri);

  //        ret = scan_file( "",
  //                         (char*)sstr_buf(info->client_ip),
  //                         (char*)sstr_buf(info->client_username),
  //                         uri,
  //                         &contentStatus,
  //                         blockReason,
  //                         &write_log );

  //        if ( -1 == ret )
  //        {
  //            die(VERBOSE, "NTP: Error occured while checking if HOST is authorized",
  //                421, "Failed to check if HOST is authorized.", 0);
  //        }

  //        if ( 0 == contentStatus )
  //        {
  //            write_log(VERBOSE, "NTP: HOST authorized");
  //        }
  //        else
  //        {
  //            die(VERBOSE, "NTP: HOST not authorized",
  //                421, blockReason, 0);
  //        }
  //    }
  // FINJAN_END
}
