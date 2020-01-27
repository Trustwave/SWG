
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

  ftp-cmds.c Parsing code for individual commands.

  ***************************************/

#include <fcntl.h>
#include <errno.h>
#include <string.h> // memcpy
#include "ftp-cmds.h"
#include "control.h"
#include "data.h"
#include "transdata.h"
#include "vscan.h"
#include "cache.h"
#include "os.h"
#include "general_net_api.h"

// FINJAN_START
#include "FTP_EXT_Plugin_Common.hpp"
// FINJAN_END

void save_pass(sstr *cmd, sstr *arg);
void pasv_parse(sstr *cmd, sstr *arg); // extension for IPV6 and NATs see : rfc2428
void epsv_parse(sstr *cmd, sstr *arg);
void port_parse(sstr *cmd, sstr *arg);
void eprt_parse(sstr *cmd, sstr *arg); // extension for IPV6 and NATs see : rfc2428
void abor_parse(sstr *cmd, sstr *arg);
void xfer_command(sstr *cmd, sstr *arg);
void cwd_command(sstr *cmd, sstr *arg);
void pasv_reply(sstr *msg);

void ftpcmds_init() {
  static struct cmd_struct list[] =
  {                       /*Pinched in part SUSE */
    {"PORT", port_parse}, /*proxy suite! */
    {"PASV", pasv_parse},
    {"EPRT", eprt_parse}, // extenstion for IPV6 and NATs see: rfc2428
    {"EPSV", epsv_parse}, // extenstion for IPV6 and NATs see: rfc2428
    {"ABOR", abor_parse},
    {"USER", user_munge},
    {"PASS", save_pass},
    {"ACCT", send_command},
    {"CWD", cwd_command},
    {"CDUP", cwd_command},
    {"SMNT", send_command},
    {"QUIT", send_command},
    {"REIN", send_command},
    {"TYPE", send_command},
    {"STRU", send_command},
    {"MODE", send_command},
    {"RETR", xfer_command},
    {"STOR", xfer_command},
    {"STOU", xfer_command},
    {"APPE", xfer_command},
    {"ALLO", send_command},
    {"REST", send_command},
    {"RNFR", send_command},
    {"RNTO", send_command},
    {"DELE", send_command},
    {"RMD", send_command},
    {"MKD", send_command},
    {"PWD", send_command},
    {"LIST", xfer_command},
    {"MLSD", xfer_command},
    {"NLST", xfer_command},
    {"SITE", send_command},
    {"SYST", send_command},
    {"STAT", send_command},
    {"HELP", send_command},
    {"NOOP", send_command},
    {"SIZE", send_command}, /* Not found in RFC 959 */
    {"MDTM", send_command},
    {"MLFL", send_command},
    {"MAIL", send_command},
    {"MSND", send_command},
    {"MSOM", send_command},
    {"MSAM", send_command},
    {"MRSQ", send_command},
    {"MRCP", send_command},
    {"XCWD", send_command},
    {"XMKD", send_command},
    {"XRMD", send_command},
    {"XPWD", send_command},
    {"XCUP", send_command},
    {"FEAT", send_command},
#if 0
		{"APSV", send_command},	/* As per RFC 1579      */
#endif
    {"", 0}
  };

  ftp_cmds = list;
}

/* NB this function can be called from other code which has already copied the
 * username into info->username and set info->anonymous. In this case arg will
 * be NULL */
void user_munge(sstr *cmd, sstr *arg) {
  sstr *tmp;
  char server_ip[INET6_ADDRSTRLEN] = {0};
  char ftpbuffer[INET6_ADDRSTRLEN] = {0};
  uint16_t server_port;
  if (arg) {
    sstr_cpy(info->username, arg);
    if (sstr_casecmp2(info->username, "ftp") && sstr_casecmp2(info->username, "anonymous"))
      info->anonymous = 0;
    else
      info->anonymous = 1;
  }

  cache_init();
  tmp = sstr_dup(info->username);

  trustwave_inet_ntop(&config.ftpproxy, ftpbuffer, INET6_ADDRSTRLEN);
  if (ftpbuffer[0]) {

    sstr_apprintf(tmp, "@%s", trustwave_inet_ntop(&info->final_server_address, server_ip, sizeof(server_ip)));

    server_port = trustwave_get_port(&info->final_server_address);

    if (!config.ftpproxynp || trustwave_get_port(&info->final_server_address) != 21) {
      sstr_apprintf(tmp, ":%d", server_port);
    }
  }

  send_command(cmd, tmp);
  sstr_free(tmp);
}

void save_pass(sstr *cmd, sstr *arg) {
  sstr_cpy(info->passwd, arg);
  send_command(cmd, arg);
}

/* ------------------------------------------------------------- **
** Parse the PORT command in arg and store the client's data listening
** port. Either send out a PASV instead, or open a port of our own
** and send this to the server in a rewritten PORT command.
** ------------------------------------------------------------- */
void port_parse(sstr *cmd, sstr *arg) {

  write_log(VERBOSE, "port_parse entry");
  int code;
  sstr *msg;
  struct sockaddr_in p;

  p = extract_address(arg);
  memcpy(&info->client_data.address, &p, sizeof(struct sockaddr_in));

  if (!config_portok(&info->client_data.address)) {
    send_cmessage(500, "Bad PORT command");
    return;
  }

  if (info->mode == PASSIVE && info->client_listen != -1)
    il_free();
  rclose(&info->server_listen);
  rclose(&info->client_listen);

  if (config.apconv) {
    info->mode = APCONV;
    write_log(VERBOSE, "Rewriting PORT command to PASV");

    send_ccommand("PASV", "");
    get_message(&code, &msg);
    memset(&p, 0, sizeof(struct sockaddr_in));
    p = extract_address(msg);

    memcpy(&info->server_data.address, &p, sizeof(struct sockaddr_in));
    if (!config_pasvok(&info->server_data.address)) {
      send_cmessage(500, "Remote server error. PORT failed");
      return;
    } else {
      write_log(VERBOSE, "Rewriting 227 reply.");
      send_cmessage(200, "PORT command OK.");
      return;
    }
  } else {
    sstr *newbuf;
    int a1, a2, a3, a4, p1, p2;
    struct sockaddr_in listenaddr;
    socklen_t len;

    info->mode = ACTIVE;

    len = sizeof(listenaddr);
    getsockname(info->server_control.fd, (struct sockaddr *)&listenaddr, &len);
    listenaddr.sin_family = AF_INET;
    info->server_listen = listen_on_socket((struct sockaddr_storage *)&listenaddr, config.actvports);

    if (info->server_listen == -1) {
      send_cmessage(451, "Proxy unable to comply.");
      return;
    }

    n2com(listenaddr, &a1, &a2, &a3, &a4, &p1, &p2);

    newbuf = sstr_init(40);
    sstr_apprintf(newbuf, "%d,%d,%d,%d,%d,%d", a1, a2, a3, a4, p1, p2);

    write_log(INFO, "PORT = %d:", (p1 * 256 + p2));
    write_log(VERBOSE, "Rewritten PORT command:");

    send_command(cmd, newbuf);
    sstr_free(newbuf);
  }
}

/*
 * Intercepted EPRT command (rfc2428)
 */

void eprt_parse(sstr *cmd, sstr *arg) {
  int code;
  sstr *msg;
  struct sockaddr_storage sa;
  write_log(VERBOSE, "extracting address...");
  sa = extract_address6(arg);
  memcpy(&info->client_data.address, &sa, sizeof(sa));

  if (!config_portok(&info->client_data.address)) {
    send_cmessage(500, "Bad EPRT command");
    return;
  }

  if (info->mode == PASSIVE && info->client_listen != -1)
    il_free();
  rclose(&info->server_listen);
  rclose(&info->client_listen);

  if (config.apconv) {
    char buffer[INET6_ADDRSTRLEN] = {0};
    uint16_t port = 0u;
    info->mode = APCONV;
    write_log(VERBOSE, "Rewriting EPRT command to EPSV");

    send_ccommand("EPSV", "");
    get_message(&code, &msg);
    memset(&sa, 0, sizeof(sa));

    write_log(VERBOSE, "Extracting port...");
    sa = extract_address6(msg);
    port = trustwave_get_port(&sa);
    // copying address from final server into data channel
    memcpy(&info->server_data.address, &info->final_server_address, sizeof(info->final_server_address));

    write_log(VERBOSE, "Setting the port %u into server_data address...", port);
    trustwave_set_port(&info->server_data.address, port);

    // begin testing
    trustwave_inet_ntop(&info->server_data.address, buffer, INET6_ADDRSTRLEN);
    port = trustwave_get_port(&info->server_data.address);
    write_log(VERBOSE, "testing: server data address: %s, port = %u", buffer, port);
    // end testing
    //
    if (!config_pasvok(&info->server_data.address)) {
      send_cmessage(500, "Remote server error. EPRT failed");
      return;
    } else {
      write_log(VERBOSE, "Rewriting 229 reply.");
      send_cmessage(200, "EPRT command OK.");
      return;
    }
  } else {
    sstr *newbuf;
    uint16_t port;
    int ec = 0;
    char buffer[INET6_ADDRSTRLEN] = {0};

    struct sockaddr_storage listenaddr;
    socklen_t len;

    info->mode = ACTIVE;

    len = sizeof(listenaddr);
    ec = getsockname(info->server_control.fd, (struct sockaddr *)&listenaddr, &len);
    if (ec != 0) {
      write_log(ERROR, "getsockname error: %d", errno);
    }

    listenaddr.ss_family = AF_INET6;
    info->server_listen = listen_on_socket(&listenaddr, config.actvports);
    if (info->server_listen == -1) {
      write_log(VERBOSE, "6to4");
      listenaddr.ss_family = AF_INET;
      info->server_listen = listen_on_socket(&listenaddr, config.actvports);
    }
    if (info->server_listen == -1) {
      send_cmessage(451, "Proxy unable to comply. in eprt_parse");
      return;
    }

    port = trustwave_get_port(&listenaddr);
    trustwave_inet_ntop(&listenaddr, buffer, INET6_ADDRSTRLEN);
    ///  port = trustwave_get_port(&sa);

    newbuf = sstr_init(60);

    if (AF_INET == listenaddr.ss_family) {
      // on success convert, build message for ipv4*/
      sstr_apprintf(newbuf, "|1|%s|%d|", buffer, port);
    } else { // assume we are ipv6*/
      sstr_apprintf(newbuf, "|2|%s|%d|", buffer, port);
    }

    write_log(VERBOSE, "newbuf=%s", sstr_buf(newbuf));
    write_log(VERBOSE, "Rewritten EPRT command:");

    send_command(cmd, newbuf);
    sstr_free(newbuf);
  }
}

/* ------------------------------------------------------------- **
** Intercepted a PASV command.
**
** Parse the 227 reply message. Either: a) We are transparently
** proxying the data connection - send the 227 through unchanged, and
** do a intercept_listen() for when the client tries to connect. b) We
** aren't - listen on a port of our own and rewrite the 227 with that.
** c) For PAConv open a port for the client, open a port for the server,
** and send the server a PORT command.
** ------------------------------------------------------------- */
void pasv_parse(sstr *cmd, sstr *arg) {

  write_log(VERBOSE, "pasv_parse entry");
  int a1, a2, a3, a4, p1, p2;
  struct sockaddr_in tmp;
  int code;
  sstr *msg, *newbuf;

  write_log(VERBOSE, "Intercepted a PASV command");

  info->mode = PASSIVE;
  rclose(&info->client_listen);
  rclose(&info->server_listen);
  rclose(&info->server_data.fd);
  rclose(&info->client_data.fd);

  if (config.paconv) {

    socklen_t len;
    newbuf = sstr_init(60);

    info->mode = PACONV;

    write_log(VERBOSE, "Rewriting PASV command to PORT");
    write_log(VERBOSE, "Start listening server-side socket");

    len = sizeof(tmp);
    getsockname(info->server_control.fd, (struct sockaddr *)&tmp, &len);

    tmp.sin_family = AF_INET;
    info->server_listen = listen_on_socket((struct sockaddr_storage *)&tmp, config.actvports);

    n2com(tmp, &a1, &a2, &a3, &a4, &p1, &p2);
    sstr_apprintf(newbuf, "%d,%d,%d,%d,%d,%d", a1, a2, a3, a4, p1, p2);
    send_ccommand("PORT", sstr_buf(newbuf));
    get_message(&code, NULL);

    if (code < 300) {
      write_log(VERBOSE, "Start listening client-side socket");
      get_local_address(info->client_control.fd, &tmp);
      info->client_listen = listen_on_socket((struct sockaddr_storage *)&tmp, config.pasvports);

      n2com(tmp, &a1, &a2, &a3, &a4, &p1, &p2);
      sstr_cpy2(newbuf, "");
      sstr_apprintf(newbuf, "Entering Passive Mode"
                            "(%d,%d,%d,%d,%d,%d)",
                    a1, a2, a3, a4, p1, p2);
      send_message(227, newbuf);
    } else {
      send_cmessage(500, "Error in processing PASV");
    }

    sstr_free(newbuf);
    return;
  }

  send_command(cmd, arg);
  get_message(&code, &msg);

  tmp = extract_address(msg);
  memcpy(&info->server_data.address, &tmp, sizeof(struct sockaddr_in));

  if (!config_pasvok(&info->server_data.address)) {
    send_cmessage(500, "Bad passive command from server");
    return;
  }

  if (config.transdata) {
    struct sockaddr_in sa;
    memcpy(&sa, &tmp, sizeof(tmp));
    get_local_address(info->client_control.fd, &sa);

    struct sockaddr_storage tmpsa;
    memcpy(&tmpsa, &tmp, sizeof(tmp));

    info->client_listen = intercept_listen(info->server_data.address, tmpsa, config.pasvports);

    if (info->client_listen != -1) {
      send_message(227, msg);
      info->mode = PASSIVE;
      return;
    }
    write_log(VERBOSE, "Intercept_listen failed. Rewriting 227 reply instead");
  }

  get_local_address(info->client_control.fd, &tmp);
  info->client_listen = listen_on_socket((struct sockaddr_storage *)&tmp, config.pasvports);

  if (info->client_listen == -1) {
    send_cmessage(451, "Screwed up pasv command.");
    return;
  }

  n2com(tmp, &a1, &a2, &a3, &a4, &p1, &p2);

  newbuf = sstr_init(60);
  sstr_apprintf(newbuf, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", a1, a2, a3, a4, p1, p2);

  write_log(VERBOSE, "Rewritten 227 reply:");

  send_message(227, newbuf);
  info->mode = PASSIVE;
  sstr_free(newbuf);
}

/* Interceped and EPSV - command request that a server listen on the data
 * port and wait for a connection. see (rfc2428)
 */
void epsv_parse(sstr *cmd, sstr *arg) {
  sstr *msg, *newbuf;
  struct sockaddr_storage tmp;
  int code;
  uint16_t port;
  char buffer[INET6_ADDRSTRLEN] = {0};
  write_log(VERBOSE, "EPSV parse");

  info->mode = PASSIVE;

  rclose(&info->client_listen);
  rclose(&info->server_listen);
  rclose(&info->server_data.fd);
  rclose(&info->client_data.fd);

  if (config.paconv) {

    socklen_t len;
    newbuf = sstr_init(60);

    info->mode = PACONV;

    write_log(VERBOSE, "Rewriting EPSV command to EPRT");
    write_log(VERBOSE, "Start listening server-side socket");

    len = sizeof(tmp);
    getsockname(info->server_control.fd, (struct sockaddr *)&tmp, &len);

    tmp.ss_family = AF_INET6;
    info->server_listen = listen_on_socket(&tmp, config.actvports);

    if (-1 == info->server_listen) {
      tmp.ss_family = AF_INET;
      info->server_listen = listen_on_socket(&tmp, config.actvports);
    }

    port = trustwave_get_port(&tmp);

    memset(buffer, 0, INET6_ADDRSTRLEN);

    if (!trustwave_inet_ntop(&tmp, buffer, INET6_ADDRSTRLEN)) {
      write_log(ERROR, "failed to convert network to presentation address in epsv_parse");
      return;
    }

    if (AF_INET == tmp.ss_family) {
      // on success convert, build message for ipv4
      sstr_apprintf(newbuf, "|1|%s|%d|", buffer, port);
    } else { // assume we are ipv6
      sstr_apprintf(newbuf, "|2|%s|%d|", buffer, port);
    }
    write_log(VERBOSE, "EPRT %s", sstr_buf(newbuf));
    send_ccommand("EPRT", sstr_buf(newbuf));
    get_message(&code, NULL);

    if (code < 300) {
      write_log(VERBOSE, "Start listening client-side socket");
      if (AF_INET == tmp.ss_family)
        get_local_address(info->client_control.fd, (struct sockaddr_in *)&tmp);
      else {
        get_local_address6(info->client_control.fd, (struct sockaddr_in6 *)&tmp);
      }

      info->client_listen = listen_on_socket((struct sockaddr_storage *)&tmp, config.pasvports);

      memset(buffer, 0, INET6_ADDRSTRLEN);
      if (!trustwave_inet_ntop(&tmp, buffer, INET6_ADDRSTRLEN)) {
        write_log(ERROR, "failed to convert network to presentation address in epsv_parse");
        return;
      }

      port = trustwave_get_port(&tmp);

      sstr_cpy2(newbuf, "");
      sstr_apprintf(newbuf, "Entering Extended Passive Mode (|||%d|)", port);
      send_message(229, newbuf);

    } else {
      send_cmessage(500, "Error in processing EPSV");
    }

    sstr_free(newbuf);
    return;
  }

  send_command(cmd, arg);
  get_message(&code, &msg);

  tmp = extract_address6(msg);
  write_log(VERBOSE, "setting port for server data!");
  memcpy(&info->server_data.address, &info->final_server_address, sizeof(info->final_server_address));
  trustwave_set_port(&info->server_data.address, trustwave_get_port(&tmp));

  if (!config_pasvok(&info->server_data.address)) {
    send_cmessage(500, "Bad EPSV command from server");
    return;
  }

  if (config.transdata) {
    if (AF_INET == tmp.ss_family)
      get_local_address(info->client_control.fd, (struct sockaddr_in *)&tmp);
    else {
      get_local_address6(info->client_control.fd, (struct sockaddr_in6 *)&tmp);
    }

    struct sockaddr_storage tmpsa;
    memcpy(&tmpsa, &tmp, sizeof(tmp));

    info->client_listen = intercept_listen(info->server_data.address, tmpsa, config.pasvports);

    if (info->client_listen != -1) {
      send_message(229, msg);
      info->mode = PASSIVE;
      return;
    }

    write_log(VERBOSE, "Intercept_listen failed. Rewriting 229 reply instead");
  }

  if (AF_INET == tmp.ss_family)
    get_local_address(info->client_control.fd, (struct sockaddr_in *)&tmp);
  else {
    get_local_address6(info->client_control.fd, (struct sockaddr_in6 *)&tmp);
  }

  info->client_listen = listen_on_socket(&tmp, config.pasvports);

  if (info->client_listen == -1) {
    send_cmessage(451, "Screwed up epsv command.");
    return;
  }

  memset(buffer, 0, INET6_ADDRSTRLEN);
  if (!trustwave_inet_ntop(&tmp, buffer, INET6_ADDRSTRLEN)) {
    write_log(ERROR, "failed to convert network to presentation address in epsv_parse");
    return;
  }
  port = trustwave_get_port(&tmp);

  newbuf = sstr_init(60);
  sstr_apprintf(newbuf, "Entering Extended Passive Mode (|||%d|)", port);
  write_log(VERBOSE, "Rewritten 229 reply:");

  send_message(229, newbuf);
  info->mode = PASSIVE;
  sstr_free(newbuf);
}

/* ------------------------------------------------------------- **
** Intercepted an ABOR -- we need to send telnet IPs etc.
** ------------------------------------------------------------- */
void abor_parse(sstr *cmd, sstr *arg) {
  int code;
  rclose(&info->server_data.fd);
  rclose(&info->client_data.fd);
  info->state = NEITHER;
  vscan_abort();

  get_message(&code, NULL);
  send_cmessage(426, "Transfer aborted. Data connection closed.");
  send_cmessage(226, "Abort successful");
  return;
}

// FINJAN_START
void build_path(sstr *url, sstr *arg) {
  // client has send absolute path
  if (sstr_getchar(arg, 0) == '/') // first character '/'
  {
    write_log(VERBOSE, "Client send absoulte path");
    if (sstr_getchar(arg, sstr_len(arg) - 1) != '/') // add '/' in case that missing
    {
      sstr_ncat2(arg, "/", 1);
      write_log(VERBOSE, "Adding missing '/'");
    }
    sstr_cpy(url, arg);
  }
  // client has send relative path
  else {
    write_log(VERBOSE, "Client send relative path");
    urlescape(url, "% ;"); // replace non printable characters
    sstr_cat(url, arg);
    if (sstr_getchar(url, sstr_len(url) - 1) != '/') // add '/' in case that missing
      sstr_ncat2(url, "/", 1);
  }
}
// FINJAN_END

/* ------------------------------------------------------------- **
** Keep track of directory for logging (and ?caching) purposes.
** ------------------------------------------------------------- */
void cwd_command(sstr *cmd, sstr *arg) {
  int code;
  sstr *msg;

  send_command(cmd, arg);

  get_message(&code, &msg);
  send_message(code, msg);

  if (code > 299)
    return;

  // FINJAN_START

  //	if(sstr_getchar(cmd, 1) == 'D')
  //		/*CDUP*/ sstr_ncat2(info->strictpath, "..", 2);
  //	else {
  //		 /*CWD*/ urlescape(arg, "%/ ;");
  //		sstr_cat(info->strictpath, arg);
  //	}
  //	sstr_ncat2(info->strictpath, "/", 1);
  //	write_log(VERBOSE, "Strictpath = \"%s\"", sstr_buf(info->strictpath));

  if (sstr_getchar(cmd, 1) == 'D') {
    sstr *tmp = sstr_init(0);
    sstr_cpy2(tmp, "..");
    build_path(info->strictpath, tmp);
  } else {
    build_path(info->strictpath, arg);
  }

  // FINJAN_END
}

/* ------------------------------------------------------------- **
** Commands that require a data stream.
** ------------------------------------------------------------- */
void xfer_command(sstr *cmd, sstr *arg) {
  if (info->mode == APCONV) {
    write_log(VERBOSE, "Connecting to both data streams for %s command", sstr_buf(cmd));
    if (connect_client_data() == -1) {
      send_cmessage(425, "Can't open data connection");
      return;
    }

    if (connect_server_data() == -1) {
      send_cmessage(425, "Can't open data connection");
      return;
    }
  }

  if (sstr_casecmp2(cmd, "LIST") && sstr_casecmp2(cmd, "NLST")) {
    info->needs_logging = TRUE;
    info->virus = -1;
    info->cached = 0;
    sstr_cpy(info->filename, arg);
    // FINJAN_START
    //		urlescape(info->filename, "% ;/");
    urlescape(info->filename, "% ;");
    // FINJAN_END
  }

  if (!sstr_casecmp2(cmd, "RETR") || !sstr_casecmp2(cmd, "LIST") ||
      !sstr_casecmp2(cmd, "MLSD") || !sstr_casecmp2(cmd, "NLST"))
    info->state = DOWNLOAD;
  else
    info->state = UPLOAD;
  info->upload = info->state == UPLOAD;
  send_command(cmd, arg);

  // if requested for APPEND command and virus
  // was not clear then do not allow APPEND.
  if (!sstr_casecmp2(cmd, "APPE") && info->virus != 0) {
    abor_parse(cmd, arg);
  }

  if (!sstr_casecmp2(cmd, "RETR") || !sstr_casecmp2(cmd, "STOR"))
    vscan_new(0);
}
