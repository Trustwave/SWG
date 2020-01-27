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

  vscan.c -- Called from localcache.c if virus scanning is enabled. We
  have two phases of operation: INCOMING and OUTGOING.

  When RETR is received it is forwarded to the server and we enter
  INCOMING mode. All incoming data is written to a temporary file, and
  the buffer length zeroed so it doesn't get written to either cache
  or client. The server's 150 reply is intercepted, and a multiline
  150 reply started instead - a line at a time every few seconds to
  prevent timeouts.

  On data connection close during INCOMING we scan the temporary file.
  If infected we send an error and return -1. If clean we switch to
  OUTGOING mode, and reopen the file for reading. This fd is returned
  and will become the new server_data fd.

  During the OUTGOING phase we do nothing. The data read from our
  temporary file will be sent to both client and cache file. On close
  we delete the temporary file.

problems:
  o Uploads not scanned
  o Sensitive to order of calls in l_retr_end and l_inc_data.
  o The file is written to disk on two occasions.

TODO Modify localcache.c to delete cache file header on failed scan.
  ***************************************/
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h> // for memcpy
#include "common.h"
#include "control.h"
#include "cache.h"
#include "vscan.h"

/*
 * Pablo: adde support for scanning uploads.
 * Modified files:
 *   vscan.c
 *   data.c
 *   ftp-cmds.c
 */

// FINJAN_START
#include "FTP_EXT_Plugin_Common.hpp"
// FINJAN_END

static char *argv[20];

static enum { NONE, INCOMING, OUTGOING } status = NONE;
static enum { STARTING, FINISHED, NOTHING } expected_reply = NOTHING;
static size_t size;
static size_t tsize;
static int fd = -1;
static char scanfile[BUF_LEN];
// FINJAN_START
static char clientIP[BUF_LEN] = {0};
static char clientUsername[BUF_LEN] = {0};
// VL
static char uri[2 * BUF_LEN + 65] = {0};
// flag whether to reflect NOOP response to client
static int block_noop_response_to_client = 0;
// FINJAN_END
static time_t lastprog;

// int vscan_scan(void);
int vscan_scan(char *);

/*This function run as root to allow making tmp dir*/
int vscan_init(void) {
  int i;
  char *p = config.vscanner;

  if (!config.vscanner)
    return 0;

  for (i = 0; i < 19; i++) {
    while (*p != 0 && *p++ != '"')
      ;
    if (*p == 0)
      break;
    argv[i] = p;
    while (*p != 0 && *p != '"')
      p++;
    if (*p == 0)
      break;
    *p++ = 0;
    if (!strcmp(argv[i], "%s")) {
      argv[i] = scanfile;
    }
    // FINJAN_START
    else if (!strcmp(argv[i], "%i")) {
      argv[i] = clientIP;
    } else if (!strcmp(argv[i], "%u")) {
      argv[i] = clientUsername;
    } else if (!strcmp(argv[i], "%p")) {
      argv[i] = uri;
    }
    // FINJAN_END
  }
  argv[i] = NULL;

  if (make_tmpdir() == -1)
    return (-1);

  snprintf(scanfile, BUF_LEN, "%s/tmp/VS_%d", config.chroot, getpid());
  write_log(VERBOSE, "VS: Virus scanner temp file is %s", scanfile);

  return 0;
}

void vscan_new(int sz) {
  if (!config.vscanner)
    return;
  fd = creat(scanfile, S_IRUSR | S_IWUSR);
  status = INCOMING;
  expected_reply = STARTING;
  time(&lastprog);
  size = sz;
  tsize = 0;
  write_log(VERBOSE, "VS: Downloading to temporary file");
}

void vscan_inc(sstr *inc) {
  time_t tmp;

  if (!config.vscanner)
    return;
  if (status == INCOMING) {
    tsize += sstr_len(inc);
    sstr_write(fd, inc, 0);
    sstr_empty(inc);
    time(&tmp);
    if (config.vscanpm && tmp - lastprog > config.vscanpm && expected_reply != STARTING &&
        info->state == DOWNLOAD) {
      sstr *msg;
      msg = sstr_init(500);
      if (size)
        sstr_apprintf(msg, "150-Downloaded %u/%u bytes to proxy", tsize, size);
      else
        sstr_apprintf(msg, "150-Downloaded %u bytes to proxy", tsize);
      send_message(0, msg);
      sstr_free(msg);
      lastprog = tmp;
    } else if (config.vscanpm && tmp - lastprog > config.vscanpm && expected_reply != STARTING &&
               info->state == UPLOAD) {
      sstr *msg;
      msg = sstr_init(500);
      if (size)
        sstr_apprintf(msg, "Uploaded %u/%u bytes to proxy", tsize, size);
      else
        sstr_apprintf(msg, "Uploaded %u bytes to proxy", tsize);
      send_message(-226, msg);
      sstr_free(msg);
      lastprog = tmp;
    }
  }
}

int vscan_switchover(void) {
  int tmp;

  if (status != INCOMING)
    return FALSE;

  rclose(&fd);

  // FINJAN_START
  status = OUTGOING;
  char blockReason[BUF_LEN] = {0};
  int ret = -1;
  //	if(!vscan_scan()) {
  if ((ret = vscan_scan(blockReason)) == 1 || ret == -1) {
    write_log(VERBOSE, "VS: Scan failed");
    if (config.vscanpm) {
      if (info->state == DOWNLOAD)
        send_cmessage(150, "Not starting Transfer");
    }
    if (info->state == DOWNLOAD) {
      if (ret == 1) {
        send_cmessage(451, blockReason);
        write_log(VERBOSE, "REASON: [%s]", blockReason);
      } else
        send_cmessage(451, "Failed to scan file. Aborting");
    } else {
      send_cmessage(226, blockReason);
    }
    unlink(scanfile);
    status = NONE;
    info->virus = TRUE;
    return FALSE;
  }
  // FINJAN_END
  info->virus = FALSE;
  write_log(VERBOSE, "VS: Scan complete. Changing fd");
  if (info->state == DOWNLOAD)
    send_cmessage(150, "Starting Transfer");
  tmp = open(scanfile, O_RDONLY);
  unlink(scanfile);
  int fd_data_origin = (info->state == DOWNLOAD) ? info->server_data.fd : info->client_data.fd;
  if (dup2(tmp, fd_data_origin) == -1) {
    debug_perr("dup2");
    die(ERROR, "Error changing file descriptors in vscan", 0, 0, -1);
  }
  close(tmp);
  return TRUE;
}

int vscan_end(void) {
  if (status == INCOMING)
    die(ERROR, "In vscan_end() and shouldn't be", 0, 0, -1);
  if (status == OUTGOING) {
    status = NONE;
    write_log(VERBOSE, "VS: Finished forwarding scanned file");
    send_cmessage(226, "Transfer Complete");
    return (VSCAN_OK);
  }
  return (VSCAN_OK);
}

void vscan_abort(void) {
  unlink(scanfile);
  status = NONE;
}

int vscan_parsed_reply(int code, sstr *msg) {
  switch (expected_reply) {
  case NOTHING:
    return (FALSE);
  case STARTING:
    if (code <= 0)
      return (TRUE);
    if (code > 299) { /*Failure */
      expected_reply = NOTHING;
      status = NONE;
      close(fd);
      unlink(scanfile);
      return (FALSE);
    }
    if (config.vscanpm) {
      if (info->state == DOWNLOAD) {
        send_cmessage(-150, "Starting Transfer (DOWNLOAD)");
        send_cmessage(0, "150-There'll be a delay while we "
                         "scan for viruses");
      } else if (info->state == UPLOAD) {
        send_cmessage(-150, "Starting Transfer (UPLOAD)");
        send_cmessage(150, "There'll be a delay while we "
                           "scan for viruses");
      } else {
        send_cmessage(code, "Starting Transfer. There'll "
                            "be a delay while we scan for viruses");
      }
    }
    expected_reply = FINISHED;
    return (TRUE);
  case FINISHED:
    if (code <= 0)
      return (TRUE);

    // patch to skip NOOP response in case of STOR and trickling
    if (info->state == UPLOAD && code == 500)
      return (TRUE);

    expected_reply = NOTHING;
    if (code > 299) { /*Failure */
      status = NONE;
      close(fd);
      // FINJAN_START
      unlink(scanfile);
      // FINJAN_END
      if (config.vscanpm) {
        if (info->state == DOWNLOAD)
          send_cmessage(150, "Error Aborting.");
        else
          send_cmessage(226, "Error Aborting.");
      }
      return (FALSE);
    }
    return (TRUE);
  }

  if (status == INCOMING)
    return (TRUE);
  return (FALSE);
}

// FINJAN_START
// int vscan_scan(void)
int vscan_scan(char *blockReason)
// FINJAN_END
{
  if (tsize >= config.vscan_limitaions[info->state].file_size_limit) {
    write_log(VERBOSE, "VS: File size is bigger than limit");
    if (!config.vscan_limitaions[info->state].continue_on_big_file) {
      write_log(VERBOSE, "VS: Configured behavior is to block ");
      strcpy(blockReason, "File size is to big for scan");
      return 1;
    } else {
      write_log(VERBOSE, "VS: Configured behavior is to not scan ");
      return 0;
    }
  }
  write_log(VERBOSE, "VS: Now scanning file");

  // FINJAN_START

  const char *str_abs_path = get_absolute_path(info);
  if (NULL == str_abs_path) {
    strcpy(uri, "ftp://");
  } else {
    int expectedLength = snprintf(uri, BUF_LEN, "ftp://%s%s", sstr_buf(info->server_hostname), str_abs_path);
    if (BUF_LEN <= expectedLength) {
      write_log(ERROR, "VS: Warning! URI buffer overflow (%d bytes required). URI truncated.",
                expectedLength);
    }
  }

  write_log(VERBOSE, "VS: URI %s", uri);
  // FINJAN_END

  if (config.vscanpm && info->state == DOWNLOAD)
    send_cmessage(0, "150-Scanning file for viruses");

  // FINJAN_START

  int contentStatus;
  snprintf(clientIP, BUF_LEN, "%s", sstr_buf(info->client_ip));
  snprintf(clientUsername, BUF_LEN, "%s", sstr_buf(info->client_username));

  if (-1 == scan_file(scanfile, clientIP, clientUsername, uri, &contentStatus,
                      (info->state == DOWNLOAD) ? 1 : 2,
                      &send_cmessage, // used for client trickling
                      &send_ccommand, // used to send noop to server
                      blockReason, &write_log)) {
    write_log(ERROR, "VS: Error occured while scanning for malicious content");
    return -1;
  }

  write_log(VERBOSE, "VS: Returned status: [%d]", contentStatus);
  return contentStatus;

  // FINJAN_END
}
void read_noop_reflection_flag() {
  static const char* conf_file = "/etc/wasp/Proxy.conf";
  struct stat file_st;
  FILE *conf;
  block_noop_response_to_client = 0;
   
  if (stat(conf_file, &file_st) == -1) {
    write_log(ERROR, "file %s is not found", conf_file);
    return;
  }
  char *conf_buff = malloc(file_st.st_size);
  if (conf_buff == NULL) {
    write_log(ERROR, "Can't allocate %d bytes", file_st.st_size);
    return;
  }
  conf = fopen(conf_file, "r");
  if (conf == NULL) {
    write_log(ERROR, "file %s can't be opened", conf_file);
    free(conf_buff);
    return;
  }
  if (0 < fread(conf_buff, file_st.st_size, 1, conf)) {
    conf_buff[file_st.st_size -1] = '\0';
    char *p = strstr(conf_buff, "block-noop-reflection");
    if (p) {
      char *end = strstr(p, ">");
      if (end) {
        *end = '\0';
        if (strstr(p, "enable"))
          block_noop_response_to_client = 1;
      }
    }
  }
  free(conf_buff);
  fclose(conf);  
  write_log(INFO, "block_noop_response_to_client = %d", block_noop_response_to_client);
}

int block_noop_reply(int code, sstr *arg) {
  if (! block_noop_response_to_client)
    return 0;
  char *p = sstr_buf(arg);
  char *pnoop = strstr(p, "NOOP");
  int cmp = sstr_casecmp2(arg, "OK");
  write_log(INFO, "block_noop_reply: code = %d; cmp = %d; pnoop = %s", code, cmp, pnoop);
  if ((code == 200) && ((cmp == 0) || pnoop))
    return 1;
  else
    return 0;
}
