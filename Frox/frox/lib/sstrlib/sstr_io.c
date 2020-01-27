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

  sstr_io.c

***************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>

#include "sstr.h"
#include "sstr_private.h"

#define min(A,B) ((A) < (B) ? (A) : (B))

int sstr_apprintf(sstr * p, const char *fmt, ...)
{
	int n;
	size_t size;
	va_list ap;

	while(1) {
		size = p->maxlen - p->len;

		va_start(ap, fmt);
		n = vsnprintf(p->buf + p->len, size, fmt, ap);
		va_end(ap);

		if(n > -1 && n < size) {
			p->len += (size_t)n;
			return (n);	/*It fitted */
		}
		if(!p->growable)
			return (n);	/*Not growable. Not enough space */

		if(n > -1)
			return sstr_alloc_space(p, p->len + (size_t)n);
		else
			return sstr_alloc_space(p, p->len + (size_t)n + 25);
	}
}

ssize_t sstr_append_read(int fd, sstr * p, size_t cnt)
{
	int i;
	size_t si;
	ssize_t ssi;
	if(ioctl(fd, FIONREAD, &i) == -1)
		return (-1);
	if(i <= 0)
		return i;

	si = (size_t)i;
	if(cnt)
		si = min(si, cnt);
	if(p->growable)
		sstr_alloc_space(p, p->len + si);	/*Don't worry about failure */

	si = min(si, p->maxlen - p->len);
	if(si == 0)
		return (-1);	/*Buffer full */

	ssi = read(fd, p->buf + p->len, si);
	if(ssi == -1)
		return (-1);
	p->len += si;
	return (ssi);
}

ssize_t sstr_write(int fd, sstr * p, size_t cnt)
{
	return write(fd, p->buf, (cnt ? min(p->len, cnt) : p->len));
}

char *sstr_fgets(sstr * p, FILE * fp)
{
	char *s;

	p->len = 0;
	do {
		s = fgets(p->buf + p->len,(int) min((p->maxlen - p->len),INT_MAX), fp);
		if(!s)
			return (NULL);
		p->len = strlen(p->buf);
	} while(p->buf[p->len - 1] != '\n' &&
		sstr_alloc_space(p, p->len + 25) != -1);
	return (s);
}
