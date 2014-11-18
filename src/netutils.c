/****************************************************************************

    NETUTILS.C - NSCA Network Utilities

    License: GPL
    Copyright (c) 1999-2006 Ethan Galstad (nagios@nagios.org)

    Last Modified: 01-21-2006

    Description:

    This file contains common network functions used in nrpe and check_nrpe.

    License Information:

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
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

 ****************************************************************************/

#include "../include/common.h"
#include "../include/netutils.h"
#include "../include/utils.h"

/* opens a tcp or udp connection to a remote host */
// removed sd arg, returns null or sd
int my_connect(char *host_name, int port) {
	struct sockaddr_in servaddr;
	struct hostent *hp;
	int sd;

	clear_buffer((char *)&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);

	/* try to bypass using a DNS lookup if this is just an IP address */
	if (!my_inet_aton(host_name, &servaddr.sin_addr)) {

		/* else do a DNS lookup */
		hp = gethostbyname((const char *)host_name);
		if (!hp) {
			printf("%s \'%s\'\n", "Invalid host name", host_name);
			return 0;
		}

		memcpy(&servaddr.sin_addr, hp->h_addr,
			(hp->h_length < sizeof(servaddr.sin_addr)) ? hp->h_length : sizeof(servaddr.sin_addr));
	}

	/* create a socket */
	if ((sd = socket(PF_INET, SOCK_STREAM, PRTP_PROTO)) <= 0) {
		printf("%s\n", "Socket creation failed");
		return 0;
	}

	/* open a connection */
	if (connect(sd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
		printf("%s - %s\n", "Connection failed:", strerror(errno));
		return 0;
	}

	return sd;
}

/*  This code was taken from Fyodor's nmap utility, which was originally taken from
    the GLIBC 2.0.6 libraries because Solaris doesn't contain the inet_aton() funtion. */
int my_inet_aton(const char *cp, struct in_addr *addr) {
	uint32_t val;	/* changed from u_long --david */
	int base, n;
	char c;
	uint32_t parts[4];	//TODO is this portable to 64bit archs?
	uint32_t *pp = parts;

	c = *cp;

	for (;;) {

		/*
		    Collect number up to ``.''.
		    Values are specified as for C:
		    0x=hex, 0=octal, isdigit=decimal.
		*/
		if (!isdigit((int)c))
			return (0);
		val = 0;
		base = 10;

		if (c=='0') {
			c = *++cp;
			if (c == 'x' || c == 'X')
				base = 16, c = *++cp;
			else
				base = 8;
		}

		for (;;) {
			if (isascii((int)c) && isdigit((int)c)) {
				val = (val * base) + (c - '0');
				c = *++cp;
			} else if (base == 16 && isascii((int)c) && isxdigit((int)c)) {
				val = (val << 4) | (c + 10 - (islower((int)c) ? 'a' : 'A'));
				c = *++cp;
			} else
				break;
		}

		if (c == '.') {

			/*
			    Internet format:
			 	a.b.c.d
			 	a.b.c	(with c treated as 16 bits)
			 	a.b	(with b treated as 24 bits)
			*/
			if (pp >= parts + 3)
				return (0);
			*pp++ = val;
			c = *++cp;
		} else
			break;
	}

	/* Check for trailing characters */
	if (c && (!isascii((int)c) || !isspace((int)c)))
		return (0);

	/* Concoct the address according to the number of parts specified */
	n = pp - parts + 1;
	switch (n) {

		case 0:
			return (0);		/* initial nondigit */

		case 1:				/* a -- 32 bits */
			break;

		case 2:				/* a.b -- 8.24 bits */
			if (val > 0xffffff)
				return (0);
			val |= parts[0] << 24;
			break;

		case 3:				/* a.b.c -- 8.8.16 bits */
			if (val > 0xffff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16);
			break;

		case 4:				/* a.b.c.d -- 8.8.8.8 bits */
			if (val > 0xff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
			break;
	}

	if (addr)
		addr->s_addr = htonl(val);

	return (1);
}

/* sends all data - thanks to Beej's Guide to Network Programming */
int sendall(int s, char *buf, int len) {
	int total = 0;
	int n = 0;

	while (total < len) {
		if ((n = send(s, buf+total, len-total, 0)) == -1)
			break;
		total += n;
	}

	/* return -1 on failure, bytes on success */
	return n;
}


/* receives all data - modelled after sendall() */
int recvall(int s, char *buf, int len, int timeout) {
	int total=0;
	int n=0;
	time_t start_time;
	time_t current_time;

	/* clear the receive buffer */
	clear_buffer(buf, len);

	time(&start_time);

	/* receive all data */
	while (total < len) {

		/* receive some data */
		n = recv(s, buf+total, len-total, 0);

		/* no data has arrived yet (non-blocking socket) */
		if (n == -1) {
			if (errno == EAGAIN) {
				time(&current_time);
				if (current_time - start_time > timeout)
					break;
				sleep(1);
				continue;
			}
			else {
				printf("%s - %s\n", "Recieve error:", strerror(errno));
				break;
			}
		}

		/* receive error or client disconnect */
		else if (n == 0)
			break;

		/* apply bytes we received */
		total += n;
	}

	/* return <=0 on failure, bytes received on success */
	return (n <= 0) ? n : total;
}
