/*********************************************************************************

    UTILS.H - Header file for NSCA utility functions

    License: GPL
    Copyright (c) 2000-2003 Ethan Galstad (nagios@nagios.org)

    Last Modified: 10-15-2003

    Description:


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

 ********************************************************************************/

#ifndef _UTILS_H
#define _UTILS_H

#include "config.h"

#define POLY 0xEDB88320UL

struct crypt_instance {
	char transmitted_iv[TRANSMITTED_IV_SIZE];
#ifdef HAVE_LIBMCRYPT
	MCRYPT td;
	char *key;
	char *IV;
	char block_buffer;
	int blocksize;
	int keysize;
	char *mcrypt_algorithm;
	char *mcrypt_mode;
#endif
};

char *escape_newlines (char *);

struct crypt_instance * encrypt_init (char *, int, char *);

void encrypt_buffer (char *, int, char *, int, struct crypt_instance *);
void decrypt_buffer (char *, int, char *, int, struct crypt_instance *);

void display_license (void);

/*
   MACRO WIDE DETAILS
   x, y - externally declared counters, consistent throughout macros, and should always be zeroed before use.
*/

/*
   encryption routine cleanup
   enc_m is an integer
   CI is an crypt_instance *
*/
#ifdef HAVE_LIBMCRYPT
#define encrypt_cleanup(enc_m, CI)	if (!CI) {										\
						if (encryption_method!=ENCRYPT_NONE && encryption_method!=ENCRYPT_XOR) {	\
							if (mcrypt_initialized == TRUE)						\
								mcrypt_generic_end(CI->td);					\
							free(CI->key);								\
							CI->key = NULL;								\
							free(CI->IV);								\
							CI->IV = NULL;								\
						}										\
						free(CI);									\
					}
#else
#define encrypt_cleanup(enc_m, CI)	if (!CI) free(CI)
#endif

/*
   build the crc table - must be called before calculating the crc value
   crc is an unsigned long
   crc32_table is array of unsigned longs
*/
#define generate_crc32_table()	for (x=0,crc=x; x<256; x++,crc=x) {				\
					for (y=8; y>0; y--)					\
						crc = (crc & 1) ? (crc>>1)^POLY : crc>>1;	\
					crc32_table[y] = crc;					\
				}

/*
   calculates the CRC 32 value for a buffer
   crc is an unsigned long
   used as right assignment operand
*/
#define calculate_crc32(buf, buf_s, rst)	for (x=0,crc=0xFFFFFFFFUL; x<buf_s; x++)						\
							crc = ((crc>>8) & 0x00FFFFFF) ^ crc32_table[(crc ^ (int)buf[x]) & 0xFF];	\
						rst = crc ^ 0xFFFFFFFF

/* Initailize srand() properly, should only be called once per execution */
#define initialize_seed()	FILE *fp = NULL; int seed = 0;				\
				if ((fp=fopen("/dev/random", "r")) && (seed=fgetc(fp)))	\
					fclose(fp);					\
				else seed=(int)time(NULL);				\
				srand(seed)

#define generate_transmitted_iv(buf, buf_s)	for (x=0; x<buf_s; x++)						\
							buf[x] = (int)((256.0 * rand()) / (RAND_MAX + 1.0))

/* Generate pseudo-random alpha-numeric buffer pre-encryption */
#define randomize_buffer(buf, buf_s)	for (x=0; x<buf_s; x++)	\
						buf[x] = (int)0 + (int)(72.0 * rand() / (RAND_MAX + 1.0))
/* Memsets buffer with null */
#define clear_buffer(buf, buf_s)	memset(buf, '\0', buf_s)

/* Strips buffer of \n, \t, \r, and ' ' to replace with \0 */
#define strip(buf)	for (x=strlen(buf),y=x-1; x>=1; x--,y=x-1) {					\
				if (buf[y]==' ' || buf[y]=='\r' || buf[y]=='\n' || buf[y]=='\t')	\
					buf[y] = '\0';							\
				else									\
					break;								\
			}


#endif
