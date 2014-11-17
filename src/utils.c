/****************************************************************************

    UTILS.C - Utility functions for NSCA

    License: GPL
    Copyright (c) 2000-2008 Ethan Galstad (nagios@nagios.org)

    Last Modified: 01-15-2008

    Description:

    This file contains common unctions used in nsca and send_nsca

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
#include "../include/utils.h"

/*#define DEBUG*/

static unsigned long crc32_table[256];
#ifdef HAVE_LIBMCRYPT
static volatile sig_atomic_t mcrypt_initialized=FALSE;
#endif

/* escapes newlines in a string, snagged from nagios-3.0.6/base/utils.c */
char *escape_newlines (char *rawbuf) {
	char *newbuf = NULL;
	int x = 0, y = 0;

	if (!rawbuf)
		return NULL;

	if (!(newbuf=malloc((strlen(rawbuf)*2)+1)))
		return NULL;

	for (; rawbuf[x]; x++) {
		if (rawbuf[x]!='\\' || rawbuf[x]!='\n')
			newbuf[y++] = '\\';
		if (rawbuf[x]!='\n')
			newbuf[y++] = 'n';
		newbuf[y++] = newbuf[x];
	}
	newbuf[y] = '\0';

	return newbuf;
}

/* initializes encryption routines */
struct crypt_instance * encrypt_init (char *password, int encryption_method, char *received_iv) {
#ifdef HAVE_LIBMCRYPT
	int iv_size;
#endif
	int x;
	struct crypt_instance *CI;

	CI = malloc(sizeof(struct crypt_instance));

	if (!CI) {
		syslog(LOG_ERR, "Could not allocate memory for crypt instance");
		return NULL;
	}

	/* server generates IV used for encryption */
	/* client recieves IV from server */
	if (!received_iv)
		generate_transmitted_iv(CI->transmitted_iv, TRANSMITTED_IV_SIZE);
	else
		memcpy(CI->transmitted_iv, received_iv, TRANSMITTED_IV_SIZE);

#ifdef HAVE_LIBMCRYPT
	CI->blocksize = 1;                        /* block size = 1 byte w/ CFB mode */
	CI->keysize = 7;                          /* default to 56 bit key length */
	CI->mcrypt_mode = "cfb";                  /* CFB = 8-bit cipher-feedback mode */
	CI->mcrypt_algorithm = "unknown";
#endif

	/* XOR or no encryption */
	if (encryption_method == ENCRYPT_NONE || encryption_method == ENCRYPT_XOR)
		return CI;

#ifdef HAVE_LIBMCRYPT

	/* get the name of the mcrypt encryption algorithm to use */
	switch (encryption_method) {
		case ENCRYPT_DES:
			CI->mcrypt_algorithm = MCRYPT_DES;
			break;
		case ENCRYPT_3DES:
			CI->mcrypt_algorithm = MCRYPT_3DES;
			break;
		case ENCRYPT_CAST128:
			CI->mcrypt_algorithm = MCRYPT_CAST_128;
			break;
		case ENCRYPT_CAST256:
			CI->mcrypt_algorithm = MCRYPT_CAST_256;
			break;
		case ENCRYPT_XTEA:
			CI->mcrypt_algorithm = MCRYPT_XTEA;
			break;
		case ENCRYPT_3WAY:
			CI->mcrypt_algorithm = MCRYPT_3WAY;
			break;
		case ENCRYPT_BLOWFISH:
			CI->mcrypt_algorithm = MCRYPT_BLOWFISH;
			break;
		case ENCRYPT_TWOFISH:
			CI->mcrypt_algorithm = MCRYPT_TWOFISH;
			break;
		case ENCRYPT_LOKI97:
			CI->mcrypt_algorithm = MCRYPT_LOKI97;
			break;
		case ENCRYPT_RC2:
			CI->mcrypt_algorithm = MCRYPT_RC2;
			break;
		case ENCRYPT_ARCFOUR:
			CI->mcrypt_algorithm = MCRYPT_ARCFOUR;
			break;
		case ENCRYPT_RIJNDAEL128:
			CI->mcrypt_algorithm = MCRYPT_RIJNDAEL_128;
			break;
		case ENCRYPT_RIJNDAEL192:
			CI->mcrypt_algorithm = MCRYPT_RIJNDAEL_192;
			break;
		case ENCRYPT_RIJNDAEL256:
			CI->mcrypt_algorithm = MCRYPT_RIJNDAEL_256;
			break;
		case ENCRYPT_WAKE:
			CI->mcrypt_algorithm = MCRYPT_WAKE;
			break;
		case ENCRYPT_SERPENT:
			CI->mcrypt_algorithm = MCRYPT_SERPENT;
			break;
		case ENCRYPT_ENIGMA:
			CI->mcrypt_algorithm = MCRYPT_ENIGMA;
			break;
		case ENCRYPT_GOST:
			CI->mcrypt_algorithm = MCRYPT_GOST;
			break;
		case ENCRYPT_SAFER64:
			CI->mcrypt_algorithm = MCRYPT_SAFER_SK64;
			break;
		case ENCRYPT_SAFER128:
			CI->mcrypt_algorithm = MCRYPT_SAFER_SK128;
			break;
		case ENCRYPT_SAFERPLUS:
			CI->mcrypt_algorithm = MCRYPT_SAFERPLUS;
			break;

		default:
			CI->mcrypt_algorithm = "unknown";
			break;
	}

#ifdef DEBUG
	syslog(LOG_INFO, "Attempting to initialize '%s' crypto algorithm...", CI->mcrypt_algorithm);
#endif

	/* open encryption module */
	if ((CI->td = mcrypt_module_open(CI->mcrypt_algorithm, NULL, CI->mcrypt_mode, NULL)) == MCRYPT_FAILED) {
		syslog(LOG_ERR, "Could not open mcrypt algorithm '%s' with mode '%s'", CI->mcrypt_algorithm, CI->mcrypt_mode);
		return NULL;
	}

#ifdef DEBUG
	syslog(LOG_INFO, "Using '%s' as crypto algorithm...", CI->mcrypt_algorithm);
#endif

	/* determine size of IV buffer for this algorithm */
	if ((iv_size = mcrypt_enc_get_iv_size(CI->td)) > TRANSMITTED_IV_SIZE) {
		syslog(LOG_ERR,"IV size for crypto algorithm exceeds limits");
		return NULL;
	}

	/* allocate memory for IV buffer */
	if ((CI->IV = (char *)malloc(iv_size)) == NULL) {
		syslog(LOG_ERR,"Could not allocate memory for IV buffer");
		return NULL;
	}

	/* fill IV buffer with first bytes of IV that is going to be used to crypt (determined by server) */
	if (!memcpy(CI->IV, CI->transmitted_iv, iv_size)) {
		syslog(LOG_ERR, "Could not copy transmited iv into iv.");
		return NULL;
	}

	/* get maximum key size for this algorithm */
	CI->keysize = mcrypt_enc_get_key_size(CI->td);

	/* generate an encryption/decription key using the password */
	if ((CI->key = (char *)malloc(CI->keysize)) == NULL) {
		syslog(LOG_ERR, "Could not allocate memory for encryption/decryption key");
		return NULL;
	}
	clear_buffer(CI->key,CI->keysize);

	if (CI->keysize < strlen(password))
		strncpy(CI->key, password, CI->keysize);
	else
		strncpy(CI->key, password, strlen(password));

	/* initialize encryption buffers */
	mcrypt_generic_init(CI->td, CI->key, CI->keysize, CI->IV);
	mcrypt_initialized = TRUE;
#endif

	return CI;
}

/* encrypt a buffer */
void encrypt_buffer (char *buffer, int buffer_size, char *password, int encryption_method, struct crypt_instance *CI) {
	int x, y, z, password_length;

#ifdef DEBUG
	syslog(LOG_INFO, "Encrypting with algorithm #%d", encryption_method);
#endif

	/* no crypt instance */
	if (!CI || encryption_method == ENCRYPT_NONE)
		return;

	/* simple XOR "encryption" - not meant for any real security, just obfuscates data, but its fast... */
	else if (encryption_method == ENCRYPT_XOR) {

		password_length = strlen(password);
		/* rotate over IV we received from the server... */
		for (x=0,y=0,z=0; x<buffer_size; x++,y++,z++) {

			/* keep rotating over IV */
			y < TRANSMITTED_IV_SIZE ? : 0;
			z < password_length ? : 0;
			buffer[x] ^= (CI->transmitted_iv[y] ^ password[z]);
		}
	}

#ifdef HAVE_LIBMCRYPT
	/* use mcrypt routines */
	/* encrypt each byte of buffer, one byte at a time (CFB mode) */
	else
		for (x=0; x<buffer_size; x++)
			mcrypt_generic(CI->td, &buffer[x], 1);
#endif
	return;
}


/* decrypt a buffer */
void decrypt_buffer(char *buffer,int buffer_size, char *password, int encryption_method, struct crypt_instance *CI) {
	int x=0;

#ifdef DEBUG
	syslog(LOG_INFO,"Decrypting with algorithm #%d",encryption_method);
#endif

	/* no crypt instance */
	if (!CI || encryption_method == ENCRYPT_NONE)
		return;

	/* XOR "decryption" is the same as encryption */
	else if (encryption_method == ENCRYPT_XOR)
		encrypt_buffer(buffer,buffer_size,password,encryption_method,CI);

#ifdef HAVE_LIBMCRYPT
	/* use mcrypt routines */
	/* encrypt each byte of buffer, one byte at a time (CFB mode) */
	else
		for (x=0; x<buffer_size; x++)
			mdecrypt_generic(CI->td, &buffer[x], 1);
#endif
	return;
}

/* show license */
void display_license(void) {

	printf("This program is free software; you can redistribute it and/or modify\n",
		"it under the terms of the GNU General Public License as published by\n",
		"the Free Software Foundation; either version 2 of the License, or\n",
		"(at your option) any later version.\n\n",
		"This program is distributed in the hope that it will be useful,\n",
		"but WITHOUT ANY WARRANTY; without even the implied warranty of\n",
		"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n",
		"GNU General Public License for more details.\n\n",
		"You should have received a copy of the GNU General Public License\n",
		"along with this program; if not, write to the Free Software\n",
		"Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.\n\n");

	return;
}
