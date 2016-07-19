/*
 *  Coniks key pair library for OTR messaging
 *  Copyright (C) 2014 Marcela Melara
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of version 2.1 of the GNU Lesser General
 *  Public License as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* system headers */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

/* libgcrypt headers */
#include <gcrypt.h>

/* libotr headers */
#include <libotr/privkey.h>
#include <libotr/proto.h>
#include <libotr/tlv.h>
#include <libotr/message.h>
#include <libotr/userstate.h>
#include <libotr/instag.h>
#include <libotr/serial.h>

#include "keypair.h"

struct s_pending_privkey_calc {
  char *accountname;
  char *protocol;
  gcry_sexp_t privkey;
};

/* Do the DSA key pair generation calculation.  You may call this from a
 * background thread.  When it completes, call
 * otrl_privkey_generate_finish from the _main_ thread. */
gcry_error_t coniks_otr_keypair_generate_calculate(void *newkey, gcry_sexp_t *pubkey)
{
  struct s_pending_privkey_calc *ppc =
	    (struct s_pending_privkey_calc *)newkey;
    gcry_error_t err;
    gcry_sexp_t key, parms;
    static const char *parmstr = "(genkey (dsa (nbits 4:1024)))";

    /* Create a DSA key */
    err = gcry_sexp_new(&parms, parmstr, strlen(parmstr), 0);
    if (err) {
	return err;
    }
    err = gcry_pk_genkey(&key, parms);
    gcry_sexp_release(parms);
    if (err) {
	return err;
    }

    /* Extract the privkey */
    ppc->privkey = gcry_sexp_find_token(key, "private-key", 0);
    gcry_sexp_t temp = gcry_sexp_find_token(key, "public-key", 0);
    *pubkey = gcry_sexp_find_token(temp, "dsa", 0);
    gcry_sexp_release(key);
    gcry_sexp_release(temp);

    return gcry_error(GPG_ERR_NO_ERROR);
}

static size_t get_keybuf_len(gcry_sexp_t sexp){
  size_t buflen;
   
  buflen = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);

  return buflen;
}

static gcry_error_t sexp_to_buf(gcry_sexp_t sexp, char **buf, size_t buflen){
  
  *buf = malloc(buflen);
   
   if (*buf == NULL && buflen > 0) {
     return gcry_error(GPG_ERR_ENOMEM);
   }
   gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, *buf, buflen);

   //don't call free(buf) because key pair generate will free after passing out to plugin

   return gcry_error(GPG_ERR_NO_ERROR);
}

/* Generate a DSA keypair for a given account, storing it into a
 * FILE*, and loading it into the given OtrlUserState.  Overwrite any
 * previously generated keys for that account in that OtrlUserState.
 * The FILE* must be open for reading and writing. */
gcry_error_t coniks_otr_keypair_generate_FILEp_str(OtrlUserState us, FILE *privf,
                                                   const char *accountname, const char *protocol, char **pubkey_buf){

  void *newkey = NULL;
  gcry_error_t err;
  gcry_sexp_t pk;
  
  err = otrl_privkey_generate_start(us, accountname, protocol, &newkey);
  if (newkey) {
    coniks_otr_keypair_generate_calculate(newkey, &pk);
    err = otrl_privkey_generate_finish_FILEp(us, newkey, privf);
  }
  
  size_t len = get_keybuf_len(pk);
  char *buf;

  err = sexp_to_buf(pk, &buf, len);

  *pubkey_buf = malloc(len);
  memcpy(*pubkey_buf, buf, len);

  gcry_sexp_release(pk);
  free(buf); // don't free pubkey_buf since the plugin will free it
  
  return err;
}

/* Generate a DSA keypair for a given account, storing it into a
 * FILE*, and loading it into the given OtrlUserState.  Overwrite any
 * previously generated keys for that account in that OtrlUserState.
 * The FILE* must be open for reading and writing. */
gcry_error_t coniks_otr_keypair_generate_FILEp(OtrlUserState us, FILE *privf,
                                               const char *accountname, const char *protocol, gcry_sexp_t *pubkey)
{
  void *newkey = NULL;
  gcry_error_t err;
  gcry_sexp_t pk;
  
  err = otrl_privkey_generate_start(us, accountname, protocol, &newkey);
  if (newkey) {
    coniks_otr_keypair_generate_calculate(newkey, &pk);
    err = otrl_privkey_generate_finish_FILEp(us, newkey, privf);
  }
  
  *pubkey = pk; // don't release since the plugin will free it
  
  return err;
}

/* Taken from libotr/src/privkey.c */
gcry_error_t extract_pubkey_param(const char *param, unsigned char ** pubbufp, size_t *publenp, gcry_sexp_t pubkey){

  gcry_mpi_t p;
  gcry_sexp_t ps;
  size_t np;
  enum gcry_mpi_format format = GCRYMPI_FMT_STD;
  unsigned char *bufp;
  size_t lenp;
  
  *pubbufp = NULL;
  *publenp = 0;
  
  /* Extract the public parameters */
  ps = gcry_sexp_find_token(pubkey, param, 0);

  if (!ps) {
    gcry_sexp_release(ps);
    return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
  }

  p = gcry_sexp_nth_mpi(ps, 1, GCRYMPI_FMT_STD);
  gcry_sexp_release(ps);

  if (!p) {
    gcry_mpi_release(p);
    return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
  }
  
  *publenp = 0;
  gcry_mpi_print(format, NULL, 0, &np, p);
  *publenp += np + 4;
  
  *pubbufp = malloc(*publenp);
  if (*pubbufp == NULL) {
    gcry_mpi_release(p);
    return gcry_error(GPG_ERR_ENOMEM);
  }
  bufp = *pubbufp;
  lenp = *publenp;
  
  // Write the integer into the buffer
  write_mpi(p,np,"P");
  
  gcry_mpi_release(p);
  
  return gcry_error(GPG_ERR_NO_ERROR);
  
}
