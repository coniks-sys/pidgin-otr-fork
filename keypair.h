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
#ifndef __KEYPAIR_H__
#define __KEYPAIR_H__

#include <gcrypt.h>
#include <libotr/userstate.h>

/* Do the DSA key pair generation calculation.  You may call this from a
 * background thread.  When it completes, call
 * otrl_privkey_generate_finish from the _main_ thread. */
gcry_error_t coniks_otr_keypair_generate_calculate(void *newkey, gcry_sexp_t *pubkey);

/* Generate a DSA keypair for a given account, storing it into a
 * FILE*, and loading it into the given OtrlUserState.  Overwrite any
 * previously generated keys for that account in that OtrlUserState.
 * The FILE* must be open for reading and writing. 
 * Note: public key is stored in char buffer. */
gcry_error_t coniks_otr_keypair_generate_FILEp_str(OtrlUserState us, FILE *privf,
                                               const char *accountname, const char *protocol, char **pubkey_buf);

/* Generate a DSA keypair for a given account, storing it into a
 * FILE*, and loading it into the given OtrlUserState.  Overwrite any
 * previously generated keys for that account in that OtrlUserState.
 * The FILE* must be open for reading and writing. 
 * Note: public key is stored in s-expression. */
gcry_error_t coniks_otr_keypair_generate_FILEp(OtrlUserState us, FILE *privf,
                                               const char *accountname, const char *protocol, gcry_sexp_t *pubkey);

gcry_error_t extract_pubkey_param(const char *param, unsigned char ** pubbufp, size_t *publenp, gcry_sexp_t pubkey);

#endif
