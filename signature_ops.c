/* signature_ops.c
 * Public API for signature generation and verification in Coniks.
 *
 * Author: Marcela Melara
 */

/* system headers */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/* ssl headers */
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

/* coniks headers */
#include "coniks.h"

// verify a commitment signature based on the server
int verify_commitment_signature(RSA *serv_pubkey, unsigned char *sig, size_t sig_len, 
                                unsigned char *root_hash, size_t hash_len, char *err_msg){
  
  // our incoming original value is already hashed so all we need to do is decrypt
  // TODO: have server send back root node instead of hash
  char * err = malloc(1300);

  if(err == NULL){
    return -1;
  }

  int result;
  result = RSA_verify(NID_sha256, root_hash, hash_len, sig, sig_len, serv_pubkey);

  if(result < 0){
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("signature ops: Error verifying sig: %s\n", err);
    return -2;
  }
  
  return result;
  
}

// from stackoverflow 2262386
void sha256(unsigned char *input, int in_size, unsigned char *digest){
    SHA256_CTX sha256;
    if(SHA256_Init(&sha256) == 0){
      digest = NULL;
      return;
    }

    if(SHA256_Update(&sha256, input, in_size) == 0){
      digest = NULL;
      return;
    }

    if(SHA256_Final(digest, &sha256) == 0){
      digest = NULL;
      return;
    }
}
