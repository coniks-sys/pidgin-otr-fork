/* signature_ops.h
 * Header file.
 * Public API for signature generation and verification in Coniks.
 *
 * Author: Marcela Melara
 */

#include <openssl/rsa.h>

// verify a commitment signature based on the server
int verify_commitment_signature(RSA *serv_pubkey, unsigned char *sig, int sig_len, 
                                unsigned char *root_hash, int hash_len, char *err_msg);

// compute a SHA 256 hash of an input
void sha256(unsigned char *input, int in_size, unsigned char *digest);
