/* client.h
 * Header file.
 * Public API for setting up connections with the Coniks chat server
 *
 * Author: Marcela Melara
 */

#include <openssl/rsa.h>

#define MAXDATASIZE 8196 // max number of bytes we can get at once: TODO: allow for variable size

// Send a message to an established SSL connection
int send_msg(uint8_t type, char *msg, int len, char *server);

// get the response type from the server
uint8_t get_serv_resp_type();

// Reads an incoming message from the ConiksChat server
size_t recv_msg(uint8_t *resp_msg);

// Reads an incoming message from the ConiksChat server of a given length.
//size_t recv_msg_with_len(uint8_t **resp_msg);

// Closes an established SSL connection
int end_conn();

// basic getter of the public key to be used in signature ops
RSA * get_server_pubkey();
