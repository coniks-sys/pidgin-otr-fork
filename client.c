/* client.c
 * Public API for setting up SSL connections with the ConiksChat server.
 *
 * Basic client functionality taken from Beej's Guide. Adapted to SSL networking.
 *
 * Author: Marcela Melara
 */

/* system headers */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/* networking headers */
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* ssl headers */
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

/* client headers */
#include "client.h"

/* TODO: Will maybe have to put this in an ifdef or config file */
#define PORT "40012" // the port client will be connecting to

/* global variables */
static SSL_CTX *ctx;
static SSL *ssl;
static int sockfd;

RSA *pubkey;

// get sockaddr, IPv4 or IPv6:
static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/*---------------------------------------------------------------------*/
/*--- InitCTX - initialize the SSL engine.                          ---*/
/*---------------------------------------------------------------------*/
static SSL_CTX* InitCTX(void){   
  SSL_METHOD *method;
  SSL_CTX *ctx;
  
  OpenSSL_add_all_algorithms();		/* Load cryptos, et.al. */
  SSL_load_error_strings();			/* Bring in and register error messages */
  method = (SSL_METHOD *)SSLv3_client_method();		/* v3 is better, Create new client-method instance */
  ctx = SSL_CTX_new(method);			/* Create new context */
  if ( ctx == NULL )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
  return ctx;
}

/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out the certificates.                       ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl){   
  X509 *cert;
  char *line;
  
  cert = SSL_get_peer_certificate(ssl);	/* get the server's certificate */
  if ( cert != NULL ){
    printf("Server certificates:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Subject: %s\n", line);
    free(line);							/* free the malloc'ed string */
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    free(line);							/* free the malloc'ed string */
    X509_free(cert);					/* free the malloc'ed certificate copy */
  }
  else
    printf("No certificates.\n");
}

// setup and establish an SSL connection to the host
static int setup_conn(char *hostname){
 
  struct addrinfo hints, *servinfo, *p;
  int rv;
  char s[INET6_ADDRSTRLEN];
  
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  
  if ((rv = getaddrinfo(hostname, PORT, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }
  
  // loop through all the results and connect to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
                         p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }
    
    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("client: connect");
      continue;
    }
    
    break;
  }
  
  if (p == NULL) {
    fprintf(stderr, "client: failed to connect\n");
    return 2;
  }

  
  /* Already connected to server, so now do SSL stuff */
  SSL_library_init(); // new thing for init of ssl lib, needs to go before all SSL stuff
  ctx = InitCTX();
  // cannot verify self-signed certs...
  //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // tell the context to verify the peer's cert
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sockfd);

  if ( SSL_connect(ssl) == -1 ){			/* perform the connection */
        ERR_print_errors_fp(stderr);
  }
  else{
  
    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
              s, sizeof s);
    printf("client: connecting to %s with %s encryption\n", s, SSL_get_cipher(ssl));
    
    // extract the RSA public key from the cert
    X509 *cert;
    cert = SSL_get_peer_certificate(ssl);
    EVP_PKEY *pk;
    pk = X509_get_pubkey(cert);
    pubkey = EVP_PKEY_get1_RSA(pk);
    EVP_PKEY_free(pk);

    freeaddrinfo(servinfo); // all done with this structure
  }
  return 0;
}

static int int_to_bytes(int num, uint8_t **byte_arr){                
  //assuming that we won't need more than 255 bytes for representing num
  int numBytes = 0;
  if(num % 255 > 0){
    numBytes = (int)((num/255)+1);         
  }
  else{
    numBytes =  (int)(num/255);
  }
  
  *byte_arr = malloc(numBytes+1);
  uint8_t temp[numBytes+1];
  
  temp[0] = (uint8_t)numBytes;
  
  int counter = num;
  int i = 1;
  for(i = 1; i < numBytes+1; i++){
    if(counter < 255){
      break;
    }
    temp[i] = (uint8_t)(255);
    counter -= 255;
  }
  temp[numBytes] = (uint8_t)counter; //at this point, counter should be less than 
  memcpy(*byte_arr, temp, numBytes+1);
  
  return numBytes+1;
}

/* Establishes an SSL connection to the ConiksChat server and 
 * sends a message. 
 * Returns the number of bytes written or -1 for error.
 */
int send_msg(uint8_t type, char *msg, int len, char *server){

  setup_conn(server);

  int bytes_sent;

  // send message type: only sending one byte for the type  
  bytes_sent = SSL_write(ssl, &type, 1);

  // send length of message
  uint8_t *msg_len;
  int len_msg_len = int_to_bytes(len, &msg_len);

  bytes_sent += SSL_write(ssl, msg_len, len_msg_len);

  free(msg_len);

  if(bytes_sent <= 0){
    end_conn();
    return -1;
  }

  /* Sending message over ssl */
  bytes_sent += SSL_write(ssl, msg, len);  

  if(bytes_sent <= 0){
    end_conn();
    return -1;
  }

  // trying to flush the buffer here...
  
  return bytes_sent;
}

// get the response type from the server
uint8_t get_serv_resp_type(){
  uint8_t serv_resp[1];
  SSL_read(ssl, serv_resp, 1);
  return serv_resp[0];
}

/* Reads an incoming message from the ConiksChat server.
 * Returns the length of the serialized message.
 */
size_t recv_msg(uint8_t *resp_msg){

  size_t bytes_recv = 0;
  size_t nread;

  while ((nread=SSL_read(ssl, resp_msg + bytes_recv, 1)) != 0){
    bytes_recv += nread;
    if (bytes_recv == MAXDATASIZE){
      fprintf(stderr, "max message length exceeded\n");
      return 0;
    }
  }

  return bytes_recv;
}

/* Reads an incoming message from the ConiksChat server of a given length.
 * Returns the length of the serialized message.
 */
/*size_t recv_msg_with_len(uint8_t **resp_msg){
  
  size_t bytes_recv = 0;
  
  // first get the message length
  uint8_t num_len_bytes_buf[1];
  SSL_read(ssl, &num_len_bytes_buf[0], 1);
  
  int num_len_bytes = num_len_bytes_buf[0] & 0x000000ff;

  uint8_t msg_len_bytes[num_len_bytes];
  SSL_read(ssl, msg_len_bytes, num_len_bytes);
  
  int msg_len = 0;
  int i = 0;
  for(i = 0; i < num_len_bytes; i++){
    int next = msg_len_bytes[i] & 0x000000ff;
    msg_len += next;
  }
  
  // now read in the actual message
  *resp_msg = malloc(msg_len); // free'd by caller
  uint8_t *buf;
  buf = malloc(msg_len);
  
  bytes_recv = SSL_read(ssl, &buf, msg_len);
  memcpy(*resp_msg, buf, msg_len);
  free(buf);
  
  return bytes_recv;
  }*/

/* Closes an SSL connection. Assumes that the connection is already open.
 * Returns 0 for success, and -1 for failure. */
int end_conn(){
  
  if(ssl == NULL || sockfd < 0 || ctx == NULL){
    return -1;
  }

  SSL_free(ssl);
  close(sockfd);
  SSL_CTX_free(ctx);

  return 0;
}

// basic getter of the public key to be used in signature ops
RSA * get_server_pubkey(){
  return pubkey;
}
