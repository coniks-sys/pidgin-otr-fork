/* coniks.c
 * Public client-side API for exchanging messages with the Coniks chat server.
 * Uses the c2s.pb-c protobufs for message serialization.
 *
 * Author: Marcela Melara
 */

/* system headers */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>

/* coniks otr headers */
#include "coniks.h"
#include "client.h"
#include "c2s.pb-c.h"
#include "util.pb-c.h"
#include "signature_ops.h"

/* Create a new ConiksOtrState. This state encapsulates the last epoch during
   which the client performed a continuity check on itself, as well as the last commitment
   it saw for its provider */
ConiksOtrState create_coniks_state(void){
  ConiksOtrState cs = malloc(sizeof(struct s_ConiksOtrState));
  if(!cs) return NULL;
  cs->last_epoch = 0;
  cs->accountname = NULL;
  cs->last_comm = NULL;
  cs->serv_init_epoch = 0;
  cs->serv_epoch_interval = 0;        
  cs->check_status = unchecked_stat;

  return cs;
}

/* Set the ConiksOtrState based on the given last epoch and commitment verified by the client.
   Only updates it if the epoch is later than the current last_epoch. Assumes validity of new_comm
   has been verified. 
   return values: 0 for success, 1 for failure
*/
void update_coniks_state(ConiksOtrState cs, char * accountname, 
                         Protos__Commitment *new_comm)
{
  uint64_t new_ep = new_comm->epoch;
  
  if(new_ep < cs->last_epoch){
    return;
  }

  if (cs->accountname == NULL) {
    cs->accountname = strdup(accountname);
  }

  cs->last_epoch = new_ep;

  // TODO: this probably leaks memory
  cs->last_comm = new_comm;
  cs->check_status = done_stat;

}

/* Set the server parameters in the ConiksOtrState based on the cached, or received, information from the
   server upon registration. This only happens once per session */
void set_server_params(ConiksOtrState cs,  char * accountname,
                       uint64_t init_epoch, uint32_t epoch_interval) {
   if (cs->accountname == NULL) {
     cs->accountname = strdup(accountname);
   }

   cs->serv_init_epoch = init_epoch;
   
   cs->serv_epoch_interval = epoch_interval;
}

/* Free a ConiksOtrState. Used when tearing down the plugin */
void destroy_coniks_state(ConiksOtrState cs){
  free(cs->accountname);
  free(cs->last_comm->root_hash->hash);
  free(cs->last_comm->signature);
  free(cs->last_comm->root_hash);
  free(cs->last_comm);
  free(cs);
}

/* Read the server params for the coniks state from a file on disk into the given
 * ConiksOtrState. */
gcry_error_t read_coniks_server_params(ConiksOtrState cs, const char *filename){
  
  gcry_error_t err;
  FILE *serverf;
  
  serverf = fopen(filename, "rb");
  if (!serverf) {
    err = gcry_error_from_errno(errno);
    return err;
  }
  
  err = read_server_params_FILEp(cs, serverf);
  
  fclose(serverf);
  return err;
}

/* Read the coniks state from a file on disk into the given
 * ConiksOtrState. */
gcry_error_t read_coniks_state(ConiksOtrState cs, const char *filename){
  
  gcry_error_t err;
  FILE *coniksf;
  
  coniksf = fopen(filename, "rb");
  if (!coniksf) {
    err = gcry_error_from_errno(errno);
    return err;
  }
  
  err = read_coniks_state_FILEp(cs, coniksf);
  
  fclose(coniksf);
  return err;
}

/* The following 5 functions have been taken from libotr's privkey.c */
/* Convert a hex character to a value */
static unsigned int ctoh(char c)
{
    if (c >= '0' && c <= '9') return c-'0';
    if (c >= 'a' && c <= 'f') return c-'a'+10;
    if (c >= 'A' && c <= 'F') return c-'A'+10;
    return 0;  /* Unknown hex char */
}

/* Read the server parameters for the coniks state from a FILE* into the given
 * ConiksOtrState.  The FILE* must be open for reading. */
gcry_error_t read_server_params_FILEp(ConiksOtrState cs, FILE *serverf){

  char serverline[1000];
  size_t maxsize = sizeof(serverline);

    if (!serverf) return gcry_error(GPG_ERR_NO_ERROR);

    while(fgets(serverline, maxsize, serverf)) {
      char *accountname;
      char *init_epoch;
      char *epoch_interval;
      char *tab;
      char *eol;

      /* Parse the line, which should be of the form:
       *    accountname\tinit_epoch\tepoch_interval\n          */
      accountname = serverline;
      tab = strchr(accountname, '\t');
      if (!tab) continue;
      *tab = '\0';
      
      init_epoch = tab + 1;
      tab = strchr(init_epoch, '\t');
      if (!tab) continue;
      *tab = '\0';

      epoch_interval = tab + 1;
      tab = strchr(epoch_interval, '\t');
      if (!tab) {
        eol = strchr(epoch_interval, '\r');
        if (!eol) eol = strchr(epoch_interval, '\n');
        if (!eol) continue;
        *eol = '\0';
      }
      
      //set coniks state
      if (cs->accountname == NULL) {
        cs->accountname = strdup(accountname);
      }
      cs->serv_init_epoch =  atol(init_epoch);
      cs->serv_epoch_interval = atoi(epoch_interval);

    }
    
    return gcry_error(GPG_ERR_NO_ERROR);
}

/* Read the coniks state from a FILE* into the given
 * ConiksOtrState.  The FILE* must be open for reading. */
gcry_error_t read_coniks_state_FILEp(ConiksOtrState cs, FILE *coniksf){

  Protos__Hash *root_hash = malloc(sizeof(struct _Protos__Hash));
  Protos__Commitment *comm = malloc(sizeof(struct _Protos__Commitment));

  protos__hash__init(root_hash);
  protos__commitment__init(comm);

  //if (root_hash == NULL || comm == NULL) return gcry_error(GPG_ERR_ENOMEM);

  char coniksline[1000];
  size_t maxsize = sizeof(coniksline);

    if (!coniksf) return gcry_error(GPG_ERR_NO_ERROR);

    while(fgets(coniksline, maxsize, coniksf)) {
      char *accountname;
      char *epoch;
      char *len;
      char *len_hash;
      char *hash;
      char *len_sig;
      char *sig;
      char *tab;
      char *eol;
      unsigned int i, j;

      /* Parse the line, which should be of the form:
       *    accountname\tlast_epoch\tn_hash\troot_hash_hex\tn_signature\tsignature_hex\n          */
      accountname = coniksline;
      tab = strchr(accountname, '\t');
      if (!tab) continue;
      *tab = '\0';
      
      epoch = tab + 1;
      tab = strchr(epoch, '\t');
      if (!tab) continue;
      *tab = '\0';

      len = tab + 1;
      tab = strchr(len, '\t');
      if (!tab) continue;
      *tab = '\0';
      
      len_hash = tab + 1;
      tab = strchr(len_hash, '\t');
      if (!tab) continue;
      *tab = '\0';
      
      hash = tab + 1;
      tab = strchr(hash, '\t');
      if (!tab) continue;
      *tab = '\0';
      
      len_sig = tab + 1;
      tab = strchr(len_sig, '\t');
      if (!tab) continue;
      *tab = '\0';
      
      sig = tab + 1;
      tab = strchr(sig, '\t');
      if (!tab) {
        eol = strchr(sig, '\r');
        if (!eol) eol = strchr(sig, '\n');
        if (!eol) continue;
        *eol = '\0';
      }
      
      //set root hash
      root_hash->len = atoi(len);
      root_hash->n_hash = atoi(len_hash);
      uint32_t *hash_buf = malloc(root_hash->n_hash*sizeof(uint32_t));
      //if (hash_buf == NULL) return gcry_error(GPG_ERR_ENOMEM);
      if (strlen(hash) != root_hash->n_hash*2) continue;
      for(j=0, i=0; i<root_hash->n_hash*2; i+=2) {
        memset(hash_buf+j, (ctoh(hash[i]) << 4) | (ctoh(hash[i+1])), sizeof(uint32_t));
        j++;
      }
      root_hash->hash = hash_buf;
      
      //set commitment
      comm->epoch = atol(epoch);
      comm->root_hash = root_hash;
      comm->n_signature = atoi(len_sig);
      //uint32_t sig_buf[comm->n_signature];
      
      uint32_t *sig_buf = malloc(comm->n_signature*sizeof(uint32_t));
      //if (sig_buf == NULL) return gcry_error(GPG_ERR_ENOMEM);
      if (strlen(sig) != comm->n_signature*2) continue;
      for(j=0, i=0; i<root_hash->n_hash*2; i+=2) {
        memset(sig_buf+j, (ctoh(sig[i]) << 4) + (ctoh(sig[i+1])), sizeof(uint32_t));
        j++;
      }

      /* if (strlen(sig) != comm->n_signature*2) continue;
      for(j=0, i=0; i < comm->n_signature*2; i+=2) {
        sig_buf[j++] = (ctoh(sig[i]) << 4) + (ctoh(sig[i+1]));
        }*/
      comm->signature = sig_buf;
      
      //set coniks state
      if (cs->accountname == NULL) {
        cs->accountname = strdup(accountname);
      }
      cs->last_epoch = atol(epoch);      
      cs->last_comm = comm;
    }
    
    return gcry_error(GPG_ERR_NO_ERROR);
}

/* Write the server parameters for a coniks state from a given ConiksOtrState to a file on disk. */
gcry_error_t write_server_params(ConiksOtrState cs, const char *filename){

    gcry_error_t err;
    FILE *serverf;

    serverf = fopen(filename, "wb");
    if (!serverf) {
	err = gcry_error_from_errno(errno);
	return err;
    }

    err = write_server_params_FILEp(cs, serverf);

    fclose(serverf);
    return err;
}

/* Write the server parameters for a coniks state from a given ConiksOtrState to a FILE*.
 * The FILE* must be open for writing. */
gcry_error_t write_server_params_FILEp(ConiksOtrState cs,	FILE *serverf)
{

    if (!serverf) return gcry_error(GPG_ERR_NO_ERROR);

    uint64_t init_epoch = cs->serv_init_epoch;
    uint32_t epoch_interval = cs->serv_epoch_interval;

    fprintf(serverf, "%s\t%lu\t%d\t\n", cs->accountname, init_epoch, epoch_interval);

    return gcry_error(GPG_ERR_NO_ERROR);
}

/* Write the coniks state from a given ConiksOtrState to a file on disk. */
gcry_error_t write_coniks_state(ConiksOtrState cs, const char *filename){

    gcry_error_t err;
    FILE *coniksf;

    coniksf = fopen(filename, "wb");
    if (!coniksf) {
	err = gcry_error_from_errno(errno);
	return err;
    }

    err = write_coniks_state_FILEp(cs, coniksf);

    fclose(coniksf);
    return err;
}

/* Write the coniks state from a given ConiksOtrState to a FILE*.
 * The FILE* must be open for writing. */
gcry_error_t write_coniks_state_FILEp(ConiksOtrState cs,
	FILE *coniksf)
{

    if (!coniksf) return gcry_error(GPG_ERR_NO_ERROR);

    uint64_t last_epoch = cs->last_epoch;
    Protos__Commitment *last_comm = cs->last_comm;

    Protos__Hash *root_hash = last_comm->root_hash; 
    int n_hash = root_hash->n_hash;
    int n_sig;

    // first write the root hash
    int i;
    fprintf(coniksf, "%s\t%lu\t%d\t%d\t", cs->accountname, last_epoch, root_hash->len, n_hash);
    //fprintf(coniksf, "%d\t%d\t%d\t", last_epoch, root_hash->len, n_hash);
    for(i=0;i<n_hash;++i) {
      fprintf(coniksf, "%02x", root_hash->hash[i]);
    }

    // then write the signature
    n_sig = last_comm->n_signature;
    fprintf(coniksf, "\t%d\t", n_sig);
    for(i=0;i<n_sig;i++) {
      fprintf(coniksf, "%02x", last_comm->signature[i]);
    }

    fprintf(coniksf, "\n");

    return gcry_error(GPG_ERR_NO_ERROR);
}

// get the server's name from a user's account name
void get_server_name(char *accountname, char **server) {

  // find the name of the server in the name
  // we know the format is name@server
  char *server_dom = strchr((const char *)accountname, '@');

  *server = server_dom+1;

}

// register a name-to-key binding
uint8_t register_key(char *name, char *key,  uint8_t **serv_msg, size_t *msg_len){
  Protos__Registration msg = PROTOS__REGISTRATION__INIT;
  void *buf;
  unsigned len;

  msg.name = name;
 
  if(key != NULL){
    msg.publickey = key;
  }

  // this gives us the length of the serialized buffer
  len = protos__registration__get_packed_size(&msg);
  
  // now serialize
  buf = malloc(len);
  protos__registration__pack(&msg,buf);
 
  // get the server's name
  char *server;
  get_server_name(name, &server);

  int bytes_sent = send_msg(registration_m,buf, len,server);

  // handle the response
  if(bytes_sent > 0){
    uint8_t resp_type = get_serv_resp_type();

    if(resp_type == server_resp_m || resp_type == registration_resp_m){ 

      uint8_t msg_data[MAXDATASIZE];
      size_t resp_len = recv_msg(msg_data);

      if(resp_len == 0){
        end_conn();        
        return -1;
      }

      *serv_msg = malloc(resp_len);
    
      if(*serv_msg != NULL){
        memcpy(*serv_msg, msg_data, resp_len);
        *msg_len = resp_len;
        return resp_type;
      }
    }
  }
  end_conn();
  return -4;
  
}

// look up the public key for the given username and epoch
uint8_t get_public_key(char *name, uint64_t ep, uint8_t **serv_msg, size_t *msg_len){
  Protos__KeyLookup msg = PROTOS__KEY_LOOKUP__INIT;
  void *buf;
  unsigned len;

  msg.name = name;

  // epochs (time in millis) need to be non-zero
  if(ep > 0){
    msg.has_epoch = 1;
    msg.epoch = ep;
  }

  // this gives us the length of the serialized buffer
  len = protos__key_lookup__get_packed_size(&msg);
  
  // now serialize
  buf = malloc(len);
  protos__key_lookup__pack(&msg,buf);
  
  // get the server's name
  char *server;
  get_server_name(name, &server);
  
  int bytes_sent = send_msg(key_lookup_m,buf, len, server);
  
  if(bytes_sent > 0){
    uint8_t resp_type = get_serv_resp_type();

    if(resp_type == server_resp_m || resp_type == auth_path_m){ 

      uint8_t msg_data[MAXDATASIZE];
      size_t resp_len = recv_msg(msg_data);

      if(resp_len == 0){
        end_conn();        
        return -1;
      }

      *serv_msg = malloc(resp_len);
    
      if(*serv_msg != NULL){
        memcpy(*serv_msg, msg_data, resp_len);
        *msg_len = resp_len;
        return resp_type;
      }
    }
  }
  end_conn();
  return -1;
}

// TODO: support witnessed commitment requests
/* Sends a commitment request to the given provider.
 * Provider must be the host name of the intended provider*/
uint8_t get_commitment(int type, uint64_t ep, char *provider, uint8_t **serv_msg, size_t *msg_len){
  printf("coniks: getting commitment\n");

 Protos__CommitmentReq msg = PROTOS__COMMITMENT_REQ__INIT;
  void *buf;
  unsigned len;

  if(type < 0){
    return -1;
  }
  else if(type == PROTOS__COMMITMENT_REQ__COMMITMENT_TYPE__SELF){
    msg.has_type = 1;
    msg.type = PROTOS__COMMITMENT_REQ__COMMITMENT_TYPE__SELF;
  }
  else if(type == PROTOS__COMMITMENT_REQ__COMMITMENT_TYPE__WITNESS){
    if(provider == NULL){
      return -1;
    }

    msg.has_type = 1;
    msg.type = PROTOS__COMMITMENT_REQ__COMMITMENT_TYPE__WITNESS;
    msg.provider = provider;
  }
  else{
    return -1;
  }
  
 // epochs (time in millis) need to be non-zero
  if(ep > 0){
    msg.has_epoch = 1;
    msg.epoch = ep;
  }

  // this gives us the length of the serialized buffer
  len = protos__commitment_req__get_packed_size(&msg);
  
  // now serialize
  buf = malloc(len);
  protos__commitment_req__pack(&msg,buf);

  int bytes_sent = send_msg(commitment_req_m,buf, len, provider);
  
  printf("coniks: request sent\n");

  if(bytes_sent > 0){
    uint8_t resp_type = get_serv_resp_type();

    if(resp_type == server_resp_m || resp_type == commitment_resp_m){ 

      uint8_t msg_data[MAXDATASIZE];
      size_t resp_len = recv_msg(msg_data);

      if(resp_len == 0){
        end_conn();        
        return -1;
      }

      *serv_msg = malloc(resp_len);
    
      if(*serv_msg != NULL){
        memcpy(*serv_msg, msg_data, resp_len);
        *msg_len = resp_len;
        return resp_type;
      }
    }
  }
  end_conn();
  return -1;
  
}

/* Continuity Checks */

static void intlist_to_uchar(uint32_t *intlist, size_t intlist_len, unsigned char * bytelist){
  unsigned int i;
  unsigned char next_byte;

  for(i = 0; i < intlist_len; i++){
    next_byte = intlist[i] & 0xff;
    memcpy(&bytelist[i], &next_byte, sizeof(unsigned char));
  }

}

int compare_commitments(Protos__Commitment *comm1, Protos__Commitment *comm2){

  // get the root hash for the commitment of the same epoch: same epoch will have been verified by caller
  Protos__Hash *root1 = comm1->root_hash;
  Protos__Hash *root2 = comm2->root_hash;

  unsigned char root_hash1[HASH_SIZE_BYTES];  
  intlist_to_uchar(root1->hash, root1->n_hash, root_hash1);

  unsigned char root_hash2[HASH_SIZE_BYTES];  
  intlist_to_uchar(root2->hash, root2->n_hash, root_hash2);

  int is_equal = memcmp(root_hash1, root_hash2, HASH_SIZE_BYTES);

  if(is_equal != 0){
    return 0;
  }

  return 1;

}

// check for non-equivocation about the commitment: follows flow chart from paper
int coniks_non_equivocation_check(ConiksOtrState cs, 
                                  Protos__Commitment *comm, Protos__Commitment *prev_comm,
                                  Protos__AuthPath__RootNode *root_node, char *err_buf){
  // first check the signature on the commitment
  int res = 0;
  
  printf("coniks: getting hashes from the current root and the previous root\n");
  
  if (comm == NULL) {
     printf("coniks: commitment for epoch is null\n");
  }
  else if (root_node == NULL) {
     printf("coniks: root node is null\n");
  }

  Protos__Hash *cur_root_hash = comm->root_hash;
  Protos__Hash *cur_root_prev_hash = root_node->prev;

  // not sure this is the cleanest way of doing this, but let's see what happens
  unsigned char sig_buf[comm->n_signature];
  intlist_to_uchar(comm->signature, comm->n_signature, sig_buf);
  unsigned char cur_root_hash_buf[cur_root_hash->n_hash];
  intlist_to_uchar(cur_root_hash->hash, cur_root_hash->n_hash, cur_root_hash_buf);

  char err_msg[1300];
  
  printf("coniks: verifying the signature\n");

  res = verify_commitment_signature(get_server_pubkey(), sig_buf, sizeof(sig_buf),
                                    cur_root_hash_buf, sizeof(cur_root_hash_buf), err_msg);

  memcpy(err_buf, err_msg, sizeof(err_msg));

  if(res <= 0){
    return res;
  }
  
  printf("coniks: checking hash chain\n");
  
  // now get the previous root hash and check if the current root node includes it
  if(comm->epoch == cs->serv_init_epoch){
    // if we're at the very first epoch for this server, we can't check the hash chain and all's good.
    res = 1;
    
    //TODO: don't return yet since we still have to do witnessed comparison check
  }
  else{
    uint8_t *msg_data;
    size_t len;    
    Protos__Hash *prev_root_hash;

    if(prev_comm == NULL){
      printf("coniks: prev_comm was null\n");

      // get the server's name
      char *server;
      get_server_name(cs->accountname, &server);
      
      uint8_t prev_comm_resp;
      prev_comm_resp = get_commitment(
                                      PROTOS__COMMITMENT_REQ__COMMITMENT_TYPE__SELF, 
                                      comm->epoch-cs->serv_epoch_interval, server, &msg_data, 
                                      &len);
      
      if(prev_comm_resp == server_resp_m){
        // TODO: handle properly      
        return -1;
      }
      else if(prev_comm_resp == commitment_resp_m){
        prev_comm = protos__commitment__unpack(NULL, len, msg_data);   
        if (prev_comm == NULL){
          return -1;
        }
        
        if(!prev_comm->has_epoch){
          return -1;
        }
      }
    }

    printf("coniks: now doing the comparison\n");

    prev_root_hash = prev_comm->root_hash;
    // check that both are same length
    if(prev_root_hash->n_hash != cur_root_prev_hash->n_hash){
      return -1;
    }
    
    int is_equal = memcmp(prev_root_hash->hash, cur_root_prev_hash->hash, 
                          prev_root_hash->n_hash);
    
     printf("coniks: comparison done\n");

      // at this point we know that the server has attmepted to change our forkset
      int i = 0, j = 0;
      for(i=0;i<HASH_SIZE_BYTES;i++) {
        j = i*2;
        printf("%02X", prev_root_hash->hash[i]);
      }
      
      printf("\n");

      for(i=0;i<HASH_SIZE_BYTES;i++) {
        j = i*2;
        printf("%02X", cur_root_prev_hash->hash[i]);
      }

      printf("\n");
    
    if(is_equal != 0){
      printf("hashes not equal\n");

      // at this point we know that the server has attempted to change our forkset
    
      res = 0;
    }
    else{
      res = 1;
      // TODO: continue with witnessed comparison after this
    }      
    
  }
  
  return res;

}

static void long_to_uchar(uint64_t long_val, unsigned char * bytelist){
  unsigned int i;
  unsigned char next_byte;
  unsigned int len = 8;

    /*bytelist[0] = (unsigned char)(long_val >> 0) & 0xff;
  bytelist[1] = (unsigned char)(long_val >> 8) & 0xff;
  bytelist[2] = (unsigned char)(long_val >> 16) & 0xff;
  bytelist[3] = (unsigned char)(long_val >> 24) & 0xff;
  bytelist[4] = (unsigned char)(long_val >> 32) & 0xff;
  bytelist[5] = (unsigned char)(long_val >> 40) & 0xff;
  bytelist[6] = (unsigned char)(long_val >> 48) & 0xff;
  bytelist[7] = (unsigned char)(long_val >> 56) & 0xff;*/
  
  for(i = 0; i < len; i++){
    next_byte = (unsigned char)(long_val >> i*len) & 0xff;
    memcpy(&bytelist[i], &next_byte, 1);
  }

}

static int compute_auth_path(Protos__AuthPath *auth_path, unsigned char *comp_root){
  Protos__AuthPath__UserLeafNode *uln = auth_path->leaf;
  int n_interior = auth_path->n_interior;
  Protos__AuthPath__InteriorNode **interior = auth_path->interior;
  Protos__AuthPath__RootNode *root = auth_path->root;

  /*leaf node*/
  int name_len = strlen(uln->name);
  int pk_len = strlen(uln->publickey);
  
  if(!uln->has_epoch_added || !uln->has_allows_unsigned_keychange) {
    return -1;
  }
  
  unsigned char epoch_added_buf[8];
  long_to_uchar(uln->epoch_added, epoch_added_buf);
 
  //first make the leaf node hashable: concatenate the two strings and add the other info
  unsigned char uln_bytes[name_len+pk_len+8+1];
  unsigned char uln_hash[HASH_SIZE_BYTES];

  memcpy(uln_bytes, uln->name, name_len);
  memcpy(uln_bytes+name_len, uln->publickey, pk_len);
  memcpy(uln_bytes+name_len+pk_len, epoch_added_buf, 8);
  memcpy(uln_bytes+name_len+pk_len+8, &(uln->allows_unsigned_keychange), 1);
  
  sha256(uln_bytes, name_len+pk_len+8+1, uln_hash);

  if(uln_hash == NULL){
    return -2;
  }

  if(!uln->has_intlevels){
    return -1;
  }

  /*interior nodes*/
  int num_levels = uln->intlevels;
  if(num_levels != n_interior){
    return -1;
  }

  int i;
  unsigned char cur_hash[HASH_SIZE_BYTES];
  unsigned char in_bytes[HASH_SIZE_BYTES*2];

  memcpy(cur_hash, uln_hash, HASH_SIZE_BYTES);

  for(i = 0; i < n_interior; i++){
    Protos__AuthPath__InteriorNode *in = interior[i];
    if(!in->has_prunedchild){
      return -1;
    }
    Protos__Hash *pc_hash = in->subtree;
    
    if(pc_hash->n_hash != HASH_SIZE_BYTES){
      return -1;
    }

    unsigned char pc_hash_buf[pc_hash->n_hash];
    intlist_to_uchar(pc_hash->hash, pc_hash->n_hash, pc_hash_buf);

    // pruned child is left, so subtree is left subtree
    if(in->prunedchild == PROTOS__AUTH_PATH__PRUNED_CHILD__LEFT){
      memcpy(in_bytes, pc_hash_buf, HASH_SIZE_BYTES);
      memcpy(in_bytes+HASH_SIZE_BYTES, cur_hash, HASH_SIZE_BYTES);
    }
    // pruned child is right, so subtree is right subtree
    else if(in->prunedchild == PROTOS__AUTH_PATH__PRUNED_CHILD__RIGHT){
      memcpy(in_bytes, cur_hash, HASH_SIZE_BYTES);
      memcpy(in_bytes+HASH_SIZE_BYTES, pc_hash_buf, HASH_SIZE_BYTES);
    }

    // this should allow us to reuse cur_hash as the running hash
    sha256(in_bytes, HASH_SIZE_BYTES*2, cur_hash);
    if(cur_hash == NULL){
      return -2;
    }

  }

  /*root node*/
  // first check that root node is valid
  if(!root->has_prunedchild || !root->has_epoch){
    return -1;
  }

  Protos__Hash *pc_hash = root->subtree;
  Protos__Hash *prev_hash = root->prev;
  if(pc_hash->n_hash != HASH_SIZE_BYTES || prev_hash->n_hash != HASH_SIZE_BYTES){
    return -1;
  }

  // at this point, cur_hash should be the root's other subtree
  unsigned char rn_bytes[HASH_SIZE_BYTES*3+8];

  unsigned char pc_hash_buf[pc_hash->n_hash];
  intlist_to_uchar(pc_hash->hash, pc_hash->n_hash, pc_hash_buf);
  
  // pruned child is left, so subtree is left subtree
  if(root->prunedchild == PROTOS__AUTH_PATH__PRUNED_CHILD__LEFT){
    memcpy(rn_bytes, pc_hash_buf, HASH_SIZE_BYTES);
    memcpy(rn_bytes+HASH_SIZE_BYTES, cur_hash, HASH_SIZE_BYTES);
  }
  // pruned child is right, so subtree is right subtree
  else if(root->prunedchild == PROTOS__AUTH_PATH__PRUNED_CHILD__RIGHT){
    memcpy(rn_bytes, cur_hash, HASH_SIZE_BYTES);
    memcpy(rn_bytes+HASH_SIZE_BYTES, pc_hash_buf, HASH_SIZE_BYTES);
  }
  
  unsigned char prev_hash_buf[prev_hash->n_hash];
  intlist_to_uchar(prev_hash->hash, prev_hash->n_hash, prev_hash_buf);
  unsigned char epoch_buf[8];
  long_to_uchar(root->epoch, epoch_buf);

  //now just set the rest of the root bytes
  memcpy(rn_bytes+(HASH_SIZE_BYTES*2), prev_hash_buf, HASH_SIZE_BYTES);
  memcpy(rn_bytes+(HASH_SIZE_BYTES*3), epoch_buf, 8);
  
  sha256(rn_bytes, (HASH_SIZE_BYTES*3)+8, comp_root);
  if(comp_root == NULL){
    return -2;
  }

  return 1;
}

// TODO: add support for key change verification
/* Check for binding validity: compute the authentication path and compare the resulting root hash with the
   root hash in the commitment for the same epoch. Follows flow chart in paper. */
int coniks_validity_check(Protos__Commitment *comm, Protos__AuthPath *auth_path, char *err_buf){
  // we have retrieved the user's public key through the auth path: should we compare this key with
  // what we have cached? 
  //TODO: insert the cached public key into auth path and see if we get the same root hash

  // for now simply compute the root hash from the given auth path
  unsigned char comp_root_hash[HASH_SIZE_BYTES];

  Protos__AuthPath__RootNode *root_node = auth_path->root;

  int good_comp = compute_auth_path(auth_path, comp_root_hash);

  // let's just make sure that the computation didn't give any errors
  if(good_comp < 0){
    return good_comp;
  }

  // get the root hash for the commitment of the same epoch: this comm will have been verified by caller
  Protos__Hash *recv_root = comm->root_hash;
  unsigned char recv_root_hash[HASH_SIZE_BYTES];  
  intlist_to_uchar(recv_root->hash, recv_root->n_hash, recv_root_hash);
  
  int is_equal = memcmp(comp_root_hash, recv_root_hash, HASH_SIZE_BYTES);

  if(is_equal != 0){
    int i, j;
    for(i=0;i<HASH_SIZE_BYTES;i++) {
      j = i*2;
      sprintf(&err_buf[j], "%02X", comp_root_hash[i]);
    }

    sprintf(err_buf+(HASH_SIZE_BYTES*2), "\n%lu %lu", comm->epoch, root_node->epoch);
    // at this point we know that the server has attempted to present an invalid binding
    return 0;
  }
  return 1;
  
}

// get the current time in milliseconds: needed for retrieving the correct epoch
uint64_t get_current_time_millis() {
  struct timeval time;
  gettimeofday(&time, NULL);
  long millis = (time.tv_sec * 1000) + (time.tv_usec /1000);
  return (uint64_t)millis;
}
