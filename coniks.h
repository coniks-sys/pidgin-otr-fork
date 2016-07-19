/* coniks.h
 * Header file.
 * Public client-side API for exchanging messages with the Coniks chat server.
 * Uses the c2s.pb-c protobufs for message serialization.
 *
 * Author: Marcela Melara
 */

#ifndef __CONIKS_OTR_PLUGIN_H__
#define __CONIKS_OTR_PLUGIN_H__

/* system headers */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* libgcrypt headers */
#include <gcrypt.h>

typedef struct s_ConiksOtrState* ConiksOtrState;
typedef struct s_ConiksPendingContinuityCheck* ConiksPendingCheck;

#include "c2s.pb-c.h"
#include "util.pb-c.h"

#define HASH_SIZE_BYTES 32

struct s_ConiksOtrState{
  //s_ConiksOtrState *next;
  char *accountname;
  uint64_t last_epoch; // represented as a epoch date in millis
  Protos__Commitment *last_comm;
  uint8_t check_status;
  uint64_t serv_init_epoch;
  uint32_t serv_epoch_interval;
};

struct s_ConiksPendingContinuityCheck{
  char *name; // the name of the user whose identity is being verified
  uint8_t *comm; // the commitment currently being verified
  uint8_t *auth_path; // the authentication path for the validity check
  uint8_t *witComm; // the witnessed commitment which should match comm
  // TODO: make this a linked list to enable multiple simultaneous chats
};

enum msg_type{
  registration_m = 0x00,
  commitment_req_m = 0x01,
  key_lookup_m = 0x02,
  server_resp_m = 0x03,
  commitment_resp_m = 0x04,
  auth_path_m = 0x05,  
  registration_resp_m = 0x06,
};

// maybe we'll use this later, but not right now
enum check_type{
  hash_chain_c = 0x00,
  witnessed_comp_c = 0x01,
  validity_c = 0x02, // TODO: add support for key change and revocation
};

// might need more status stages if we end up breaking up the
// continuity checks
enum check_status {
  done_stat = 0x00,
  unchecked_stat = 0x01,
  in_prog_stat = 0x02,
};

// create a new ConiksOtrState
ConiksOtrState create_coniks_state(void);

/* Set the ConiksOtrState based on the given last epoch and commitment verified by the client.
 Return 0 upon success, 1 upon failure. */
void update_coniks_state(ConiksOtrState cs, char *accountname, 
                         Protos__Commitment *new_comm);

/* Set the server parameters in the ConiksOtrState based on the cached, or received, information from the
   server upon registration. This only happens once per session */
void set_server_params(ConiksOtrState cs, char *accountname, uint64_t init_epoch, uint32_t epoch_interval);

/* Free a ConiksOtrState. Used when tearing down the plugin */
void destroy_coniks_state(ConiksOtrState cs);

/* Read the coniks state from a file on disk into the given
 * ConiksOtrState. */
gcry_error_t read_coniks_state(ConiksOtrState cs, const char *filename);

/* Read the server params for the coniks state from a file on disk into the given
 * ConiksOtrState. */
gcry_error_t read_coniks_server_params(ConiksOtrState cs, const char *filename);

/* Read the server parameters for the coniks state from a FILE* into the given
 * ConiksOtrState.  The FILE* must be open for reading. */
gcry_error_t read_server_params_FILEp(ConiksOtrState cs, FILE *serverf);

/* Read the coniks state from a FILE* into the given
 * ConiksOtrState.  The FILE* must be open for reading. */
gcry_error_t read_coniks_state_FILEp(ConiksOtrState cs, FILE *coniksf);

/* Write the server parameters for a coniks state from a given ConiksOtrState to a file on disk. */
gcry_error_t write_server_params(ConiksOtrState cs, const char *filename);

/* Write the server parameters for a coniks state from a given ConiksOtrState to a FILE*.
 * The FILE* must be open for writing. */
gcry_error_t write_server_params_FILEp(ConiksOtrState cs,	FILE *serverf);

/* Write the fingerprint store from a given OtrlUserState to a file on disk. */
gcry_error_t write_coniks_state(ConiksOtrState cs, const char *filename);

/* Write the coniks state from a given ConiksOtrState to a FILE*.
 * The FILE* must be open for writing. */
gcry_error_t write_coniks_state_FILEp(ConiksOtrState cs, FILE *coniksf);

// register a name-to-key binding
uint8_t register_key(char *name, char *key, uint8_t **serv_msg, size_t *msg_len);

// compares to commitments and checks for equality
int compare_commitments(Protos__Commitment *comm1, Protos__Commitment *comm2);

// Sends a commitment request to the given provider
uint8_t get_commitment(int type, uint64_t ep, char *provider, uint8_t **serv_msg, size_t *msg_len);

// look up the public key for the given username and epoch
uint8_t get_public_key(char *name, uint64_t ep, uint8_t **serv_msg, size_t *msg_len);

// check for non-equivocation about the commitment: follows flow chart from paper
int coniks_non_equivocation_check(ConiksOtrState cs, 
                                  Protos__Commitment *comm, Protos__Commitment *prev_comm,
                                  Protos__AuthPath__RootNode *root_node, char *err_buf);

// check for binding validity: compute the authentication path
int coniks_validity_check(Protos__Commitment *comm, Protos__AuthPath *auth_path, char *err_buf);

// get the current time in milliseconds: needed for retrieving the correct epoch
uint64_t get_current_time_millis();

// get the server's name from a user's account name
void get_server_name(char *accountname, char **server);

#endif
