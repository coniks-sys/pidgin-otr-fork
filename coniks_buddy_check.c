/* purple headers */
#include "pidgin.h"
#include "notify.h"
#include "version.h"
#include "util.h"
#include "debug.h"
#include "core.h"

/* libotr headers */
#include <libotr/privkey.h>
#include <libotr/proto.h>
#include <libotr/tlv.h>
#include <libotr/message.h>
#include <libotr/userstate.h>
#include <libotr/instag.h>
#include <libotr/serial.h>

/* purple-otr headers */
#include "ui.h"
#include "dialogs.h"
#include "otr-plugin.h"

/* coniks otr headers */
#include "keypair.h"
#include "coniks.h"
#include "util.pb-c.h"
#include "c2s.pb-c.h"
#include "coniks_buddy_check.h"

#ifdef USING_GTK
/* purple GTK headers */
#include "gtkplugin.h"
#endif

#ifdef USING_GTK
/* purple-otr GTK headers */
#include <glib.h>
#include "gtk-ui.h"
#include "gtk-dialog.h"
#endif

extern OtrlUserState otrg_plugin_userstate;
extern ConiksOtrState coniks_state;

/* Actually perform the continuity checks */
static gboolean do_continuity_checks_buddy(Protos__Commitment *comm, Protos__AuthPath *auth_path){
  // first check the hash chain, for this retrieve the previous commitment and get its root hash
  Protos__AuthPath__RootNode *cur_root;
  cur_root = auth_path->root;

  char err_msg[1500];

  int eq_res;
  printf("coniks_buddy_checks: first equivocation check for epoch %lu\n", cur_root->epoch);
  eq_res = coniks_non_equivocation_check(coniks_state, comm, NULL, cur_root, err_msg);
 
  if(eq_res < 0){    
    purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Buddy Continuity Checks", err_msg, NULL, NULL, NULL);
    return 0;
  }
  else if(eq_res == 0){
    purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Buddy Continuity Checks", "Your identity provider seems to have equivocated. You should whistleblow.", NULL, NULL, NULL);
    return 0; 
    }
  
  // at this point we assume that res==1 so we perform the validity check
  int val_res;
  val_res = coniks_validity_check(comm, auth_path, err_msg);

   if(val_res < 0){
    purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Buddy Continuity Checks", "Something went wrong", NULL, NULL, NULL);
  }
  else if(val_res == 0){
    purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Buddy Continuity Checks", err_msg, NULL, NULL, NULL);
    return val_res;
  }
  else{
    purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Buddy Continuity Checks", "Your buddy's identity is continuous.", NULL, NULL, NULL);
    return 1;
  }
   return 0;
}

/* Retrieves all necessary information to perform the coniks continuity checks on the requested user 
* for the current epoch */
void otrg_plugin_coniks_continuity_checks_buddy(ConnContext *context){
  // key lookup
  uint8_t resp;
  uint8_t *msg_data;
  size_t len;
  Protos__ServerResp *serv_resp;
  Protos__AuthPath *auth_path = NULL;
  Protos__Commitment *comm = NULL;
  
  uint64_t current_time = get_current_time_millis();

  char err_buf[150];
  resp = get_public_key(context->username, current_time, &msg_data, &len); // TODO: find a better way to get most recent version
  OtrgDialogWaitHandle waithandle;    

  if(resp == server_resp_m){
    serv_resp = protos__server_resp__unpack(NULL, len, msg_data);   
    if (serv_resp == NULL){
      sprintf(err_buf, "resp: error unpacking incoming message.");
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Public Key Lookup", err_buf, NULL, NULL, NULL);
    }
    
    if(serv_resp->has_message && 
       serv_resp->message == PROTOS__SERVER_RESP__MESSAGE__NAME_NOT_FOUND_ERR){
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Public Key Lookup", "Your contact doesn't support Coniks!", NULL, NULL, NULL);     
      otrg_gtk_dialog_socialist_millionaires(context, NULL, FALSE);
      goto out;
    }
    else{
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Public Key Lookup", "Something went wrong", NULL, NULL, NULL);
    }
  }
  else if(resp == auth_path_m){
    // Store the authentication path in the pending check struct
    auth_path = protos__auth_path__unpack(NULL, len, msg_data);   
    if (auth_path == NULL){
      sprintf(err_buf, "resp: error unpacking incoming message.");
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Public Key Lookup", err_buf, NULL, NULL, NULL);
    }

  }
  else{
    sprintf(err_buf, "Bad server response");
    purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Public key lookup", err_buf, NULL, NULL, NULL);
  }

  // get the server's name
  char *server;
  get_server_name(context->username, &server);

  // commitment lookup  
  resp = get_commitment(PROTOS__COMMITMENT_REQ__COMMITMENT_TYPE__SELF, current_time, 
                        server, &msg_data, &len);
  
  if(resp == server_resp_m){    
    serv_resp = protos__server_resp__unpack(NULL, len, msg_data);   
    if (serv_resp == NULL){
      sprintf(err_buf, "resp: error unpacking incoming message.");
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Commitment retrieval", err_buf, NULL, NULL, NULL);
    }
    
    if(serv_resp->has_message){
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Commitment retrieval", "Server error", NULL, NULL, NULL);
    }
  }
  else if(resp == commitment_resp_m){
    comm = protos__commitment__unpack(NULL, len, msg_data);   
    if (comm == NULL){
      sprintf(err_buf, "resp: error unpacking incoming message.");
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Commitment retrieval", err_buf, NULL, NULL, NULL);
    }


    if(!comm->has_epoch){
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Commitment retrieval", "No epoch", NULL, NULL, NULL);
    }
  }
  else{
    sprintf(err_buf, "Bad server response");
    purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Commitment retrieval", err_buf, NULL, NULL, NULL);
  }  

  waithandle = otrg_gtk_dialog_continuity_check_wait_start(context->username);

  // now call the actual do_check function
  gboolean check_passed = do_continuity_checks_buddy(comm, auth_path);
  
  otrg_gtk_dialog_continuity_check_wait_done(waithandle, check_passed);

  if (check_passed) {
    otrl_context_set_trust(context->active_fingerprint, "smp");
    dialog_update_label(context);
  }
 out:;
  return;

}
