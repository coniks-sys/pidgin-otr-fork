/*
 *  Off-the-Record Messaging plugin for pidgin
 *  Copyright (C) 2004-2014  Ian Goldberg, Rob Smits,
 *                           Chris Alexander, Willy Lew,
 *                           Lisa Du, Nikita Borisov
 *                           <otr@cypherpunks.ca>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* config.h */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* system headers */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* libgcrypt headers */
#include <gcrypt.h>

/* purple headers */
#include "pidgin.h"
#include "notify.h"
#include "version.h"
#include "util.h"
#include "debug.h"
#include "core.h"

#ifdef USING_GTK
/* purple GTK headers */
#include "gtkplugin.h"
#endif

#ifdef ENABLE_NLS

#ifdef WIN32
/* On Win32, include win32dep.h from pidgin for correct definition
 * of LOCALEDIR */
#include "win32dep.h"
#endif /* WIN32 */

/* internationalisation header */
#include <glib/gi18n-lib.h>

#else /* ENABLE_NLS */

#define _(x) (x)
#define N_(x) (x)

#endif /* ENABLE_NLS */

/* libotr headers */
#include <libotr/privkey.h>
#include <libotr/proto.h>
#include <libotr/tlv.h>
#include <libotr/message.h>
#include <libotr/userstate.h>
#include <libotr/instag.h>

/* purple-otr headers */
#include "ui.h"
#include "dialogs.h"
#include "otr-plugin.h"

/* coniks otr headers */
#include "keypair.h"
#include "coniks.h"
#include "util.pb-c.h"
#include "c2s.pb-c.h"

#ifdef USING_GTK
/* purple-otr GTK headers */
#include <glib.h>
#include "gtk-ui.h"
#include "gtk-dialog.h"

/* Controls a beta warning/expiry dialog */
#define BETA_DIALOG 0

#if BETA_DIALOG && defined USING_GTK /* Only for beta */
#include "gtkblist.h"
#endif

#endif

/* If we're using glib on Windows, we need to use g_fopen to open files.
 * On other platforms, it's also safe to use it.  If we're not using
 * glib, just use fopen. */
#ifdef USING_GTK
/* If we're cross-compiling, this might be wrong, so fix it. */
#ifdef WIN32
#undef G_OS_UNIX
#define G_OS_WIN32
#endif
#include <glib/gstdio.h>
#else
#define g_fopen fopen
#endif

PurplePlugin *otrg_plugin_handle;

/* We'll only use the one OtrlUserState. */
OtrlUserState otrg_plugin_userstate = NULL;

/* We'll only use on ConiksOtrState. */
ConiksOtrState coniks_state = NULL;

/* GLib HashTable for storing the maximum message size for various
 * protocols. */
GHashTable* mms_table = NULL;

static void otrg_plugin_coniks_continuity_checks_self(char *accountname);

/* Send an IM from the given account to the given recipient.  Display an
 * error dialog if that account isn't currently logged in. */
void otrg_plugin_inject_message(PurpleAccount *account, const char *recipient,
	const char *message)
{
    PurpleConnection *connection;

    connection = purple_account_get_connection(account);
    if (!connection) {
	const char *protocol = purple_account_get_protocol_id(account);
	const char *accountname = purple_account_get_username(account);
	PurplePlugin *p = purple_find_prpl(protocol);
	char *msg = g_strdup_printf(_("You are not currently connected to "
		"account %s (%s)."), accountname,
		(p && p->info->name) ? p->info->name : _("Unknown"));
	otrg_dialog_notify_error(accountname, protocol, recipient,
		_("Not connected"), msg, NULL);
	g_free(msg);
	return;
    }

    // all this for self check
    const char *accountname, *proto;
    accountname = purple_account_get_username(account);
    proto = purple_account_get_protocol_id(account);

    // Needed so we can send the username via the proto (does not have const char * name)
    size_t uname_len = strlen(accountname);
    char *uname = malloc(uname_len);
    strcpy(uname, accountname);

    // only check logged in user if she has a public key and she hasn't checked
    // its continuity yet in this session or epoch
    if (otrl_privkey_find(otrg_plugin_userstate, accountname, proto) != NULL && 
        coniks_state->check_status == unchecked_stat 
        /* || (coniks_state->check_status == done_stat && 
           get_current_time_millis() >= coniks_state->last_epoch + coniks_state->serv_epoch_interval))*/) {
      coniks_state->check_status = in_prog_stat;
      otrg_plugin_coniks_continuity_checks_self(uname);
    } 

    free(uname);

    serv_send_im(connection, recipient, message, 0);
}

/* Display a notification message for a particular accountname /
 * protocol / username conversation. */
static void notify(void *opdata, OtrlNotifyLevel level,
	const char *accountname, const char *protocol, const char *username,
	const char *title, const char *primary, const char *secondary)
{
    PurpleNotifyMsgType purplelevel = PURPLE_NOTIFY_MSG_ERROR;

    switch (level) {
	case OTRL_NOTIFY_ERROR:
	    purplelevel = PURPLE_NOTIFY_MSG_ERROR;
	    break;
	case OTRL_NOTIFY_WARNING:
	    purplelevel = PURPLE_NOTIFY_MSG_WARNING;
	    break;
	case OTRL_NOTIFY_INFO:
	    purplelevel = PURPLE_NOTIFY_MSG_INFO;
	    break;
    }

    otrg_dialog_notify_message(purplelevel, accountname, protocol,
	    username, title, primary, secondary);
}

/* Display an OTR control message for a particular accountname /
 * protocol / username conversation.  If force_create is non-zero and
 * if the corresponding conversation window is not present, a new
 * conversation window will be created and the message will be displayed
 * there. If the message cannot be displayed, try notify() instead and
 * return 1. Otherwise return 0 if message is successfully displayed. */
static int display_otr_message_or_notify(void *opdata, const char *accountname,
	const char *protocol, const char *username, const char *msg,
	int force_create, OtrlNotifyLevel level, const char *title,
	const char *primary, const char *secondary)
{
    if (otrg_dialog_display_otr_message(accountname, protocol,
	    username, msg, force_create)) {
	notify(opdata, level, accountname, protocol, username, title, primary,
		secondary);
	return 1;
    } else return 0;
}

static void log_message(void *opdata, const char *message)
{
    purple_debug_info("otr", "%s", message);
}

static OtrlPolicy policy_cb(void *opdata, ConnContext *context)
{
    PurpleAccount *account;
    OtrlPolicy policy = OTRL_POLICY_DEFAULT;
    OtrgUiPrefs prefs;

    if (!context) return policy;

    account = purple_accounts_find(context->accountname, context->protocol);
    if (!account) return policy;

    otrg_ui_get_prefs(&prefs, account, context->username);
    return prefs.policy;
}

/* Generate a private key for the given accountname/protocol */
void otrg_plugin_create_privkey(const char *accountname,
	const char *protocol)
{
    OtrgDialogWaitHandle waithandle;
#ifndef WIN32
    mode_t mask;
#endif  /* WIN32 */
    FILE *privf;

    gchar *privkeyfile = g_build_filename(purple_user_dir(),
	    PRIVKEYFNAME, NULL);
    if (!privkeyfile) {
	fprintf(stderr, _("Out of memory building filenames!\n"));
	return;
    }
#ifndef WIN32
    mask = umask (0077);
#endif  /* WIN32 */
    privf = g_fopen(privkeyfile, "w+b");
#ifndef WIN32
    umask (mask);
#endif  /* WIN32 */
    g_free(privkeyfile);
    if (!privf) {
	fprintf(stderr, _("Could not write private key file\n"));
	return;
    }

    waithandle = otrg_dialog_private_key_wait_start(accountname, protocol);

    char *pubkey, *uname;

    // Needed so we can send the username via the proto (does not have const char * name)
    size_t uname_len = strlen(accountname);
    uname = malloc(uname_len);
    strcpy(uname, accountname);

    /* Generate the keypair */
    coniks_otr_keypair_generate_FILEp_str(otrg_plugin_userstate, privf,
                                      accountname, protocol, &pubkey);
    fclose(privf);
    otrg_ui_update_fingerprint();
      
    /* register the public key and name with the server */
    // cache the returned initial epoch and epoch interval for future continuity checks
    uint8_t resp;
    uint8_t *msg_data;
    size_t len;
    Protos__ServerResp *serv_resp;
    Protos__RegistrationResp *reg_resp = NULL;
    resp = register_key(uname, pubkey, &msg_data, &len);

    char err_buf[150];
    if(resp == server_resp_m){
      serv_resp = protos__server_resp__unpack(NULL, len, msg_data);   
      if (serv_resp == NULL){
        sprintf(err_buf, "resp: error unpacking incoming message.");
        purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Key Registration", err_buf, NULL, NULL, NULL);
        return;
      }
      
      /* Mark the dialog as done but an error occurred. */
      otrg_dialog_private_key_wait_done(waithandle);

      if(serv_resp->has_message && 
         serv_resp->message == PROTOS__SERVER_RESP__MESSAGE__NAME_EXISTS_ERR){
        purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Key Registration", "The server already has a registered key under your name", NULL, NULL, NULL);  
        return;
      }
      else{
        purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Key Registration", "Something went wrong", NULL, NULL, NULL);
        return;
      }
    }
    else if(resp == registration_resp_m){
      reg_resp = protos__registration_resp__unpack(NULL, len, msg_data);   
      if (reg_resp == NULL){
        sprintf(err_buf, "resp: error unpacking incoming message.");
        purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Key Registration", err_buf, NULL, NULL, NULL);
        return;
      }
      
      if(reg_resp->has_init_epoch && reg_resp->has_epoch_interval) {
        // now we can update the server params in the coniks state and save the new state
        set_server_params(coniks_state, uname, reg_resp->init_epoch, reg_resp->epoch_interval);
        gchar *coniksservfile = g_build_filename(purple_user_dir(), CONIKSSERVFNAME, NULL);
        gcry_error_t err = write_server_params(coniks_state, coniksservfile); 
        
        if (err) {
          purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Key Registration", gcry_strerror(err), NULL, NULL, NULL);
          return;
        }
      }
      /* Mark the dialog as done. */
      otrg_dialog_private_key_wait_done(waithandle);
  }
  else{
    sprintf(err_buf, "Bad server response");
    purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Public key lookup", err_buf, NULL, NULL, NULL);
    return;
  }

    free(uname);
    free(pubkey);

}

static void create_privkey_cb(void *opdata, const char *accountname,
	const char *protocol)
{
    otrg_plugin_create_privkey(accountname, protocol);
}

/* Generate a instance tag for the given accountname/protocol */
void otrg_plugin_create_instag(const char *accountname,
	const char *protocol)
{
    FILE *instagf;

    gchar *instagfile = g_build_filename(purple_user_dir(), INSTAGFNAME, NULL);
    if (!instagfile) {
	fprintf(stderr, _("Out of memory building filenames!\n"));
	return;
    }
    instagf = g_fopen(instagfile, "w+b");
    g_free(instagfile);
    if (!instagf) {
	fprintf(stderr, _("Could not write private key file\n"));
	return;
    }

    /* Generate the instag */
    otrl_instag_generate_FILEp(otrg_plugin_userstate, instagf,
	    accountname, protocol);
    fclose(instagf);

}

static void create_instag_cb(void *opdata, const char *accountname,
	const char *protocol)
{
    otrg_plugin_create_instag(accountname, protocol);
}

static int is_logged_in_cb(void *opdata, const char *accountname,
	const char *protocol, const char *recipient)
{
    PurpleAccount *account;
    PurpleBuddy *buddy;

    account = purple_accounts_find(accountname, protocol);
    if (!account) return -1;

    buddy = purple_find_buddy(account, recipient);
    if (!buddy) return -1;

    return (PURPLE_BUDDY_IS_ONLINE(buddy));
}

static void inject_message_cb(void *opdata, const char *accountname,
	const char *protocol, const char *recipient, const char *message)
{
    PurpleAccount *account = purple_accounts_find(accountname, protocol);
    if (!account) {
	PurplePlugin *p = purple_find_prpl(protocol);
	char *msg = g_strdup_printf(_("Unknown account %s (%s)."),
		accountname,
		(p && p->info->name) ? p->info->name : _("Unknown"));
	otrg_dialog_notify_error(accountname, protocol, recipient,
		_("Unknown account"), msg, NULL);
	g_free(msg);
	return;
    }
    otrg_plugin_inject_message(account, recipient, message);
}

static void update_context_list_cb(void *opdata)
{
    otrg_ui_update_keylist();
}

static void confirm_fingerprint_cb(void *opdata, OtrlUserState us,
	const char *accountname, const char *protocol, const char *username,
	unsigned char fingerprint[20])
{
    otrg_dialog_unknown_fingerprint(us, accountname, protocol, username,
	    fingerprint);
}

static void write_fingerprints_cb(void *opdata)
{
    otrg_plugin_write_fingerprints();
    otrg_ui_update_keylist();
    otrg_dialog_resensitize_all();
}

static void gone_secure_cb(void *opdata, ConnContext *context)
{
    otrg_dialog_connected(context);
}

static void gone_insecure_cb(void *opdata, ConnContext *context)
{
    otrg_dialog_disconnected(context);
}

static void still_secure_cb(void *opdata, ConnContext *context, int is_reply)
{
    if (is_reply == 0) {
	otrg_dialog_stillconnected(context);
    }
}

static int max_message_size_cb(void *opdata, ConnContext *context)
{
    void* lookup_result = g_hash_table_lookup(mms_table, context->protocol);
    if (!lookup_result)
	return 0;
    else
	return *((int*)lookup_result);
}

static const char* otr_error_message_cb(void *opdata, ConnContext *context,
	OtrlErrorCode err_code)
{
    char *err_msg = NULL;
    switch (err_code)
    {
    case OTRL_ERRCODE_NONE :
	break;
    case OTRL_ERRCODE_ENCRYPTION_ERROR :
	err_msg = g_strdup(_("Error occurred encrypting message."));
	break;
    case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE :
	if (context) {
	    err_msg = g_strdup_printf(_("You sent encrypted data to %s, who"
		    " wasn't expecting it."), context->accountname);
	}
	break;
    case OTRL_ERRCODE_MSG_UNREADABLE :
	err_msg =
		g_strdup(_("You transmitted an unreadable encrypted message."));
	break;
    case OTRL_ERRCODE_MSG_MALFORMED :
	err_msg = g_strdup(_("You transmitted a malformed data message."));
	break;
    }
    return err_msg;
}

static void otr_error_message_free_cb(void *opdata, const char *err_msg)
{
    if (err_msg) g_free((char*)err_msg);
}

static const char *resent_msg_prefix_cb(void *opdata, ConnContext *context)
{
	return g_strdup(_("[resent]"));
}

static void resent_msg_prefix_free_cb(void *opdata, const char *prefix)
{
	if (prefix) g_free((char*)prefix);
}

static void handle_smp_event_cb(void *opdata, OtrlSMPEvent smp_event,
	ConnContext *context, unsigned short progress_percent,
	char *question)
{
    if (!context) return;
    switch (smp_event)
    {
	case OTRL_SMPEVENT_NONE :
	    break;
	case OTRL_SMPEVENT_ASK_FOR_SECRET :
	    otrg_dialog_socialist_millionaires(context);
	    break;
	case OTRL_SMPEVENT_ASK_FOR_ANSWER :
	    otrg_dialog_socialist_millionaires_q(context, question);
	    break;
	case OTRL_SMPEVENT_CHEATED :
	    otrg_plugin_abort_smp(context);
	    /* FALLTHROUGH */
	case OTRL_SMPEVENT_IN_PROGRESS :
	case OTRL_SMPEVENT_SUCCESS :
	case OTRL_SMPEVENT_FAILURE :
	case OTRL_SMPEVENT_ABORT :
	    otrg_dialog_update_smp(context,
		    smp_event, ((gdouble)progress_percent)/100.0);
	    break;
	case OTRL_SMPEVENT_ERROR :
	    otrg_plugin_abort_smp(context);
	    break;
    }
}

/* Treat this event like other incoming messages. This allows message
 * notification events to get properly triggered. */
static void emit_msg_received(ConnContext *context, const char* message) {
    PurpleConversation *conv = otrg_plugin_userinfo_to_conv(
	    context->accountname, context->protocol, context->username, 1);
    PurpleMessageFlags flags = PURPLE_MESSAGE_RECV | PURPLE_MESSAGE_SYSTEM
	    | PURPLE_MESSAGE_NOTIFY;
    PurpleAccount * account = purple_conversation_get_account(conv);

    purple_signal_emit(purple_conversations_get_handle(), "received-im-msg",
	    account, context->username, message, conv, flags);
}

static void handle_msg_event_cb(void *opdata, OtrlMessageEvent msg_event,
	ConnContext *context, const char* message, gcry_error_t err)
{
    PurpleConversation *conv = NULL;
    gchar *buf;
    OtrlMessageEvent * last_msg_event;

    if (!context) return;

    conv = otrg_plugin_context_to_conv(context, 1);
    last_msg_event = g_hash_table_lookup(conv->data, "otr-last_msg_event");

    switch (msg_event)
    {
	case OTRL_MSGEVENT_NONE:
	    break;
	case OTRL_MSGEVENT_ENCRYPTION_REQUIRED:
	    buf = g_strdup_printf(_("You attempted to send an "
		    "unencrypted message to %s"), context->username);
	    display_otr_message_or_notify(opdata, context->accountname,
		    context->protocol, context->username, _("Attempting to"
		    " start a private conversation..."), 1, OTRL_NOTIFY_WARNING,
		    _("OTR Policy Violation"), buf,
		    _("Unencrypted messages to this recipient are "
		    "not allowed.  Attempting to start a private "
		    "conversation.\n\nYour message will be "
		    "retransmitted when the private conversation "
		    "starts."));
	    g_free(buf);
	    break;
	case OTRL_MSGEVENT_ENCRYPTION_ERROR:
	    display_otr_message_or_notify(opdata, context->accountname,
		    context->protocol, context->username, _("An error occurred "
		    "when encrypting your message.  The message was not sent."),
		    1, OTRL_NOTIFY_ERROR, _("Error encrypting message"),
		    _("An error occurred when encrypting your message"),
		    _("The message was not sent."));
	    break;
	case OTRL_MSGEVENT_CONNECTION_ENDED:
	    buf = g_strdup_printf(_("%s has already closed his/her private "
			"connection to you"), context->username);
	    display_otr_message_or_notify(opdata, context->accountname,
		    context->protocol, context->username, _("Your message "
		    "was not sent.  Either end your private conversation, "
		    "or restart it."), 1, OTRL_NOTIFY_ERROR,
		    _("Private connection closed"), buf,
		    _("Your message was not sent.  Either close your "
		    "private connection to him, or refresh it."));
	    g_free(buf);
	    break;
	case OTRL_MSGEVENT_SETUP_ERROR:
	    if (!err) {
		err = GPG_ERR_INV_VALUE;
	    }
	    switch(gcry_err_code(err)) {
		case GPG_ERR_INV_VALUE:
		    buf = g_strdup(_("Error setting up private "
			    "conversation: Malformed message received"));
		    break;
		default:
		    buf = g_strdup_printf(_("Error setting up private "
			    "conversation: %s"), gcry_strerror(err));
		    break;
	    }

	    display_otr_message_or_notify(opdata, context->accountname,
		    context->protocol, context->username, buf, 1,
		    OTRL_NOTIFY_ERROR, _("OTR Error"), buf, NULL);
	    g_free(buf);
	    break;
	case OTRL_MSGEVENT_MSG_REFLECTED:
	    display_otr_message_or_notify(opdata,
		    context->accountname, context->protocol,
		    context->username,
		    _("We are receiving our own OTR messages.  "
		    "You are either trying to talk to yourself, "
		    "or someone is reflecting your messages back "
		    "at you."), 1, OTRL_NOTIFY_ERROR,
		    _("OTR Error"), _("We are receiving our own OTR messages."),
		    _("You are either trying to talk to yourself, "
		    "or someone is reflecting your messages back "
		    "at you."));
	    break;
	case OTRL_MSGEVENT_MSG_RESENT:
	    buf = g_strdup_printf(_("<b>The last message to %s was resent."
		    "</b>"), context->username);
	    display_otr_message_or_notify(opdata, context->accountname,
		    context->protocol, context->username, buf, 1,
		    OTRL_NOTIFY_INFO, _("Message resent"), buf, NULL);
	    g_free(buf);
	    break;
	case OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE:
	    buf = g_strdup_printf(_("<b>The encrypted message received from "
		    "%s is unreadable, as you are not currently communicating "
		    "privately.</b>"), context->username);
	    display_otr_message_or_notify(opdata, context->accountname,
		    context->protocol, context->username, buf, 1,
		    OTRL_NOTIFY_INFO, _("Unreadable message"), buf, NULL);
	    g_free(buf);
	    break;
	case OTRL_MSGEVENT_RCVDMSG_UNREADABLE:
	    buf = g_strdup_printf(_("We received an unreadable "
		    "encrypted message from %s."), context->username);
	    display_otr_message_or_notify(opdata, context->accountname,
		    context->protocol, context->username, buf, 1,
		    OTRL_NOTIFY_ERROR, _("OTR Error"), buf, NULL);
	    g_free(buf);
	    break;
	case OTRL_MSGEVENT_RCVDMSG_MALFORMED:
	    buf = g_strdup_printf(_("We received a malformed data "
		    "message from %s."), context->username);
	    display_otr_message_or_notify(opdata, context->accountname,
		    context->protocol, context->username, buf, 1,
		    OTRL_NOTIFY_ERROR, _("OTR Error"), buf, NULL);
	    g_free(buf);
	    break;
	case OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD:
	    buf = g_strdup_printf(_("Heartbeat received from %s.\n"),
		    context->username);
	    log_message(opdata, buf);
	    g_free(buf);
	    break;
	case OTRL_MSGEVENT_LOG_HEARTBEAT_SENT:
	    buf = g_strdup_printf(_("Heartbeat sent to %s.\n"),
		    context->username);
	    log_message(opdata, buf);
	    g_free(buf);
	    break;
	case OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR:
	    display_otr_message_or_notify(opdata, context->accountname,
		    context->protocol, context->username, message, 1,
		    OTRL_NOTIFY_ERROR, _("OTR Error"), message, NULL);
	    break;
	case OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED:
	    buf = g_strdup_printf(_("<b>The following message received "
		    "from %s was <i>not</i> encrypted: [</b>%s<b>]</b>"),
		    context->username, message);
	    display_otr_message_or_notify(opdata, context->accountname,
		    context->protocol, context->username, buf, 1,
		    OTRL_NOTIFY_INFO, _("Received unencrypted message"),
		    buf, NULL);
	    emit_msg_received(context, buf);
	    g_free(buf);
	    break;
	case OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED:
	    buf = g_strdup_printf(_("Unrecognized OTR message received "
		    "from %s.\n"), context->username);
	    log_message(opdata, buf);
	    g_free(buf);
	    break;
	case OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE:
	    if (*last_msg_event == msg_event) {
		break;
	    }
	    buf = g_strdup_printf(_("%s has sent a message intended for a "
		    "different session. If you are logged in multiple times, "
		    "another session may have received the message."),
		    context->username);
	    display_otr_message_or_notify(opdata, context->accountname,
		    context->protocol, context->username, buf, 1,
		    OTRL_NOTIFY_INFO, _("Received message for a different "
		    "session"), buf, NULL);
	    g_free(buf);
	    break;
    }

    *last_msg_event = msg_event;
}

#ifdef DUMP_RECEIVED_SYMKEY
static void dump_data(const unsigned char *d, size_t l)
{
    size_t i;
    for (i=0;i<l;++i) printf("%02x", d[i]);
}

static void received_symkey_cb(void *opdata, ConnContext *context,
	unsigned int use, const unsigned  char *usedata,
	size_t usedatalen, const unsigned char *symkey)
{
    printf("Received symkey use: %08x\nKey: ", use);
    dump_data(symkey, OTRL_EXTRAKEY_BYTES);
    printf("\nUsedata: ");
    dump_data(usedata, usedatalen);
    printf("\n\n");
}
#endif

static guint otrg_plugin_timerid = 0;

/* Called by the glib main loop, as set up by stop_start_timer */
static gboolean timer_fired_cb(gpointer data);

/* Stop the timer, if it's currently running.  If interval > 0, start it
 * to periodically fire every interval seconds. */
static void stop_start_timer(unsigned int interval) {
    if (otrg_plugin_timerid) {
	g_source_remove(otrg_plugin_timerid);
	otrg_plugin_timerid = 0;
    }
    if (interval > 0) {
	otrg_plugin_timerid = g_timeout_add_seconds(interval,
		timer_fired_cb, NULL);
    }
}

/* Called by libotr */
static void timer_control_cb(void *opdata, unsigned int interval)
{
    stop_start_timer(interval);
}

static OtrlMessageAppOps ui_ops = {
    policy_cb,
    create_privkey_cb,
    is_logged_in_cb,
    inject_message_cb,
    update_context_list_cb,
    confirm_fingerprint_cb,
    write_fingerprints_cb,
    gone_secure_cb,
    gone_insecure_cb,
    still_secure_cb,
    max_message_size_cb,
    NULL,                   /* account_name */
    NULL,                   /* account_name_free */
#ifdef DUMP_RECEIVED_SYMKEY
    received_symkey_cb,
#else
    NULL,		    /* received_symkey */
#endif
    otr_error_message_cb,
    otr_error_message_free_cb,
    resent_msg_prefix_cb,
    resent_msg_prefix_free_cb,
    handle_smp_event_cb,
    handle_msg_event_cb,
    create_instag_cb,
    NULL,		    /* convert_data */
    NULL,		    /* convert_data_free */
    timer_control_cb
};

/* Called by the glib main loop, as set up by stop_start_timer */
static gboolean timer_fired_cb(gpointer data) {
    otrl_message_poll(otrg_plugin_userstate, &ui_ops, NULL);
    return TRUE;
}

static void process_sending_im(PurpleAccount *account, char *who,
	char **message, void *m)
{
    char *newmessage = NULL;
    const char *accountname = purple_account_get_username(account);
    const char *protocol = purple_account_get_protocol_id(account);
    char *username;
    gcry_error_t err;
    PurpleConversation * conv = NULL;
    otrl_instag_t instance;

    if (!who || !message || !*message)
	return;

    username = strdup(purple_normalize(account, who));

    conv = otrg_plugin_userinfo_to_conv(accountname, protocol, username, 1);

    instance = otrg_plugin_conv_to_selected_instag(conv, OTRL_INSTAG_BEST);

    err = otrl_message_sending(otrg_plugin_userstate, &ui_ops, NULL,
	    accountname, protocol, username, instance, *message, NULL,
	    &newmessage, OTRL_FRAGMENT_SEND_ALL_BUT_LAST, NULL, NULL, NULL);

    if (err) {
	/* Do not send out plain text */
	char *ourm = strdup("");
	free(*message);
	*message = ourm;
    } else if (newmessage) {
	*message = strdup(newmessage);
    }

    otrl_message_free(newmessage);
    free(username);
}

/* Abort the SMP protocol.  Used when malformed or unexpected messages
 * are received. */
void otrg_plugin_abort_smp(ConnContext *context)
{
    otrl_message_abort_smp(otrg_plugin_userstate, &ui_ops, NULL, context);
}

/* Start the Socialist Millionaires' Protocol over the current connection,
 * using the given initial secret, and optionally a question to pass to
 * the buddy. */
void otrg_plugin_start_smp(ConnContext *context, const char *question,
	const unsigned char *secret, size_t secretlen)
{
    otrl_message_initiate_smp_q(otrg_plugin_userstate, &ui_ops, NULL,
	    context, question, secret, secretlen);
}

/* Continue the Socialist Millionaires' Protocol over the current connection,
 * using the given initial secret (ie finish step 2). */
void otrg_plugin_continue_smp(ConnContext *context,
	const unsigned char *secret, size_t secretlen)
{
    otrl_message_respond_smp(otrg_plugin_userstate, &ui_ops, NULL,
	    context, secret, secretlen);
}

/* Send the default OTR Query message to the correspondent of the given
 * context, from the given account.  [account is actually a
 * PurpleAccount*, but it's declared here as void* so this can be passed
 * as a callback.] */
void otrg_plugin_send_default_query(ConnContext *context, void *vaccount)
{
    PurpleAccount *account = vaccount;
    char *msg;
    OtrgUiPrefs prefs;

    otrg_ui_get_prefs(&prefs, account, context->username);
    msg = otrl_proto_default_query_msg(context->accountname,
	    prefs.policy);
    otrg_plugin_inject_message(account, context->username,
	    msg ? msg : "?OTRv23?");
    free(msg);
}

/* Send the default OTR Query message to the correspondent of the given
 * conversation. */
void otrg_plugin_send_default_query_conv(PurpleConversation *conv)
{
    PurpleAccount *account;
    const char *username, *accountname;
    char *msg;
    OtrgUiPrefs prefs;

    account = purple_conversation_get_account(conv);
    accountname = purple_account_get_username(account);
    username = purple_conversation_get_name(conv);

    otrg_ui_get_prefs(&prefs, account, username);
    msg = otrl_proto_default_query_msg(accountname, prefs.policy);
    otrg_plugin_inject_message(account, username, msg ? msg : "?OTRv23?");
    free(msg);

}

static int plugin_get_commitment(uint64_t epoch, uint8_t **comm_msg_data, size_t *msg_data_len){
  uint8_t resp;
  uint8_t *msg_data;
  size_t len;
  Protos__ServerResp *serv_resp;
  Protos__Commitment *comm;
  
  printf("otr-plugin: retrieving the commitment\n");
  
  char *server;
  get_server_name(coniks_state->accountname, &server);

  resp = get_commitment(PROTOS__COMMITMENT_REQ__COMMITMENT_TYPE__SELF, epoch, 
                        server, &msg_data, &len);
  
  if(resp == server_resp_m){    
    serv_resp = protos__server_resp__unpack(NULL, len, msg_data);   
    if (serv_resp == NULL){
      return -1;
    }
    
    if(serv_resp->has_message){
      protos__server_resp__free_unpacked(serv_resp, NULL);
      return 0;
    }
    else{
      protos__server_resp__free_unpacked(serv_resp, NULL);
      return -2;
    }
  }
  else if(resp == commitment_resp_m){
    comm = protos__commitment__unpack(NULL, len, msg_data);   
    if (comm == NULL){
      return -3;
    }

    if(!comm->has_epoch){
      return -4;
    }
  }
  else{
    return -5;
  }
  
  printf("otr-plugin: commitment data seems fine\n");
  
  // we got here so we know the message data is good
  *comm_msg_data = malloc(len);

  if(*comm_msg_data == NULL){
    return -6;
  }
  else{
    memcpy(*comm_msg_data, msg_data, len);
    *msg_data_len = len;
  }

  return 1;
}

static int plugin_get_public_key(char *accountname, uint64_t epoch_date, uint8_t **ap_msg_data, size_t *msg_data_len){

  uint8_t resp;
  uint8_t *msg_data;
  size_t len;
  Protos__ServerResp *serv_resp;
  Protos__AuthPath *auth_path;
  
  resp = get_public_key(accountname, epoch_date, &msg_data, &len); // TODO: find a better way to get most recent version

  if(resp == server_resp_m){
    serv_resp = protos__server_resp__unpack(NULL, len, msg_data);   
    if (serv_resp == NULL){
      return -1;
    }
    
    if(serv_resp->has_message && 
       serv_resp->message == PROTOS__SERVER_RESP__MESSAGE__NAME_NOT_FOUND_ERR){
      protos__server_resp__free_unpacked(serv_resp, NULL);
      return 0;
    }
    else{
      protos__server_resp__free_unpacked(serv_resp, NULL);
      return -2;
    }
  }
  else if(resp == auth_path_m){
    auth_path = protos__auth_path__unpack(NULL, len, msg_data);   
    if (auth_path == NULL){
      return -3;
    }

  }
  else{
    
    return -4;
  }

  // we got here so we know the message data is good
  *ap_msg_data = malloc(len);
  
  if(*ap_msg_data == NULL){
    return -6;
  }
  else{
    memcpy(*ap_msg_data, msg_data, len);
    *msg_data_len = len;
  }
  
  return 1;
  
}

/* Actually perform the continuity checks */
static gboolean do_continuity_checks_self(Protos__Commitment *comm, Protos__AuthPath *auth_path){
  // first check the hash chain, for this retrieve the previous commitment and get its root hash
  Protos__AuthPath__RootNode *cur_root;
  cur_root = auth_path->root;

  uint64_t last_epoch;

  // have we ever checked ourselves before?
  if(coniks_state->last_epoch == 0){
    // no, otherwise this value would have been initialized in plugin-load
    // this is actually my initial epoch with the server
    last_epoch = coniks_state->serv_init_epoch; // server epoch numbers start at some non-zero number
  }
  else{
    last_epoch = coniks_state->last_epoch;
  }

  uint64_t diff = comm->epoch - last_epoch;
  int eq_res, val_res;  
  char err_msg[1500];

  if(diff == 0){
    printf("otr-plugin: first equivocation check for epoch %lu\n", comm->epoch);
    eq_res = coniks_non_equivocation_check(coniks_state, comm, NULL, cur_root, err_msg);

    if(!eq_res){
      return 0;
    }
    else{
      val_res = coniks_validity_check(comm, auth_path, err_msg);
      return val_res;
    }
  }
  else if(diff > 0){
    Protos__Commitment *cur_comm = comm;
    Protos__AuthPath *cur_authPath = auth_path;
    Protos__Commitment *prev_comm;

     printf("otr-plugin: starting epoch: %lu\n", comm->epoch);

    uint64_t ep;
    for(ep = comm->epoch; ep > last_epoch; ){
        printf("otr-plugin: current epoch: %lu\n", ep);
    
      uint8_t *msg_data;
      size_t msg_data_len;

      if(ep < comm->epoch){
        // only get the next authentication path if we're past the first iteration
        int ret = plugin_get_public_key(coniks_state->accountname, ep, &msg_data, 
                                        &msg_data_len);
        
        if(ret != 1){
          return 0;
        }
        
        cur_authPath = protos__auth_path__unpack(NULL, msg_data_len, msg_data);   
        if (cur_authPath == NULL){
          return 0;
        }
        
        cur_root = cur_authPath->root;

        free(msg_data);
      }

      // get the commitment for the previous epoch so we can check the commitment 
      // history
      int ret = plugin_get_commitment(ep-coniks_state->serv_epoch_interval, 
                                      &msg_data, &msg_data_len);

      if(ret != 1){
        return 0;
      }

      prev_comm = protos__commitment__unpack(NULL, msg_data_len, msg_data);   
      if (prev_comm == NULL){
        return 0;
      }

      free(msg_data);
      
      printf("otr-plugin: before equivocation check in loop\n");

      eq_res = coniks_non_equivocation_check(coniks_state, cur_comm, prev_comm, 
                                             cur_root, err_msg);

      if(!eq_res){
        return 0;
      }
      
       printf("otr-plugin: equivocation check passed\n");
      
      val_res = coniks_validity_check(cur_comm, cur_authPath, err_msg);

      if(!val_res){
        return 0;
      }

      printf("otr-plugin: validity check passed\n");

      cur_comm = prev_comm;
      ep = prev_comm->epoch;
      
    }

    //at this point cur_comm should be equal to last_comm, so let's perform 
    // this equality check...
    if (coniks_state->last_comm == NULL){
      // ...unless we've never checked ourselves, then we *have* to trust our provider
      return 1;
    }
    else if (coniks_state->last_epoch != cur_comm->epoch) {
      return 0;
    }

    int all_good;
    all_good =  compare_commitments(coniks_state->last_comm, cur_comm);

    printf("otr-plugin: checking that stored commitment is consistent with recv comm\n");

    return all_good;
  }
  
  // we should really never get here
  return 0;

}

/* Retrieves all necessary information to perform the coniks continuity checks on the requested user 
* for the current epoch */
static void otrg_plugin_coniks_continuity_checks_self(char *accountname)
{
  // key lookup
  uint8_t resp;
  uint8_t *msg_data;
  size_t len;
  Protos__ServerResp *serv_resp;
  Protos__AuthPath *auth_path = NULL;
  Protos__Commitment *comm = NULL;

  uint64_t current_time = get_current_time_millis();

  // retrieve the most recent public key for myself
  char err_buf[150];
  resp = get_public_key(accountname, current_time, &msg_data, &len);  // this helps us report error messages to the user according to the server response

  coniks_state->accountname = accountname;

  OtrgDialogWaitHandle waithandle;

  if(resp == server_resp_m){
    serv_resp = protos__server_resp__unpack(NULL, len, msg_data);   
    if (serv_resp == NULL){
      sprintf(err_buf, "resp: error unpacking incoming message.");
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Public Key Lookup", err_buf, NULL, NULL, NULL);
      goto out_err;
    }
    
    if(serv_resp->has_message && 
       serv_resp->message == PROTOS__SERVER_RESP__MESSAGE__NAME_NOT_FOUND_ERR){
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Public Key Lookup", "The server couldn't find your name.", "If you generated your public key less than an hour ago, the server has not published a snapshot that includes your key yet. Your key will appear within the hour. If you have not generated a public key, please go to Configure Plugin.", NULL, NULL);  
      goto out_err;
    }
    else{
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Public Key Lookup", "Something went wrong", NULL, NULL, NULL);
      goto out_err;
    }
  }
  else if(resp == auth_path_m){
    auth_path = protos__auth_path__unpack(NULL, len, msg_data);   
    if (auth_path == NULL){
      sprintf(err_buf, "resp: error unpacking incoming message.");
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Public Key Lookup", err_buf, NULL, NULL, NULL);
      goto out_err;
    }
    
    if (auth_path->leaf == NULL) {
        printf("otr-plugin: uhhh...\n");
    }

  }
  else{
    sprintf(err_buf, "Bad server response");
    purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Public key lookup", err_buf, NULL, NULL, NULL);
    goto out_err;
  }

  // get the server's name
  char *server;
  get_server_name(accountname, &server);

  resp = get_commitment(PROTOS__COMMITMENT_REQ__COMMITMENT_TYPE__SELF, current_time, 
                        server, &msg_data, &len);
  
  if(resp == server_resp_m){    
    serv_resp = protos__server_resp__unpack(NULL, len, msg_data);   
    if (serv_resp == NULL){
      sprintf(err_buf, "resp: error unpacking incoming message.");
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Commitment retrieval", err_buf, NULL, NULL, NULL);
      goto out_err;
    }
    
    if(serv_resp->has_message){
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Commitment retrieval", "Server error", NULL, NULL, NULL);
      goto out_err;
    }
  }
  else if(resp == commitment_resp_m){
    comm = protos__commitment__unpack(NULL, len, msg_data);   
    if (comm == NULL){
      sprintf(err_buf, "resp: error unpacking incoming message.");
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Commitment retrieval", err_buf, NULL, NULL, NULL);
      goto out_err;
    }

    if(!comm->has_epoch){
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Commitment retrieval", "No epoch", NULL, NULL, NULL);
      goto out_err;
    }
  }
  else{
    sprintf(err_buf, "Bad server response");
    printf("otr-plugin: server's bad response: %d\n", resp);
    purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Commitment retrieval", err_buf, NULL, NULL, NULL);
    goto out_err;
    } 

  // now call the actual do_check function
  gboolean check_passed = do_continuity_checks_self(comm, auth_path);

  if(check_passed && coniks_state->check_status == in_prog_stat){
    // now we can update the coniks state and save the new state
    update_coniks_state(coniks_state, accountname, comm);
    gchar *coniksfile = g_build_filename(purple_user_dir(), CONIKSFNAME, NULL);
    gcry_error_t err = write_coniks_state(coniks_state, coniksfile); 

    if (err) {
      purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Continuity Self Checks", gcry_strerror(err), NULL, NULL, NULL);
      goto out_err;
    }
  
  }
  else{
    purple_notify_message(otrg_plugin_handle, PURPLE_NOTIFY_MSG_INFO, "Continuity Self Checks", "Malicious server behavior suspected. Use your secure identity with caution.", NULL, NULL, NULL);
  }

 out_err:;
  return;

}


static gboolean process_receiving_im(PurpleAccount *account, char **who,
	char **message, int *flags, void *m)
{
    char *newmessage = NULL;
    OtrlTLV *tlvs = NULL;
    OtrlTLV *tlv = NULL;
    char *username;
    gboolean res;
    const char *accountname;
    const char *protocol;

    if (!who || !*who || !message || !*message)
	return 0;

    username = strdup(purple_normalize(account, *who));
    accountname = purple_account_get_username(account);
    protocol = purple_account_get_protocol_id(account);

    res = otrl_message_receiving(otrg_plugin_userstate, &ui_ops, NULL,
	    accountname, protocol, username, *message,
	    &newmessage, &tlvs, NULL, NULL, NULL);

    if (newmessage) {
	char *ourm = strdup(newmessage);
	otrl_message_free(newmessage);
	free(*message);
	*message = ourm;
    }

    tlv = otrl_tlv_find(tlvs, OTRL_TLV_DISCONNECTED);
    if (tlv) {
	/* Notify the user that the other side disconnected. */
	otrg_dialog_finished(accountname, protocol, username);
	otrg_ui_update_keylist();
    }

    otrl_tlv_free(tlvs);

    free(username);

    /* If we're supposed to ignore this incoming message (because it's a
     * protocol message), set it to NULL, so that other plugins that
     * catch receiving-im-msg don't return 0, and cause it to be
     * displayed anyway. */
    if (res) {
	free(*message);
	*message = NULL;
    }
    return res;
}

/* Find the ConnContext appropriate to a given PurpleConversation. */
ConnContext *otrg_plugin_conv_to_context(PurpleConversation *conv,
	otrl_instag_t their_instance, int force_create)
{
    PurpleAccount *account;
    char *username;
    const char *accountname, *proto;
    ConnContext *context;

    if (!conv) return NULL;

    account = purple_conversation_get_account(conv);
    accountname = purple_account_get_username(account);
    proto = purple_account_get_protocol_id(account);
    username = g_strdup(
	    purple_normalize(account, purple_conversation_get_name(conv)));

    context = otrl_context_find(otrg_plugin_userstate, username, accountname,
	    proto, their_instance, force_create, NULL, NULL, NULL);

    g_free(username);

    return context;
}

/* Given a PurpleConversation, return the selected instag */
otrl_instag_t otrg_plugin_conv_to_selected_instag(PurpleConversation *conv,
	otrl_instag_t default_val)
{
    otrl_instag_t *selected_instance;

    if (!conv || !conv->data) {
	return default_val;
    }

    selected_instance = purple_conversation_get_data(conv,
	    "otr-ui_selected_ctx");

    if (!selected_instance) {
	return default_val;
    }

    return *selected_instance;
}

/* Given a PurpleConversation, return the selected ConnContext */
ConnContext* otrg_plugin_conv_to_selected_context(PurpleConversation *conv,
	int force_create)
{
    otrl_instag_t selected_instance;

    selected_instance = otrg_plugin_conv_to_selected_instag(conv,
	    OTRL_INSTAG_BEST);

    return otrg_plugin_conv_to_context(conv, selected_instance, force_create);
}

static void process_conv_create(PurpleConversation *conv)
{
    otrl_instag_t * selected_instance;
    OtrlMessageEvent * msg_event;
    if (!conv) return;

    /* If this malloc fails (or the other below), trouble will be
     * unavoidable. */
    selected_instance = g_malloc(sizeof(otrl_instag_t));
    *selected_instance = OTRL_INSTAG_BEST;
    purple_conversation_set_data(conv, "otr-ui_selected_ctx",
	    (gpointer)selected_instance);

    msg_event = g_malloc(sizeof(OtrlMessageEvent));
    *msg_event = OTRL_MSGEVENT_NONE;
    purple_conversation_set_data(conv, "otr-last_msg_event",
	    (gpointer)msg_event);

    otrg_dialog_new_conv(conv);
}

/* Wrapper around process_conv_create for callback purposes */
static void process_conv_create_cb(PurpleConversation *conv, void *data)
{
    process_conv_create(conv);
}

static void process_conv_updated(PurpleConversation *conv,
	PurpleConvUpdateType type, void *data)
{
    /* See if someone's trying to turn logging on for this conversation,
     * and we don't want them to. */
    if (type == PURPLE_CONV_UPDATE_LOGGING) {
	ConnContext *context;
	OtrgUiPrefs prefs;
	PurpleAccount *account = purple_conversation_get_account(conv);
	otrg_ui_get_prefs(&prefs, account, purple_conversation_get_name(conv));

	context = otrg_plugin_conv_to_selected_context(conv, 0);
	if (context && prefs.avoid_logging_otr &&
		context->msgstate == OTRL_MSGSTATE_ENCRYPTED &&
		conv->logging == TRUE) {
	    purple_conversation_set_logging(conv, FALSE);
	}
    }
}

static void process_conv_destroyed(PurpleConversation *conv)
{
    otrl_instag_t * selected_instance =
	    purple_conversation_get_data(conv, "otr-ui_selected_ctx");
    OtrlMessageEvent * msg_event =
	    purple_conversation_get_data(conv, "otr-last_msg_event");

    if (selected_instance) {
	g_free(selected_instance);
    }

    if (msg_event) {
	g_free(msg_event);
    }

    g_hash_table_remove(conv->data, "otr-ui_selected_ctx");
    g_hash_table_remove(conv->data, "otr-last_msg_event");
}

static void process_connection_change(PurpleConnection *conn, void *data)
{
    /* If we log in or out of a connection, make sure all of the OTR
     * buttons are in the appropriate sensitive/insensitive state. */
    otrg_dialog_resensitize_all();
}

static void otr_options_cb(PurpleBlistNode *node, gpointer user_data)
{
    /* We've already checked PURPLE_BLIST_NODE_IS_BUDDY(node) */
    PurpleBuddy *buddy = (PurpleBuddy *)node;

    /* Modify the settings for this buddy */
    otrg_ui_config_buddy(buddy);
}

static void supply_extended_menu(PurpleBlistNode *node, GList **menu)
{
    PurpleMenuAction *act;
    PurpleBuddy *buddy;
    PurpleAccount *acct;
    const char *proto;

    if (!PURPLE_BLIST_NODE_IS_BUDDY(node)) return;

    /* Extract the account, and then the protocol, for this buddy */
    buddy = (PurpleBuddy *)node;
    acct = buddy->account;
    if (acct == NULL) return;
    proto = purple_account_get_protocol_id(acct);
    if (!otrg_plugin_proto_supports_otr(proto)) return;

    act = purple_menu_action_new(_("OTR Settings"),
	    (PurpleCallback)otr_options_cb, NULL, NULL);
    *menu = g_list_append(*menu, act);
}

/* Disconnect all context instances, sending a notice to the other side, if
 * appropriate. */
void otrg_plugin_disconnect_all_instances(ConnContext *context)
{
    otrl_message_disconnect_all_instances(otrg_plugin_userstate, &ui_ops, NULL,
	    context->accountname, context->protocol, context->username);
}

/* Disconnect a context, sending a notice to the other side, if
 * appropriate. */
void otrg_plugin_disconnect(ConnContext *context)
{
    otrl_message_disconnect(otrg_plugin_userstate, &ui_ops, NULL,
	    context->accountname, context->protocol, context->username,
	    context->their_instance);
}

/* Write the fingerprints to disk. */
void otrg_plugin_write_fingerprints(void)
{
#ifndef WIN32
    mode_t mask;
#endif  /* WIN32 */
    FILE *storef;
    gchar *storefile = g_build_filename(purple_user_dir(), STOREFNAME, NULL);
#ifndef WIN32
    mask = umask (0077);
#endif  /* WIN32 */
    storef = g_fopen(storefile, "wb");
#ifndef WIN32
    umask (mask);
#endif  /* WIN32 */
    g_free(storefile);
    if (!storef) return;
    otrl_privkey_write_fingerprints_FILEp(otrg_plugin_userstate, storef);
    fclose(storef);
}

/* Find the PurpleConversation appropriate to the given userinfo.  If
 * one doesn't yet exist, create it if force_create is true. */
PurpleConversation *otrg_plugin_userinfo_to_conv(const char *accountname,
	const char *protocol, const char *username, int force_create)
{
    PurpleAccount *account;
    PurpleConversation *conv;

    account = purple_accounts_find(accountname, protocol);
    if (account == NULL) return NULL;

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
	    username, account);
    if (conv == NULL && force_create) {
	conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, username);
    }

    return conv;
}

/* Find the PurpleConversation appropriate to the given ConnContext.  If
 * one doesn't yet exist, create it if force_create is true. */
PurpleConversation *otrg_plugin_context_to_conv(ConnContext *context,
	int force_create)
{
    return otrg_plugin_userinfo_to_conv(context->accountname,
	    context->protocol, context->username, force_create);
}

/* What level of trust do we have in the privacy of this ConnContext? */
TrustLevel otrg_plugin_context_to_trust(ConnContext *context)
{
    TrustLevel level = TRUST_NOT_PRIVATE;

    if (context && context->msgstate == OTRL_MSGSTATE_ENCRYPTED) {
	if (context->active_fingerprint &&
		context->active_fingerprint->trust &&
		context->active_fingerprint->trust[0] != '\0') {
	    level = TRUST_PRIVATE;
	} else {
	    level = TRUST_UNVERIFIED;
	}
    } else if (context && context->msgstate == OTRL_MSGSTATE_FINISHED) {
	level = TRUST_FINISHED;
    }

    return level;
}

/* Send the OTRL_TLV_DISCONNECTED packets when we're about to quit. */
static void process_quitting(void)
{
    ConnContext *context = otrg_plugin_userstate->context_root;
    while(context) {
	ConnContext *next = context->next;
	if (context->msgstate == OTRL_MSGSTATE_ENCRYPTED &&
		context->protocol_version > 1) {
	    otrg_plugin_disconnect(context);
	}
	context = next;
    }
}

/* Read the maxmsgsizes from a FILE* into the given GHashTable.
 * The FILE* must be open for reading. */
static void mms_read_FILEp(FILE *mmsf, GHashTable *ght)
{
    char storeline[50];
    size_t maxsize = sizeof(storeline);

    if (!mmsf) return;

    while(fgets(storeline, maxsize, mmsf)) {
	char *protocol;
	char *prot_in_table;
	char *mms;
	int *mms_in_table;
	char *tab;
	char *eol;
	/* Parse the line, which should be of the form:
	 *    protocol\tmaxmsgsize\n          */
	protocol = storeline;
	tab = strchr(protocol, '\t');
	if (!tab) continue;
	*tab = '\0';

	mms = tab + 1;
	tab = strchr(mms, '\t');
	if (tab) continue;
	eol = strchr(mms, '\r');
	if (!eol) eol = strchr(mms, '\n');
	if (!eol) continue;
	*eol = '\0';

	prot_in_table = strdup(protocol);
	mms_in_table = malloc(sizeof(int));
	*mms_in_table = atoi(mms);
	g_hash_table_insert(ght, prot_in_table, mms_in_table);
    }
}

static void otrg_str_free(gpointer data)
{
    g_free((char*)data);
}

static void otrg_int_free(gpointer data)
{
    g_free((int*)data);
}

static void otrg_init_mms_table()
{
    /* Hardcoded defaults for maximum message sizes for various
     * protocols.  These can be overridden in the user's MAXMSGSIZEFNAME
     * file. */
    static const struct s_OtrgIdProtPair {
	char *protid;
	int maxmsgsize;
    } mmsPairs[] = {{"prpl-msn", 1409}, {"prpl-icq", 2346},
	{"prpl-aim", 2343}, {"prpl-yahoo", 799}, {"prpl-gg", 1999},
	{"prpl-irc", 417}, {"prpl-oscar", 2343},
        {"prpl-novell", 1792}, {NULL, 0}};
    int i = 0;
    gchar *maxmsgsizefile;
    FILE *mmsf;

    mms_table = g_hash_table_new_full(g_str_hash, g_str_equal,
	    otrg_str_free, otrg_int_free);

    for (i=0; mmsPairs[i].protid != NULL; i++) {
	char* nextprot = g_strdup(mmsPairs[i].protid);
	int* nextsize = g_malloc(sizeof(int));
	*nextsize = mmsPairs[i].maxmsgsize;
	g_hash_table_insert(mms_table, nextprot, nextsize);
    }

    maxmsgsizefile = g_build_filename(purple_user_dir(),
	    MAXMSGSIZEFNAME, NULL);

    if (maxmsgsizefile) {
	mmsf = g_fopen(maxmsgsizefile, "rt");
	/* Actually read the file here */
	if (mmsf) {
	    mms_read_FILEp(mmsf, mms_table);
	    fclose(mmsf);
	}
	g_free(maxmsgsizefile);
    }
}

static void otrg_free_mms_table()
{
    g_hash_table_destroy(mms_table);
    mms_table = NULL;
}

static gboolean otr_plugin_load(PurplePlugin *handle)
{
    gchar *privkeyfile = g_build_filename(purple_user_dir(), PRIVKEYFNAME,
           NULL);
    gchar *storefile = g_build_filename(purple_user_dir(), STOREFNAME, NULL);
    gchar *instagfile = g_build_filename(purple_user_dir(), INSTAGFNAME, NULL);
    gchar *coniksfile = g_build_filename(purple_user_dir(), CONIKSFNAME, NULL);
    gchar *coniksservfile = g_build_filename(purple_user_dir(), CONIKSSERVFNAME, NULL);
    void *conv_handle = purple_conversations_get_handle();
    void *conn_handle = purple_connections_get_handle();
    void *blist_handle = purple_blist_get_handle();
    void *core_handle = purple_get_core();
    FILE *privf;
    FILE *storef;
    FILE *instagf;
    FILE *coniksf;
    FILE *serverf;
#if BETA_DIALOG && defined USING_GTK /* Only for beta */
    GtkWidget *dialog;
    GtkWidget *dialog_text;
    PidginBuddyList *blist;
    gchar * buf = NULL;
#endif

    if (!privkeyfile || !storefile || !instagfile || !coniksfile || !coniksservfile) {
	g_free(privkeyfile);
	g_free(storefile);
	g_free(instagfile);
        g_free(coniksfile);
        g_free(coniksservfile);
	return 0;
    }

#if BETA_DIALOG && defined USING_GTK /* Only for beta */
    blist = pidgin_blist_get_default_gtk_blist();

    if (time(NULL) > 1356998400) /* 2013-01-01 */ {
	buf = g_strdup_printf(_("OTR PLUGIN v%s"), PIDGIN_OTR_VERSION);
	dialog = gtk_dialog_new_with_buttons (buf,
		GTK_WINDOW(blist->window),
		GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
		GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);
	dialog_text = gtk_label_new(NULL);
	gtk_widget_set_size_request(dialog_text, 350, 100);
	gtk_label_set_line_wrap(GTK_LABEL(dialog_text), TRUE);
	g_free(buf);
	buf = g_strdup_printf(_("This beta copy of the "
		"Off-the-Record Messaging v%s Pidgin plugin has expired as of "
		"2013-01-01. Please look for an updated release at "
		"http://otr.cypherpunks.ca/"), PIDGIN_OTR_VERSION);
	gtk_label_set_text(GTK_LABEL(dialog_text), buf);
	gtk_widget_show(dialog_text);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), dialog_text,
		TRUE, TRUE, 0);
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);

	g_free(buf);
	g_free(privkeyfile);
	g_free(storefile);
	g_free(instagfile);
        g_free(coniksfile);
        g_free(coniksservfile);
	return 0;
    }

    buf = g_strdup_printf(_("OTR PLUGIN v%s"), PIDGIN_OTR_VERSION);
    dialog = gtk_dialog_new_with_buttons (buf,
	    GTK_WINDOW(blist->window),
	    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
	    GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);
    dialog_text = gtk_label_new(NULL);
    gtk_widget_set_size_request(dialog_text, 350, 100);
    gtk_label_set_line_wrap(GTK_LABEL(dialog_text), TRUE);
    g_free(buf);
    buf = g_strdup_printf(_("You have enabled a beta "
	    "version of the Off-the-Record Messaging v%s Pidgin plugin. "
	    "This version is intended for testing purposes only and is not "
	    "for general purpose use."), PIDGIN_OTR_VERSION);
    gtk_label_set_text(GTK_LABEL(dialog_text), buf);
    gtk_widget_show(dialog_text);
    gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), dialog_text,
	    TRUE, TRUE, 0);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    g_free(buf);
#endif

    privf = g_fopen(privkeyfile, "rb");
    storef = g_fopen(storefile, "rb");
    instagf = g_fopen(instagfile, "rb");
    coniksf = g_fopen(coniksfile, "rb");
    serverf = g_fopen(coniksservfile, "rb");
    g_free(privkeyfile);
    g_free(storefile);
    g_free(instagfile);
    g_free(coniksfile);
    g_free(coniksservfile);

    otrg_init_mms_table();

    otrg_plugin_handle = handle;

    /* Make our OtrlUserState; we'll only use the one. */
    otrg_plugin_userstate = otrl_userstate_create();
    coniks_state = create_coniks_state();

    otrg_plugin_timerid = 0;

    otrl_privkey_read_FILEp(otrg_plugin_userstate, privf);
    otrl_privkey_read_fingerprints_FILEp(otrg_plugin_userstate, storef,
	    NULL, NULL);
    otrl_instag_read_FILEp(otrg_plugin_userstate, instagf);
    read_coniks_state_FILEp(coniks_state, coniksf);
    read_server_params_FILEp(coniks_state, serverf);

    if (privf) fclose(privf);
    if (storef) fclose(storef);
    if (instagf) fclose(instagf);
    if (coniksf) fclose(coniksf);
    if (serverf) fclose(serverf);

    otrg_ui_update_fingerprint();

    // move self checks to inject_message

    purple_signal_connect(core_handle, "quitting", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_quitting), NULL);
    purple_signal_connect(conv_handle, "sending-im-msg", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_sending_im), NULL);
    purple_signal_connect(conv_handle, "receiving-im-msg", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_receiving_im), NULL);
    purple_signal_connect(conv_handle, "conversation-updated",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_conv_updated), NULL);
    purple_signal_connect(conv_handle, "conversation-created",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_conv_create_cb), NULL);
    purple_signal_connect(conv_handle, "deleting-conversation",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_conv_destroyed), NULL);
    purple_signal_connect(conn_handle, "signed-on", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_connection_change), NULL);
    purple_signal_connect(conn_handle, "signed-off", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_connection_change), NULL);
    purple_signal_connect(blist_handle, "blist-node-extended-menu",
	    otrg_plugin_handle, PURPLE_CALLBACK(supply_extended_menu), NULL);

    otrg_ui_init();
    otrg_dialog_init();

    purple_conversation_foreach(process_conv_create);

    return 1;
}

static gboolean otr_plugin_unload(PurplePlugin *handle)
{
    void *conv_handle = purple_conversations_get_handle();
    void *conn_handle = purple_connections_get_handle();
    void *blist_handle = purple_blist_get_handle();
    void *core_handle = purple_get_core();

    /* Clean up all of our state. */

    purple_conversation_foreach(otrg_dialog_remove_conv);

    otrg_dialog_cleanup();
    otrg_ui_cleanup();

    purple_signal_disconnect(core_handle, "quitting", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_quitting));
    purple_signal_disconnect(conv_handle, "sending-im-msg",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_sending_im));
    purple_signal_disconnect(conv_handle, "receiving-im-msg",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_receiving_im));
    purple_signal_disconnect(conv_handle, "conversation-updated",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_conv_updated));
    purple_signal_disconnect(conv_handle, "conversation-created",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_conv_create_cb));
    purple_signal_disconnect(conv_handle, "deleting-conversation",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_conv_destroyed));
    purple_signal_disconnect(conn_handle, "signed-on", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_connection_change));
    purple_signal_disconnect(conn_handle, "signed-off", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_connection_change));
    purple_signal_disconnect(blist_handle, "blist-node-extended-menu",
	    otrg_plugin_handle, PURPLE_CALLBACK(supply_extended_menu));

    /* Stop the timer, if necessary */
    stop_start_timer(0);

    otrl_userstate_free(otrg_plugin_userstate);
    destroy_coniks_state(coniks_state);
    otrg_plugin_userstate = NULL;
    coniks_state = NULL;

    otrg_free_mms_table();

    return 1;
}

/* Return 1 if the given protocol supports OTR, 0 otherwise. */
int otrg_plugin_proto_supports_otr(const char *proto)
{
    /* Right now, OTR should work on all protocols, possibly
     * with the help of fragmentation. */
    return 1;
}

#ifdef USING_GTK

static PidginPluginUiInfo ui_info =
{
	otrg_gtk_ui_make_widget
};

#define UI_INFO &ui_info
#define PLUGIN_TYPE PIDGIN_PLUGIN_TYPE

#else

#define UI_INFO NULL
#define PLUGIN_TYPE ""

#endif

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,

	/* Use the 2.0.x API */
	2,                                                /* major version  */
	0,                                                /* minor version  */

	PURPLE_PLUGIN_STANDARD,                           /* type           */
	PLUGIN_TYPE,                                      /* ui_requirement */
	0,                                                /* flags          */
	NULL,                                             /* dependencies   */
	PURPLE_PRIORITY_DEFAULT,                          /* priority       */
	"coniks-otr",                                     /* id             */
	NULL,                                             /* name           */
	PIDGIN_OTR_VERSION,                               /* version        */
	NULL,                                             /* summary        */
	NULL,                                             /* description    */
							  /* author         */
        "Ian Goldberg, Rob Smits,\n"
	    "\t\t\tChris Alexander, Willy Lew, Lisa Du,\n"
	    "\t\t\tNikita Borisov <otr@cypherpunks.ca>",
	"https://otr.cypherpunks.ca/",                    /* homepage       */

	otr_plugin_load,                                  /* load           */
	otr_plugin_unload,                                /* unload         */
	NULL,                                             /* destroy        */

	UI_INFO,                                          /* ui_info        */
	NULL,                                             /* extra_info     */
	NULL,                                             /* prefs_info     */
	NULL                                              /* actions        */
};

static void
__init_plugin(PurplePlugin *plugin)
{
    /* Set up the UI ops */
#ifdef USING_GTK
    otrg_ui_set_ui_ops(otrg_gtk_ui_get_ui_ops());
    otrg_dialog_set_ui_ops(otrg_gtk_dialog_get_ui_ops());
#endif

#ifndef WIN32
    /* Make key generation use /dev/urandom instead of /dev/random */
    gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
#endif

    /* Initialize the OTR library */
    OTRL_INIT;

#ifdef ENABLE_NLS
    bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
#endif

    info.name        = _("CONIKS Off-the-Record Messaging");
    info.summary     = _("Provides private and secure conversations");
    info.description = _("Preserves the security and privacy of IM communications by providing "
             "automated key management and verification on top of OTR's encryption, authentication, "
			 "deniability, and perfect forward secrecy.");
}

PURPLE_INIT_PLUGIN(otr, __init_plugin, info)
