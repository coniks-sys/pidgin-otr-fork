/* coniks_buddy_check.h
 * Header file.
 * Specifically for buddy continuity checks
 * 
 * Author: Marcela Melara
 */

/* purple headers */
#include "pidgin.h"
#include "notify.h"
#include "version.h"
#include "util.h"
#include "debug.h"
#include "core.h"

/* Retrieves all necessary information to perform the coniks continuity checks on the requested user 
* for the current epoch */
void otrg_plugin_coniks_continuity_checks_buddy(ConnContext *context);
