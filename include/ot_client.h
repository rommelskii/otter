/* 
 * Otter Protocol (C) Rommel John Ronduen 2026
 *
 * file: ot_client.h
 *
 * Contains public API for Otter clients
 *
 * Clients can utilize this API to create a client context in their programs. Client contexts
 * serve as data buffers throughout the lifecycle of the client. To mutate the client context,
 * the client must utilize the API's socket functions to authenticate, renew, or to pull information
 * from the server. 
 *
 * Recall that the ot_cli_ctx object stores the header containing the srv_ip, cli_ip, 
 * expiry time, and the renew time. All consequent functions involving the client context
 * will utilize it for storing the information throughout the client lifecycle.
 *
 * In terms of time, it has its own capability of tracking if it is within bounds of renewal. 
 * Ideally, all socket functions must be time aware whether the client can renew or has already
 * expired.
 */

#ifndef OT_CLIENT_H_
#define OT_CLIENT_H_

// Project Headers
#include "ot_context.h" //<< for context structures and methods

// Standard Library Headers
#include <stdbool.h>
#include <stdint.h>

// Authenticates the client with the server
//
// Utilizes existing information in the client context to send a TREQ pkt to the server. 
// Upon successful authentication, it receives a TACK reply from the server. If the server 
// has already authenticated, a TINV reply will be received. 
//
// Also updates the context lease and expiry time as a result of authentication.
bool ot_cli_auth(ot_cli_ctx* ctx);

// Renews the client expiry with the server
//
// Assuming the client is within renewal bounds and has not yet expired, it sends a TREN pkt to the
// server. If successful, the server sends back a TPRV pkt containing the new (most likely default) 
// expiry and renew times. The client context replaces its old values with the ones received from the
// server.
bool ot_cli_renew(ot_cli_ctx* ctx);

// Pulls credentials from a server using the username and sets it to the destination psk string 
//
// Assuming authentication has been made with the server, it sends a CPULL pkt to the server 
// containing the desired username (uname). Upon successful lookup of the username with the Otter 
// database, it receives a CPUSH pkt containing the corresponding password (psk) payload. If no 
// password is found, it receives a CINV designated for the desired username
//
// If the client is not authenticated, a CINV is also provided with the username being "UNKN"
bool ot_cli_pull(ot_cli_ctx ctx, const char* uname, char** dest_psk);



#endif //OT_CLIENT_H_
