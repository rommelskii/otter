/* 
 * Otter Protocol (C) Rommel John Ronduen 2026
 *
 * file: ot_context.h
 *
 * Contains public API for Otter context objects 
 *
 * Otter contexts are objects that act as storage for server-client interactions.  Contexts are classified into
 * two: server (ot_srv_ctx) and client (ot_cli_ctx)
 *
 * OTTER SERVER CONTEXTS
 * The ot_srv_ctx object contains a server metadata object and two hash tables for keeping client contexts 
 * (context table or ctable) and for credentials (otfile table or otable).
 *
 * OTTER SERVER METADATA
 * The ot_srv_ctx_mdata just contains the server IP and MAC address to be used as a reference for subsequent
 * protocol operations.
 *
 * OTTER CLIENT CONTEXTS
 * The ot_cli_ctx stores client information (via the header of the last transaction packet) and the
 * timestamps for expiry and renewal. 
 *
 * CLIENT EXPIRY AND RENEWAL TIMES
 * Instead of the usual uint32_t expiry and renewal magnitude times, the client expiry (ctx_exp_time) and
 * renewal (ctx_renew_time) times are time_t variables. These are timestamps compared with the current time
 * for checking whether the client has expired or is within bounds for a renewal. 
 *
 * It is very important to note that the expiry and renewal times are first calculated during the TACK/TPRV 
 * reply of the server to the client.
 */

#ifndef OT_CONTEXT_H_
#define OT_CONTEXT_H_

// Project Headers
#include "ot_packet.h" //<< for ot_pkt_header
#include "ht.h" //<< for otable and ctables

// Standard Library Headers
#include <time.h> //<< for time_t variables

// Client Context Object
#pragma pack(push, 1)
typedef struct ot_cli_ctx 
{
  ot_pkt_header     header;
  ot_cli_state_t    state;
  time_t            ctx_exp_time;
  time_t            ctx_renew_time;
} ot_cli_ctx;
#pragma pack(pop)

// Server Metadata Object
#pragma pack(push, 1)
typedef struct ot_srv_ctx_mdata 
{
  int       sockfd; // deprecated
  int       port;   // deprecated
  uint32_t  srv_ip;
  uint8_t   srv_mac[6];
} ot_srv_ctx_mdata;
#pragma pack(pop)

// Server Context Object
typedef struct ot_srv_ctx
{
  ot_srv_ctx_mdata  sc_mdata;
  ht*               ctable;
  ht*               otable;
} ot_srv_ctx;

// Creates a server context metadata object
ot_srv_ctx_mdata 
ot_srv_ctx_mdata_create(const int PORT, const uint32_t SRV_IP, uint8_t* SRV_MAC);

// Allocates memory for a client context and creates it
ot_cli_ctx 
ot_cli_ctx_create(ot_pkt_header h, time_t exp_time, time_t renew_time);

// Finds a client context from a server's ctable and returns it
ot_cli_ctx 
ot_srv_get_cli_ctx(ot_srv_ctx* sc, const char* macstr);

// Allocates memory for a server context and creates it
ot_srv_ctx* 
ot_srv_ctx_create(ot_srv_ctx_mdata sc_metadata);

// Inserts a client context into a server's ctable
const char* 
ot_srv_set_cli_ctx(ot_srv_ctx* sc, const char* macstr, ot_cli_ctx cc);

// Frees a server context and its ctable and otable to memory, and sets the caller's server context variable
// to NULL
void 
ot_srv_ctx_destroy(ot_srv_ctx** os);

#endif //OT_CONTEXT_H_
