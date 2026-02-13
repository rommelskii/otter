#ifndef OT_SERVER_H_
#define OT_SERVER_H_

#include "ot_packet.h"
#include "ht.h"

typedef enum 
{
  TREQ,
  TACK,
  TINV,
  TREN,
  CPULL,
  CPUSH,
  CINV,
  UNKN
} ot_cli_state_t;

typedef struct ot_cli_ctx 
{
  ot_pkt_header     header;
  ot_cli_state_t    state;
} ot_cli_ctx;

typedef struct ot_srv_ctx
{
  // Server variables
  int       sockfd;
  int       port;

  // Client context table
  ht*       cli_ctable;

  // EXPERIMENTAL: maps to specific tables
  ht*       otfile_lookup;

  // Server information
  uint32_t  srv_ip;
  uint8_t   srv_mac[6];
} ot_srv_ctx;

/**
 * Context initializers
 */
// Allocates memory for a client context and creates it
ot_cli_ctx* ot_cli_ctx_create(ot_pkt_header h, ot_cli_state_t s);

// Allocates memory for a server context and creates it
ot_srv_ctx* ot_srv_ctx_create(const int PORT, uint32_t srv_ip, uint8_t* srv_mac);


/**
* Client context getters/setters
*/
// Inserts a client context into a server's ctable
const char* ot_srv_set_cli_ctx(ot_srv_ctx* sc, const char* macstr, ot_cli_ctx cc);

// Finds a client context from a server's ctable and returns it
ot_cli_ctx ot_srv_get_cli_ctx(ot_srv_ctx* sc, const char* macstr);

/**
* Destructors
*/
// Frees a server context and its ctable to memory
void ot_srv_ctx_destroy(ot_srv_context** os);

// Runs the server loop
void ot_srv_run(); //<< insert the packet logic here

#endif //OT_SERVER_H_


