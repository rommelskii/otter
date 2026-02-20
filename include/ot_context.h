#ifndef OT_CONTEXT_H_
#define OT_CONTEXT_H_

#include <stdlib.h>
#include <time.h>

#include "ot_packet.h"
#include "ht.h"

#pragma pack(push, 1) //<< make memcmp happy
typedef struct ot_cli_ctx 
{
  ot_pkt_header     header;
  ot_cli_state_t    state;
  time_t            ctx_exp_time;
  time_t            ctx_renew_time;
} ot_cli_ctx;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ot_srv_ctx_mdata 
{
  int       sockfd;
  int       port;
  uint32_t  srv_ip;
  uint8_t   srv_mac[6];
} ot_srv_ctx_mdata;
#pragma pack(pop)

typedef struct ot_srv_ctx
{
  ot_srv_ctx_mdata  sc_mdata;
  ht*               ctable;
  ht*               otable;
} ot_srv_ctx;

/**
 * Context initializers
 */

// Creates a server context metadata object
ot_srv_ctx_mdata ot_srv_ctx_mdata_create(const int PORT, const uint32_t SRV_IP, uint8_t* SRV_MAC);

// Allocates memory for a client context and creates it
ot_cli_ctx ot_cli_ctx_create(ot_pkt_header h, time_t exp_time, time_t renew_time);

// Allocates memory for a server context and creates it
ot_srv_ctx* ot_srv_ctx_create(ot_srv_ctx_mdata sc_metadata);

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
void ot_srv_ctx_destroy(ot_srv_ctx** os);

#endif //OT_CONTEXT_H_
