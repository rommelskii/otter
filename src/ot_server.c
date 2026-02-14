#include "ot_server.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ht.h"


/**
 * Context initializers
 */
// Allocates memory for a client context and creates it
ot_cli_ctx* ot_cli_ctx_create(ot_pkt_header h, ot_cli_state_t s)
{
  return NULL;
}

// Allocates memory for a server context and creates it
ot_srv_ctx* ot_srv_ctx_create(const int PORT, uint32_t srv_ip, uint8_t* srv_mac) 
{
  return NULL;
}

/**
* Client context getters/setters
*/
// Inserts a client context into a server's ctable
const char* ot_srv_set_cli_ctx(ot_srv_ctx* sc, const char* macstr, ot_cli_ctx cc)
{
  return NULL;
}

// Finds a client context from a server's ctable and returns it
ot_cli_ctx ot_srv_get_cli_ctx(ot_srv_ctx* sc, const char* macstr)
{
  ot_cli_ctx ret = {0};

  return ret;
}

/**
* Destructors
*/
// Frees a server context and its ctable to memory
void ot_srv_ctx_destroy(ot_srv_ctx** os) 
{

  return;
}

// Runs the server loop
void ot_srv_run() 
{
  
  return;
}

