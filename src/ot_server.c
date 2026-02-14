#include "ot_server.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ht.h"


/**
 * Private method wrappers for ht API
 */
static const char* ht_set_cli_ctx(ht* ctable, const char* macstr, ot_cli_ctx cc)
{
  return ht_set(&ctable, macstr, &cc, sizeof(cc));
}

static ot_cli_ctx ht_get_cli_ctx(ht* ctable, const char* macstr)
{
  ot_cli_ctx* ret = ht_get(ctable, macstr);

  if (ret == NULL)
  {
    ot_cli_ctx failret = {0};
    failret.state = UNKN;
    return failret;
  }

  return *ret;
}

/**
 * Context initializers
 */
// Creates a server context metadata object
ot_srv_ctx_mdata ot_srv_ctx_mdata_create(const int PORT, const uint32_t SRV_IP, uint8_t* SRV_MAC)
{
  ot_srv_ctx_mdata ret = {0};

  ret.port = PORT;
  ret.sockfd = 0;
  ret.srv_ip = SRV_IP;
  memcpy(ret.srv_mac, SRV_MAC, 6);

  return ret;
}

// Allocates memory for a client context and creates it
ot_cli_ctx ot_cli_ctx_create(ot_pkt_header h, ot_cli_state_t s)
{
  ot_cli_ctx pcc = {0};
  
  // Proceed to copying values to new and allocated client context
  memcpy(&(pcc.header), &h, sizeof(ot_pkt_header));
  pcc.state = s;

  return pcc;
}

// Allocates memory for a server context and creates it
ot_srv_ctx* ot_srv_ctx_create(ot_srv_ctx_mdata sc_mdata) 
{
  // Check if we can allocate memory for a new server context
  ot_srv_ctx* psc = malloc(sizeof(ot_srv_ctx));
  if (psc == NULL)
  {
    fprintf(stderr, "ot_psc_ctx_create error: out of memory");
    free(psc);
    return NULL;
  }

  // Set the server metadata
  memcpy(&(psc->sc_mdata), &sc_mdata, sizeof(ot_srv_ctx_mdata));

  // Allocate memory for hash tables
  psc->ctable = ht_create(HT_DEF_SZ);
  psc->otable = ht_create(HT_DEF_SZ);

  return psc;
}

/**
* Client context getters/setters
*/
// Inserts a client context into a server's ctable
const char* ot_srv_set_cli_ctx(ot_srv_ctx* sc, const char* macstr, ot_cli_ctx cc)
{
  if (sc == NULL || macstr == NULL) return NULL;

  if (strlen(macstr) != 17) return NULL;

  return ht_set_cli_ctx(sc->ctable, macstr, cc);
}

// Finds a client context from a server's ctable and returns it
ot_cli_ctx ot_srv_get_cli_ctx(ot_srv_ctx* sc, const char* macstr)
{
  ot_cli_ctx failret = {0};
  failret.state = UNKN;

  if (sc == NULL || macstr == NULL)
  {
    return failret;
  }

  return ht_get_cli_ctx(sc->ctable, macstr);
}

/**
* Destructors
*/
// Frees a server context and its ctable to memory
void ot_srv_ctx_destroy(ot_srv_ctx** os) 
{
  if (os == NULL) return;
  
  ot_srv_ctx* osc = *os; 
  
  if (osc->ctable != NULL)
  {
    ht_destroy(osc->ctable);
    osc->ctable = NULL;
  }

  if (osc->otable != NULL)
  {
    ht_destroy(osc->otable);
    osc->otable = NULL;
  }

  free(*os);

  *os = NULL;

  return;
}

// Runs the server loop
void ot_srv_run() 
{
  
  return;
}

