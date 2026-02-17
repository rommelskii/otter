#include "ot_server.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>

#include "ht.h"

#define SRV_PORT 7192
#define SRV_BUFFER_SIZE 2048

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
void ot_srv_run(uint32_t SRV_IP, uint8_t* SRV_MAC) 
{ 
  int server_fd, new_socket;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);
  uint8_t buffer[SRV_BUFFER_SIZE] = {0};

  // 1. Create socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  // 2. Attach socket to the port 8080 (Forcefully)
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
  address.sin_port = htons(SRV_PORT);

  // 3. Bind the socket to the network address and port
  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  // 4. Start listening for incoming connections
  if (listen(server_fd, 3) < 0) {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  printf("[OTTER SERVER] listening on port %d...\n", SRV_PORT);

  // Otter server variables go here
  ot_srv_ctx_mdata srv_mdata = ot_srv_ctx_mdata_create(SRV_PORT, SRV_IP, SRV_MAC);
  ot_srv_ctx* srv_ctx = ot_srv_ctx_create(srv_mdata);

  char ipbuf[INET_ADDRSTRLEN] = {0};

  while(1) {
    // 5. Accept a connection (This blocks until a client connects)
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
      perror("accept");
      exit(EXIT_FAILURE);
    }

    // 6. Read data from the client
    int valread = read(new_socket, buffer, SRV_BUFFER_SIZE);
    if (valread > 0) {
      printf("[Server] Received: %s\n", buffer);
    }

    ot_pkt* recv_pkt = NULL;
    ssize_t bytes_deserialized = 0;

    if ((bytes_deserialized = ot_pkt_deserialize(recv_pkt, buffer, sizeof buffer)) < 0)
    {
      printf("[OTTER SERVER] failed deserialization from %s\n", inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));

      ot_pkt_destroy(&recv_pkt);
      close(new_socket);
      memset(buffer, 0, SRV_BUFFER_SIZE);

      continue;
    } 

    printf("[OTTER SERVER] deserialized %zu bytes from %s\n", bytes_deserialized, inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));
    
    // Build parse table
    ht* parse_table = ht_create(8);
    pl_parse_table_build(&parse_table, recv_pkt->payload);
    
    // Check for the client's request type
    ot_cli_state_t* recv_req_type = ht_get(parse_table, "PL_STATE");
    switch( *recv_req_type )
    {
      case TREQ:  //<< Client is requesting to tether
      {
        // TREQ does not need a context check, just add the MAC and header as a context
        ot_cli_ctx cc = ot_cli_ctx_create(recv_pkt->header, *recv_req_type);

        char recv_macstr[24];
        bytes_to_macstr(recv_pkt->header.cli_mac, recv_macstr);

        // Add client context
        if ( ht_set_cli_ctx(srv_ctx->ctable, recv_macstr, cc) == NULL ) 
        {
          printf("[OTTER SERVER] failed to add context for client %s from %s\n", recv_macstr, inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));
        }

        // Compute expiry time
        assert("TODO: expiry/renewal time computation" && false);

        // If all successful, reply with a TACK pkt
        /*
        if ( ot_srv_tack_reply() < 0 )
        {
          printf("[OTTER SERVER] failed reply to client %s from %s\n", recv_macstr, inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));

          ot_pkt_destroy(&recv_pkt);
          close(new_socket);
          memset(buffer, 0, SRV_BUFFER_SIZE);

          continue;
        }
        */

        break;
        }
      case TREN:  //<< Client is trying to renew
        break;
      case CPULL: //<< Client is pulling credentials
        break;

      default:    //<< The client request is not a viable request (perform cleanup)
        ot_pkt_destroy(&recv_pkt);
        close(new_socket);
        memset(buffer, 0, SRV_BUFFER_SIZE);
        continue; 

        break;
    }


    // Close the specific connection, but keep the server_fd open for the next client
    close(new_socket);
    memset(buffer, 0, SRV_BUFFER_SIZE);
  }
}

