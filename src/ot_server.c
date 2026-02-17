#include "ot_server.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <assert.h>

#include "ht.h"

#define SRV_PORT 7192
#define MAX_RECV_SIZE 2048


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
ot_cli_ctx ot_cli_ctx_create(ot_pkt_header h, ot_cli_state_t s, time_t exp_time, time_t renew_time)
{
  ot_cli_ctx pcc = {0};

  // Proceed to copying values to new and allocated client context
  memcpy(&(pcc.header), &h, sizeof(ot_pkt_header));
  pcc.state = s;

  pcc.ctx_exp_time = exp_time;
  pcc.ctx_renew_time = renew_time;

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
  int server_fd, conn_fd;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);

  // Buffer for raw bytes
  uint8_t rx_buffer[MAX_RECV_SIZE];

  // 1. Create and configure socket
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(SRV_PORT);

  // 2. Bind and Listen
  bind(server_fd, (struct sockaddr *)&address, sizeof(address));
  listen(server_fd, 5);

  printf("[Server] Ready to receive bytes on port %d...\n", SRV_PORT);

  while (1) {
    conn_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    if (conn_fd < 0) continue;

    // 3. Receive Loop
    // recv returns the number of bytes actually read
    ssize_t bytes_received = recv(conn_fd, rx_buffer, MAX_RECV_SIZE, 0);

    if (bytes_received < 0) {
      perror("recv failed");
    } else if (bytes_received == 0) {
      printf("[Server] Client closed connection.\n");
    } else {
      printf("[Server] Received %zd bytes:\n", bytes_received);

      //Pre-populate the buffer with null terminators after the payload has been set 
      memset(&rx_buffer[bytes_received], 0xff, sizeof(rx_buffer) - bytes_received);

      ot_pkt* recv_pkt = ot_pkt_create();
      ot_pkt_deserialize(recv_pkt, rx_buffer, sizeof rx_buffer);

      // Begin parsing payload
      ht* ptable = ht_create(8);
      pl_parse_table_build(&ptable, recv_pkt->payload);

      // Extract the PL_STATE payload
      ot_cli_state_t* recv_state = ht_get(ptable, "PL_STATE");
      if (recv_state == NULL) 
      {
        fprintf(stderr, "[ot srv] pkt recv err: no PL_STATE payload\n");
        goto cleanup;
      }

      switch(*recv_state)
      {
        case TREQ: 
          {
            //assert("TREQ reached; not yet implemented" && false);
            uint32_t* recv_cli_ip;
            if ((recv_cli_ip = ht_get(ptable, "PL_CLI_IP")) == NULL) 
            {
              fprintf(stderr, "[ot srv] treq parse error: no cli ip payload\n");
              break;
            }

            uint8_t recv_cli_mac[6] = {0};
            if (ht_get(ptable, "PL_CLI_IP") == NULL)
            {
              fprintf(stderr, "[ot srv] treq parse error: no cli mac payload\n");
              break;
            }
            memcpy(recv_cli_mac, ht_get(ptable, "PL_CLI_MAC"), sizeof(recv_cli_mac));

            ot_pkt_header tack_hd = ot_pkt_header_create(SRV_IP, *recv_cli_ip, SRV_MAC, recv_cli_mac, 
                                                         DEF_EXP_TIME, DEF_EXP_TIME*0.75);
            ot_pkt* tack_reply = ot_pkt_create();
            tack_reply->header = tack_hd;
            
            uint8_t pl_tack_state_msgtype = (uint8_t)PL_STATE;
            uint8_t pl_tack_state_value = (uint8_t)TACK;
            uint8_t pl_tack_state_vlen = (uint8_t)sizeof(pl_tack_state_value);
            ot_payload* pl_tack_state_payload = ot_payload_create(pl_tack_state_msgtype, &pl_tack_state_value, pl_tack_state_vlen);

            uint8_t pl_tack_srv_ip_msgtype = (uint8_t)PL_SRV_IP;
            uint32_t pl_tack_srv_ip_value = SRV_IP;
            uint8_t pl_tack_srv_ip_vlen = (uint8_t)sizeof(pl_tack_srv_ip_value);
            ot_payload* pl_tack_srv_ip_payload = ot_payload_create(pl_tack_srv_ip_msgtype, &pl_tack_srv_ip_value,
                                                                   pl_tack_srv_ip_vlen);

            uint8_t pl_tack_srv_mac_msgtype = (uint8_t)PL_SRV_MAC;
            uint8_t pl_tack_srv_mac_value[6] = {0}; 
            memcpy(pl_tack_srv_mac_value, SRV_MAC, 6);

            uint8_t pl_tack_srv_mac_vlen = (uint8_t)sizeof(pl_tack_srv_mac_value);
            ot_payload* pl_tack_srv_mac_payload = ot_payload_create(pl_tack_srv_mac_msgtype, &pl_tack_srv_mac_value,
                                                                   pl_tack_srv_mac_vlen);

            uint8_t pl_tack_exp_time_msgtype = (uint8_t)PL_ETIME;
            uint32_t pl_tack_exp_time_value = DEF_EXP_TIME;
            uint8_t pl_tack_exp_time_vlen = (uint8_t)sizeof(pl_tack_exp_time_value);
            ot_payload* pl_tack_exp_time_payload = ot_payload_create(pl_tack_exp_time_msgtype, &pl_tack_exp_time_value,
                                                                     pl_tack_exp_time_vlen);

            uint8_t pl_tack_renew_time_msgtype = (uint8_t)PL_RTIME;
            uint32_t pl_tack_renew_time_value = DEF_EXP_TIME*0.75;
            uint8_t pl_tack_renew_time_vlen = (uint8_t)sizeof(pl_tack_renew_time_value);
            ot_payload* pl_tack_renew_time_payload = ot_payload_create(pl_tack_renew_time_msgtype, &pl_tack_renew_time_value,
                                                                     pl_tack_renew_time_vlen);

            tack_reply->payload = ot_payload_append(tack_reply->payload, pl_tack_state_payload);
            tack_reply->payload = ot_payload_append(tack_reply->payload, pl_tack_srv_ip_payload);
            tack_reply->payload = ot_payload_append(tack_reply->payload, pl_tack_srv_mac_payload);
            tack_reply->payload = ot_payload_append(tack_reply->payload, pl_tack_exp_time_payload);
            tack_reply->payload = ot_payload_append(tack_reply->payload, pl_tack_renew_time_payload);

            ssize_t bytes_serialized = ot_pkt_serialize(tack_reply, rx_buffer, sizeof rx_buffer);

            send(conn_fd, rx_buffer, bytes_serialized, 0);
            break;
          }
        case TREN: 
          {
            assert("TREN reached; not yet implemented" && false);
            break;
          }
        case CPULL: 
          {
            assert("CPULL reached; not yet implemented" && false);
            break;
          }
        default: 
          {
            assert("illegal client state; not yet implemented" && false);
            break;
          }
      }

    cleanup:
      ht_destroy(ptable);
      ptable=NULL;
      ot_pkt_destroy(&recv_pkt);

      close(conn_fd);
    }



    close(conn_fd);
  }
}

