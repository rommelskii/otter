#include "ot_server.h"


#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <assert.h>

#include "ht.h"
#include "otfile_utils.h"

#define SRV_PORT 7192
#define MAX_RECV_SIZE 2048


/**
 * Private Implementations
 */
static bool pl_treq_validate(ot_srv_ctx* sc, ht* ptable, ot_pkt* recv_pkt);

static ssize_t send_pkt(int* sockfd, ot_pkt* pkt, uint8_t* buf, size_t buflen);

static bool cli_expiry_check(ot_srv_ctx* sc, ot_pkt_header hd);

// Validates a deserialized TREN pkt.
//
// Populates the parse table (ptable) with existing payloads and checks whether the correct
// payloads exist and correlate with the header
//
// Returns true if the pkt is valid, otherwise false.
static bool tren_pl_validate(ot_srv_ctx* sc, ht* ptable, ot_pkt* recv_pkt);

static bool cpull_pl_validate(ot_srv_ctx* sc, ht* ptable, ot_pkt* recv_pkt);

// Checks if the client sending a TREN pkt can renew. 
//
// Validates whether the client is present in the srv ctable, then checks if the current time is within
// bounds for renewal.
//
// Returns true if the client can renew, otherwise false.
static bool tren_renewal_time_check(ot_srv_ctx* sc, uint8_t* cli_mac, time_t curr_time);

// Builds an allocated TINV reply pkt
//
// Sets the header (tinv_hd) and the appropriate payloads (PL_STATE, PL_SRV_IP, PL_CLI_IP)
// for a valid TINV reply to a client.
static void tinv_reply_build(ot_pkt* tinv_reply, ot_pkt_header tinv_hd, 
                             uint32_t srv_ip, uint32_t cli_ip);

static void cinv_reply_build(ot_pkt* cinv_reply, ot_pkt_header cinv_hd, uint32_t srv_ip, 
                             uint32_t cli_ip, const char* uname);

static void cpush_reply_build(ot_pkt* cpush_reply, ot_pkt_header cpush_hd, uint32_t srv_ip,
                              uint32_t cli_ip, const char* uname, const char* psk);


// Builds an allocated TPRV reply pkt 
// 
// Sets the header (tprv_hd) and the appropriate payloads (PL_STATE, PL_SRV_IP, PL_CLI_IP, 
// PL_ETIME, PL_RTIME) for a valid TPRV reply to a client.
static void tprv_reply_build(ot_pkt* tprv_reply, ot_pkt_header tprv_hd, uint32_t srv_ip, 
                             uint32_t cli_ip, uint32_t exp_time, uint32_t renew_time);

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
  time_t curr_time;

  // Socket variables
  int server_fd, conn_fd;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);
  uint8_t rx_buffer[MAX_RECV_SIZE];
  
  // Socket setup
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(SRV_PORT);

  bind(server_fd, (struct sockaddr *)&address, sizeof(address));
  listen(server_fd, 5);

  // Build server context metadata and allocate memory for server context
  ot_srv_ctx_mdata srv_mdata = ot_srv_ctx_mdata_create(SRV_PORT, SRV_IP, SRV_MAC);
  ot_srv_ctx* srv_ctx = ot_srv_ctx_create(srv_mdata);

  otfile_build("/Users/mels/projects/otter/tests/files/test.ot", &srv_ctx->otable); 

  printf("[ot srv] Ready to receive bytes on port %d...\n", SRV_PORT);

  // Start server runtime loop
  while (1) {
    // Runtime variables
    time(&curr_time);
    char ipbuf[INET_ADDRSTRLEN] = {0}; //<< for printing IP addresses via inet_ntop
    ssize_t bytes_received = 0;

    // Accept any inbound client requests
    conn_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    if (conn_fd < 0) continue;

    // Upon accepted client, receive pkt
    bytes_received = recv(conn_fd, rx_buffer, MAX_RECV_SIZE, 0);
    if (bytes_received < 0) {
      perror("recv failed");
    } else if (bytes_received == 0) {
      printf("[ot srv] Client closed connection.\n");
    } else {
      printf("[ot srv] Received %zd bytes from %s\n", bytes_received, 
             inet_ntop(AF_INET, &(address.sin_addr.s_addr), (char*)ipbuf, INET_ADDRSTRLEN));

      //Pre-populate the buffer with 0xff terminators after the payload has been set 
      memset(&rx_buffer[bytes_received], 0xff, sizeof(rx_buffer) - bytes_received);

      // Allocate memory for the recv pkt & parse table 
      ot_pkt* recv_pkt = ot_pkt_create();
      ht* ptable = ht_create(8);

      // Deserialize recv pkt from recv buffer
      ot_pkt_deserialize(recv_pkt, rx_buffer, sizeof(rx_buffer));
      if (recv_pkt == NULL)           //<< assure deserialization was successful
      {
        fprintf(stderr, "[ot srv] failed to deserialize reply from %s\n", 
                inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));
        goto cleanup;
      }
      if (recv_pkt->payload == NULL)  //<< assure that we have payloads
      {
        fprintf(stderr, "[ot srv] recv pkt has no payload from %s\n", 
                inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));
        goto cleanup;
      }

      // Build the parse table from recv_pkt payloads
      pl_parse_table_build(&ptable, recv_pkt->payload);

      // Extract the PL_STATE payload
      ot_cli_state_t* recv_state = ht_get(ptable, "PL_STATE");
      if (recv_state == NULL) 
      {
        fprintf(stderr, "[ot srv] pkt recv err: no PL_STATE payload\n");
        goto cleanup;
      }

      // State table for the defined cli state from msgtype
      switch(*recv_state)
      {
        case TREQ:
          {
            // Check if the mandatory fields (cli_ip and cli_mac) are in the payloads
            if (!pl_treq_validate(srv_ctx, ptable, recv_pkt)) 
            {
              ot_pkt* tinv_reply = ot_pkt_create();
              tinv_reply_build(tinv_reply, recv_pkt->header, SRV_IP, recv_pkt->header.cli_ip);
              if (send_pkt(&conn_fd, tinv_reply, rx_buffer, sizeof rx_buffer) < 0) 
              {
                fprintf(stderr, "[ot srv] failed to send tinv to %s\n",
                        inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));
              }
              goto cleanup; 
            }

            // After validating pkt, safely extract from parse table the mandatory info
            uint32_t* recv_cli_ip = ht_get(ptable, "PL_CLI_IP");
            
            uint8_t recv_cli_mac[6] = {0};
            memcpy(recv_cli_mac, ht_get(ptable, "PL_CLI_MAC"), sizeof(recv_cli_mac));


            // Allocate memory for TACK reply pkt and set header
            ot_pkt* tack_reply = ot_pkt_create();
            ot_pkt_header tack_hd = ot_pkt_header_create(SRV_IP, *recv_cli_ip, SRV_MAC, recv_cli_mac, 
                                                         DEF_EXP_TIME, DEF_EXP_TIME*0.75);
            tack_reply->header = tack_hd;
            
            // Start building payloads for TACK reply
            
            // PL_STATE payload
            uint8_t pl_tack_state_msgtype = (uint8_t)PL_STATE;
            uint8_t pl_tack_state_value = (uint8_t)TACK;
            uint8_t pl_tack_state_vlen = (uint8_t)sizeof(pl_tack_state_value);
            ot_payload* pl_tack_state_payload = ot_payload_create(pl_tack_state_msgtype, 
                                                                  &pl_tack_state_value, 
                                                                  pl_tack_state_vlen);

            // PL_SRV_IP payload
            uint8_t pl_tack_srv_ip_msgtype = (uint8_t)PL_SRV_IP;
            uint32_t pl_tack_srv_ip_value = SRV_IP;
            uint8_t pl_tack_srv_ip_vlen = (uint8_t)sizeof(pl_tack_srv_ip_value);
            ot_payload* pl_tack_srv_ip_payload = ot_payload_create(pl_tack_srv_ip_msgtype, 
                                                                   &pl_tack_srv_ip_value,
                                                                   pl_tack_srv_ip_vlen);

            // PL_SRV_MAC payload
            uint8_t pl_tack_srv_mac_msgtype = (uint8_t)PL_SRV_MAC;
            uint8_t pl_tack_srv_mac_value[6] = {0}; 
            memcpy(pl_tack_srv_mac_value, SRV_MAC, 6);
            uint8_t pl_tack_srv_mac_vlen = (uint8_t)sizeof(pl_tack_srv_mac_value);
            ot_payload* pl_tack_srv_mac_payload = ot_payload_create(pl_tack_srv_mac_msgtype, 
                                                                    &pl_tack_srv_mac_value,
                                                                    pl_tack_srv_mac_vlen);

            uint8_t pl_tack_cli_ip_msgtype = (uint8_t)PL_CLI_IP;
            uint32_t pl_tack_cli_ip_value = recv_pkt->header.cli_ip;
            uint8_t pl_tack_cli_ip_vlen = (uint8_t)sizeof(pl_tack_cli_ip_value);
            ot_payload* pl_tack_cli_ip_payload = ot_payload_create(pl_tack_cli_ip_msgtype, 
                                                                   &pl_tack_cli_ip_value,
                                                                   pl_tack_cli_ip_vlen);

            // PL_ETIME payload
            uint8_t pl_tack_exp_time_msgtype = (uint8_t)PL_ETIME;
            uint32_t pl_tack_exp_time_value = DEF_EXP_TIME;
            uint8_t pl_tack_exp_time_vlen = (uint8_t)sizeof(pl_tack_exp_time_value);
            ot_payload* pl_tack_exp_time_payload = ot_payload_create(pl_tack_exp_time_msgtype, 
                                                                     &pl_tack_exp_time_value,
                                                                     pl_tack_exp_time_vlen);

            // PL_RTIME payload
            uint8_t pl_tack_renew_time_msgtype = (uint8_t)PL_RTIME;
            uint32_t pl_tack_renew_time_value = DEF_EXP_TIME*0.75;
            uint8_t pl_tack_renew_time_vlen = (uint8_t)sizeof(pl_tack_renew_time_value);
            ot_payload* pl_tack_renew_time_payload = ot_payload_create(pl_tack_renew_time_msgtype, 
                                                                       &pl_tack_renew_time_value,
                                                                       pl_tack_renew_time_vlen);

            // Build the list on the TACK reply pkt
            tack_reply->payload = ot_payload_append(tack_reply->payload, pl_tack_state_payload);
            tack_reply->payload = ot_payload_append(tack_reply->payload, pl_tack_srv_ip_payload);
            tack_reply->payload = ot_payload_append(tack_reply->payload, pl_tack_srv_mac_payload);
            tack_reply->payload = ot_payload_append(tack_reply->payload, pl_tack_cli_ip_payload);
            tack_reply->payload = ot_payload_append(tack_reply->payload, pl_tack_exp_time_payload);
            tack_reply->payload = ot_payload_append(tack_reply->payload, pl_tack_renew_time_payload);

            // Finally serialize the TACK reply and send to client
            ssize_t bytes_serialized;
            if ((bytes_serialized = send_pkt(&conn_fd, tack_reply, rx_buffer, sizeof rx_buffer)) < 0)
            {
              fprintf(stderr, "[ot srv] error: failed to reply TACK to client\n");
              goto cleanup;
            }


            // Free the tack reply pkt
            ot_pkt_destroy(&tack_reply);

            printf("[ot srv] sent TACK reply (%zuB) to %s\n", 
                   bytes_serialized, 
                   inet_ntop(AF_INET, &address.sin_addr.s_addr, ipbuf, INET_ADDRSTRLEN));

            // Add client to server context after sending TACK


            // Convert client MAC to string (for key)
            char macstr[24] = {0}; //<< needed for converting mac to key
            bytes_to_macstr(recv_pkt->header.cli_mac, macstr);

            // Perform expiry/renew time computation
            time(&curr_time); //<< get current time
            time_t exp_time = curr_time + DEF_EXP_TIME;  
            time_t renew_time = curr_time + 0.75*DEF_EXP_TIME;
            if ( strcmp(macstr,"00:00:00:ab:ab:ff") == 0 ) 
            {
              printf("[ot srv] received debug mac\n");
              exp_time = curr_time + 20;
              renew_time = curr_time + 0.75*20;
              recv_pkt->header.exp_time = 20;
              recv_pkt->header.renew_time = 20*0.75;
            }

            // Finally build the client context object and set to srv ctable
            ot_cli_ctx cli_ctx = ot_cli_ctx_create(tack_hd, TACK, 
                                                   exp_time, 
                                                   renew_time);
            if ( strcmp(ht_set_cli_ctx(srv_ctx->ctable, macstr, cli_ctx), macstr) != 0 )  
            {
              fprintf(stderr, "[ot srv] error: failed to add client context\n");
              goto cleanup;
            }

            printf("[ot srv] successfully added client %s to srv ctable\n", macstr);

            break;
          }
        case TREN: 
          {
            // We utilize tren_pl_validate to pull the mandatory payloads from the deserialized recv pkt
            // Check for PL_CLI_MAC and PL_CLI_IP and check if they are the same from ptable
            // Returns false if TREN payload is invalid

            if (!tren_pl_validate(srv_ctx, ptable, recv_pkt)) 
            {
              fprintf(stderr, "[ot srv] inbound tren error: one or more tren payloads are missing\n");
              // send tinv due to malformed tren
              ot_pkt* tinv_reply = ot_pkt_create();
              tinv_reply_build(tinv_reply, recv_pkt->header, SRV_IP, recv_pkt->header.cli_ip);
              if (send_pkt(&conn_fd, tinv_reply, rx_buffer, sizeof rx_buffer) < 0) 
              {
                fprintf(stderr, "[ot srv] failed to send tinv to %s\n",
                        inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));
              }
              goto cleanup; 
            }

            // Handle expired clients
            char macstr[24] = {0};
            bytes_to_macstr(recv_pkt->header.cli_mac, macstr);
            if (cli_expiry_check(srv_ctx, recv_pkt->header)) 
            {
              printf("[ot srv] client %s is expired, deleting...\n", macstr);
              ht_delete(srv_ctx->ctable, macstr);

              // send tinv due to expired client
              ot_pkt* tinv_reply = ot_pkt_create();
              tinv_reply_build(tinv_reply, recv_pkt->header, SRV_IP, recv_pkt->header.cli_ip);
              if (send_pkt(&conn_fd, tinv_reply, rx_buffer, sizeof rx_buffer) < 0) 
              {
                fprintf(stderr, "[ot srv] failed to send tinv to %s\n",
                        inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));
              }

              goto cleanup;
            }

            // Check whether client is eligible for renewal (within renewal window)
            if (!tren_renewal_time_check(srv_ctx, recv_pkt->header.cli_mac, curr_time))
            {
              // send tinv due to renewal time error
              ot_pkt* tinv_reply = ot_pkt_create();
              tinv_reply_build(tinv_reply, recv_pkt->header, SRV_IP, recv_pkt->header.cli_ip);
              if (send_pkt(&conn_fd, tinv_reply, rx_buffer, sizeof rx_buffer) < 0) 
              {
                fprintf(stderr, "[ot srv] failed to send tinv to %s\n",
                        inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));
              }

              printf("[ot srv] renewal bound error: client %s, replied with TINV\n",
                     inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));

              goto cleanup; 
            } else {
              // Get reference of cli ctx but change the expiry and renewal
              // Replace cli ctx mapped by cli mac with new cli ctx

              // Convert MAC bytes to string key
              char macstr[24] = {0};
              bytes_to_macstr(recv_pkt->header.cli_mac, macstr);

              // Reference the client context 
              ot_cli_ctx* reference_cc = ht_get(srv_ctx->ctable, macstr);
              reference_cc->ctx_exp_time = curr_time + DEF_EXP_TIME;
              reference_cc->ctx_renew_time = curr_time + 0.75*DEF_EXP_TIME;

              // Replace existing entry in srv ctx with the new client context
              if (strcmp(macstr, ht_set_cli_ctx(srv_ctx->ctable, macstr, *reference_cc)) != 0)
              {
                fprintf(stderr, "[ot srv] failed to replace client context with mac %s\n", macstr);
                //send_oerr(conn_fd);
                goto cleanup;
              }

              printf("[ot srv] successfully renewed client context for %s\n", macstr);

              // Allocate memory for TPRV reply to client then build
              ot_pkt* tprv_reply = ot_pkt_create();
              tprv_reply_build(tprv_reply, recv_pkt->header, SRV_IP, 
                               recv_pkt->header.cli_ip, DEF_EXP_TIME, 0.75*DEF_EXP_TIME);

              size_t bytes_serialized;
              if ( (bytes_serialized = ot_pkt_serialize(tprv_reply, rx_buffer, sizeof rx_buffer)) < 0 ) 
              {
                fprintf(stderr, "[ot srv] error: failed to serialize tprv reply\n");
                goto cleanup;
              }

              if (send(conn_fd, rx_buffer, bytes_serialized, 0) < 0) 
              {
                fprintf(stderr, "[ot srv] failed to send tprv to %s\n",
                        inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));
                goto cleanup;
              }
            }

            break;
          }
        case CPULL: 
          {
            // validate the inbound cpull packet
            if (!cpull_pl_validate(srv_ctx, ptable, recv_pkt)) 
            {
              // if invalid, reply with cinv with uname (if it exists in payload)
              ot_pkt* cinv_reply = ot_pkt_create();
              char* uname = ht_get(ptable, "PL_UNAME");
              if (uname == NULL)
              {
                cinv_reply_build(cinv_reply, recv_pkt->header,
                                 SRV_IP, recv_pkt->header.cli_ip, "MLFM");
              } else {
                cinv_reply_build(cinv_reply, recv_pkt->header,
                                 SRV_IP, recv_pkt->header.cli_ip, uname);
              }

              if (send_pkt(&conn_fd, cinv_reply, rx_buffer, sizeof rx_buffer) < 0) 
              {
                fprintf(stderr, "[ot srv] failed to send cinv to %s\n",
                        inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));
              }

              printf("[ot srv] malformed cpull: client %s, replied with CINV\n",
                     inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));
            }

            // Handle expired clients
            char macstr[24] = {0};
            bytes_to_macstr(recv_pkt->header.cli_mac, macstr);
            if (cli_expiry_check(srv_ctx, recv_pkt->header)) 
            {
              printf("[ot srv] client %s is expired, deleting...\n", macstr);
              ht_delete(srv_ctx->ctable, macstr);

              // send tinv due to expired client
              ot_pkt* cinv_reply = ot_pkt_create();
              char* uname = ht_get(ptable, "PL_UNAME");
              cinv_reply_build(cinv_reply, recv_pkt->header, SRV_IP, recv_pkt->header.cli_ip, uname);
              if (send_pkt(&conn_fd, cinv_reply, rx_buffer, sizeof rx_buffer) < 0) 
              {
                fprintf(stderr, "[ot srv] failed to send cinv to %s\n",
                        inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));
              }

              goto cleanup;
            }

            // Begin sending a cpush pkt

            char* pl_uname = ht_get(ptable, "PL_UNAME");

            // Pull credentials
            ot_pkt* cpush_reply = ot_pkt_create();
            char* get_psk = ht_get(srv_ctx->otable, pl_uname);
            if (get_psk == NULL)
            {
              cinv_reply_build(cpush_reply, recv_pkt->header, SRV_IP, recv_pkt->header.cli_ip,
                                pl_uname);
            } else {
              cpush_reply_build(cpush_reply, recv_pkt->header, SRV_IP, recv_pkt->header.cli_ip,
                                pl_uname, get_psk);
            }

            if (send_pkt(&conn_fd, cpush_reply, rx_buffer, sizeof rx_buffer) < 0) 
            {
              fprintf(stderr, "[ot srv] failed to send cpush to %s\n",
                      inet_ntop(AF_INET, &address.sin_addr.s_addr, (char*)ipbuf, INET_ADDRSTRLEN));
            }

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
  }

server_close:
  printf("[ot srv] shutting down...\n");
  ot_srv_ctx_destroy(&srv_ctx);
  close(server_fd);
  return;
}

static void err_pl_treq_validate(const char* pl) 
{
  if (pl == NULL) return;
  fprintf(stderr, "[ot srv] treq validation error: failed to find %s\n", pl);
}

static bool pl_treq_validate(ot_srv_ctx* sc, ht* ptable, ot_pkt* recv_pkt)
{
  if (sc == NULL || ptable == NULL || recv_pkt == NULL) return false;

  uint32_t* expected_srv_ip = ht_get(ptable, "PL_SRV_IP");
  uint32_t* expected_cli_ip = ht_get(ptable, "PL_CLI_IP");
  uint32_t* expected_cli_mac = ht_get(ptable, "PL_CLI_MAC");

  if (expected_srv_ip == NULL) 
  {
    err_pl_treq_validate("PL_SRV_IP");
    return false;
  }
  if (expected_cli_ip == NULL) 
  {
    err_pl_treq_validate("PL_CLI_IP");
    return false;
  }
  if (expected_cli_mac == NULL) 
  {
    err_pl_treq_validate("PL_CLI_MAC");
    return false;
  }

  return true;
}

// Serializes and sends a pkt to an existing TCP client  
static ssize_t send_pkt(int* sockfd, ot_pkt* pkt, uint8_t* buf, size_t buflen)
{
  int retval = -1;
  ssize_t bytes_serialized;
  if ((bytes_serialized = ot_pkt_serialize(pkt, buf, buflen)) < 0)
  {
    fprintf(stderr, "[ot srv] error: failed to serialize pkt\n");
    return -1;
  } else {
    retval = send(*sockfd, buf, bytes_serialized, 0);
  }

  return retval;
}

static bool cli_expiry_check(ot_srv_ctx* sc, ot_pkt_header hd)
{
  if (sc == NULL) return false;

  char macstr[24] = {0};
  bytes_to_macstr(hd.cli_mac, macstr);

  ot_cli_ctx cc = ht_get_cli_ctx(sc->ctable, macstr);
  if (cc.state == UNKN) return true;
  
  time_t ctx_exp_time = cc.ctx_exp_time;

  time_t curr_time;
  time(&curr_time);

  if (curr_time >= ctx_exp_time) return true;

  return false;
}

// Validates a deserialized TREN pkt.
//
// Checks whether the correct payloads exist and correlate with the header
//
// Returns true if the pkt is valid, otherwise false.
static bool tren_pl_validate(ot_srv_ctx* sc, ht* ptable, ot_pkt* recv_pkt)
{
  if (sc == NULL || ptable == NULL || recv_pkt == NULL)
  {
    fprintf(stderr, "[ot srv] tren validation error: sc, ptable, or recv pkt is/are null\n");
    return false;
  }

  // Check mandatory fields in ptable
  uint32_t* pl_srv_ip = ht_get(ptable, "PL_SRV_IP");
  uint32_t* pl_cli_ip = ht_get(ptable, "PL_CLI_IP");
  uint8_t* pl_cli_mac = ht_get(ptable, "PL_CLI_MAC");

  if (pl_srv_ip == NULL)
  {
    fprintf(stderr, "[ot srv] tren validation error: pl_srv_ip not found\n");
    return false;
  }
  if (pl_cli_ip == NULL)
  {
    fprintf(stderr, "[ot srv] tren validation error: pl_cli_ip not found\n");
    return false;
  }
  if (pl_cli_mac == NULL)
  {
    fprintf(stderr, "[ot srv] tren validation error: pl_cli_mac not found\n");
    return false;
  }
  
  if (*pl_srv_ip != recv_pkt->header.srv_ip) return false;
  if (*pl_cli_ip != recv_pkt->header.cli_ip) return false;
  if (memcmp(pl_cli_mac, recv_pkt->header.cli_mac, 6) != 0) return false;

  // Lastly, check if the client mac maps to an existing client context
  char macstr[24];
  bytes_to_macstr(pl_cli_mac, macstr);
  ot_cli_ctx cc_get = ht_get_cli_ctx(sc->ctable, macstr);
  if ( cc_get.state == UNKN ) return false;

  return true;
}

static bool cpull_pl_validate(ot_srv_ctx* sc, ht* ptable, ot_pkt* recv_pkt)
{
  if (sc == NULL || ptable == NULL || recv_pkt == NULL)
  {
    fprintf(stderr, "[ot srv] tren validation error: sc, ptable, or recv pkt is/are null\n");
    return false;
  }

  // Check mandatory fields in ptable
  uint32_t* pl_srv_ip = ht_get(ptable, "PL_SRV_IP");
  uint32_t* pl_cli_ip = ht_get(ptable, "PL_CLI_IP");
  char* pl_uname = ht_get(ptable, "PL_UNAME");

  if (pl_srv_ip == NULL)
  {
    fprintf(stderr, "[ot srv] cpull validation error: pl_srv_ip not found\n");
    return false;
  }
  if (pl_cli_ip == NULL)
  {
    fprintf(stderr, "[ot srv] cpull validation error: pl_cli_ip not found\n");
    return false;
  }
  if (pl_uname == NULL)
  {
    fprintf(stderr, "[ot srv] cpull validation error: pl_uname not found\n");
    return false;
  }
  
  // Header correlation checks
  if (*pl_srv_ip != recv_pkt->header.srv_ip) return false;
  if (*pl_cli_ip != recv_pkt->header.cli_ip) return false;

  // Lastly, check if the client mac maps to an existing client context
  char macstr[24];
  bytes_to_macstr(recv_pkt->header.cli_mac, macstr);
  ot_cli_ctx cc_get = ht_get_cli_ctx(sc->ctable, macstr);
  if ( cc_get.state == UNKN ) return false;

  return true;
}

// Checks if the client sending a TREN pkt can renew. 
//
// Validates whether the client is present in the srv ctable, then checks if the current time is within
// bounds for renewal.
//
// Returns true if the client can renew, otherwise false.
static bool tren_renewal_time_check(ot_srv_ctx* sc, uint8_t* cli_mac, time_t curr_time)
{
  time(&curr_time);
  ht* srv_ctable = sc->ctable;

  char macstr[24] = {0};
  bytes_to_macstr(cli_mac, macstr);

  ot_cli_ctx cc;
  if((cc = ht_get_cli_ctx(srv_ctable, macstr)).state == UNKN) 
  {
    fprintf(stderr, "[ot srv] client %s does not have a context\n", macstr);
    return false;
  }

  /* DEPRECATED, HANDLE EXPIRY FROM RUNTIME
  // Check if client is expired (delete if it is)
  uint32_t ctx_exp_time = cc.ctx_exp_time;
  if (curr_time >= ctx_exp_time) 
  {
    ht_delete(srv_ctable, macstr);
    return false;
  }
  */

  // Return true if within renew bounds
  uint32_t ctx_renew_time = cc.ctx_renew_time;
  if (curr_time >= ctx_renew_time) return true;

  return false;
}

// Builds an allocated TINV reply pkt
//
// Sets the header (tinv_hd) and the appropriate payloads (PL_STATE, PL_SRV_IP, PL_CLI_IP)
// for a valid TINV reply to a client.
static void tinv_reply_build(ot_pkt* tinv_reply, ot_pkt_header tinv_hd, 
                             uint32_t srv_ip, uint32_t cli_ip)
{
  if (tinv_reply == NULL) fprintf(stderr, "[ot srv] tinv reply build error: tinv pkt not allocated\n");
  
  tinv_reply->header = tinv_hd;
  
  uint8_t pl_state_msgtype = PL_STATE;
  uint8_t pl_state_value = TINV;
  uint8_t pl_state_vlen = sizeof(pl_state_value);
  ot_payload* pl_state_payload = ot_payload_create(pl_state_msgtype, &pl_state_value, pl_state_vlen);

  uint8_t pl_srv_ip_msgtype = PL_SRV_IP;
  uint32_t pl_srv_ip_value = srv_ip;
  uint8_t pl_srv_ip_vlen = sizeof(pl_srv_ip_value);
  ot_payload* pl_srv_ip_payload = ot_payload_create(pl_srv_ip_msgtype, &pl_srv_ip_value, pl_srv_ip_vlen);

  uint8_t pl_cli_ip_msgtype = PL_CLI_IP;
  uint32_t pl_cli_ip_value = cli_ip;
  uint8_t pl_cli_ip_vlen = sizeof(pl_cli_ip_value);
  ot_payload* pl_cli_ip_payload = ot_payload_create(pl_cli_ip_msgtype, 
                                                    &pl_cli_ip_value, 
                                                    pl_cli_ip_vlen);

  tinv_reply->payload = ot_payload_append(tinv_reply->payload, pl_state_payload);
  tinv_reply->payload = ot_payload_append(tinv_reply->payload, pl_srv_ip_payload);
  tinv_reply->payload = ot_payload_append(tinv_reply->payload, pl_cli_ip_payload);
}

static void cinv_reply_build(ot_pkt* cinv_reply, ot_pkt_header cinv_hd, uint32_t srv_ip,
                              uint32_t cli_ip, const char* uname)
{
  if (cinv_reply == NULL) fprintf(stderr, "[ot srv] cinv reply build error: cpush pkt not allocated\n");
  
  cinv_reply->header = cinv_hd;
  
  uint8_t pl_state_msgtype = PL_STATE;
  uint8_t pl_state_value = CINV;
  uint8_t pl_state_vlen = sizeof(pl_state_value);
  ot_payload* pl_state_payload = ot_payload_create(pl_state_msgtype, &pl_state_value, pl_state_vlen);

  uint8_t pl_srv_ip_msgtype = PL_SRV_IP;
  uint32_t pl_srv_ip_value = srv_ip;
  uint8_t pl_srv_ip_vlen = sizeof(pl_srv_ip_value);
  ot_payload* pl_srv_ip_payload = ot_payload_create(pl_srv_ip_msgtype, &pl_srv_ip_value, 
                                                    pl_srv_ip_vlen);

  uint8_t pl_cli_ip_msgtype = PL_CLI_IP;
  uint32_t pl_cli_ip_value = cli_ip;
  uint8_t pl_cli_ip_vlen = sizeof(pl_cli_ip_value);
  ot_payload* pl_cli_ip_payload = ot_payload_create(pl_cli_ip_msgtype, &pl_cli_ip_value, 
                                                    pl_cli_ip_vlen);

  uint8_t pl_uname_msgtype = PL_UNAME;
  char* pl_uname_value = (char*)uname;
  uint8_t pl_uname_vlen = strlen(pl_uname_value)+1;
  ot_payload* pl_uname_payload = ot_payload_create(pl_uname_msgtype, pl_uname_value, 
                                                   pl_uname_vlen);

  cinv_reply->payload = ot_payload_append(cinv_reply->payload, pl_state_payload);
  cinv_reply->payload = ot_payload_append(cinv_reply->payload, pl_srv_ip_payload);
  cinv_reply->payload = ot_payload_append(cinv_reply->payload, pl_cli_ip_payload);
  cinv_reply->payload = ot_payload_append(cinv_reply->payload, pl_uname_payload);
}

static void cpush_reply_build(ot_pkt* cpush_reply, ot_pkt_header cpush_hd, uint32_t srv_ip,
                              uint32_t cli_ip, const char* uname, const char* psk)
{
  if (cpush_reply == NULL) fprintf(stderr, "[ot srv] cpush reply build error: cpush pkt not allocated\n");
  
  cpush_reply->header = cpush_hd;
  
  uint8_t pl_state_msgtype = PL_STATE;
  uint8_t pl_state_value = CPUSH;
  uint8_t pl_state_vlen = sizeof(pl_state_value);
  ot_payload* pl_state_payload = ot_payload_create(pl_state_msgtype, &pl_state_value, pl_state_vlen);

  uint8_t pl_srv_ip_msgtype = PL_SRV_IP;
  uint32_t pl_srv_ip_value = srv_ip;
  uint8_t pl_srv_ip_vlen = sizeof(pl_srv_ip_value);
  ot_payload* pl_srv_ip_payload = ot_payload_create(pl_srv_ip_msgtype, &pl_srv_ip_value, 
                                                    pl_srv_ip_vlen);

  uint8_t pl_cli_ip_msgtype = PL_CLI_IP;
  uint32_t pl_cli_ip_value = cli_ip;
  uint8_t pl_cli_ip_vlen = sizeof(pl_cli_ip_value);
  ot_payload* pl_cli_ip_payload = ot_payload_create(pl_cli_ip_msgtype, &pl_cli_ip_value, 
                                                    pl_cli_ip_vlen);

  uint8_t pl_uname_msgtype = PL_UNAME;
  char* pl_uname_value = (char*)uname;
  uint8_t pl_uname_vlen = (uint8_t)strlen(pl_uname_value)+1;
  ot_payload* pl_uname_payload = ot_payload_create(pl_uname_msgtype, pl_uname_value, 
                                                   pl_uname_vlen);

  uint8_t pl_psk_msgtype = PL_PSK;
  char* pl_psk_value = (char*)psk;
  uint8_t pl_psk_vlen = (uint8_t)strlen(pl_psk_value)+1;
  ot_payload* pl_psk_payload = ot_payload_create(pl_psk_msgtype, pl_psk_value, 
                                                   pl_psk_vlen);

  cpush_reply->payload = ot_payload_append(cpush_reply->payload, pl_state_payload);
  cpush_reply->payload = ot_payload_append(cpush_reply->payload, pl_srv_ip_payload);
  cpush_reply->payload = ot_payload_append(cpush_reply->payload, pl_cli_ip_payload);
  cpush_reply->payload = ot_payload_append(cpush_reply->payload, pl_uname_payload);
  cpush_reply->payload = ot_payload_append(cpush_reply->payload, pl_psk_payload);
}

// Builds an allocated TPRV reply pkt 
// 
// Sets the header (tprv_hd) and the appropriate payloads (PL_STATE, PL_SRV_IP, PL_CLI_IP, 
// PL_ETIME, PL_RTIME) for a valid TPRV reply to a client.
static void tprv_reply_build(ot_pkt* tprv_reply, ot_pkt_header tprv_hd, uint32_t srv_ip, 
                             uint32_t cli_ip, uint32_t exp_time, uint32_t renew_time)
{
  if (tprv_reply == NULL) fprintf(stderr, "[ot srv] tprv reply build error: tprv pkt not allocated\n");
  
  tprv_reply->header = tprv_hd;
  
  uint8_t pl_state_msgtype = PL_STATE;
  uint8_t pl_state_value = TPRV;
  uint8_t pl_state_vlen = sizeof(pl_state_value);
  ot_payload* pl_state_payload = ot_payload_create(pl_state_msgtype, &pl_state_value, pl_state_vlen);

  uint8_t pl_srv_ip_msgtype = PL_SRV_IP;
  uint32_t pl_srv_ip_value = srv_ip;
  uint8_t pl_srv_ip_vlen = sizeof(pl_srv_ip_value);
  ot_payload* pl_srv_ip_payload = ot_payload_create(pl_srv_ip_msgtype, &pl_srv_ip_value, pl_srv_ip_vlen);

  uint8_t pl_cli_ip_msgtype = PL_CLI_IP;
  uint32_t pl_cli_ip_value = cli_ip;
  uint8_t pl_cli_ip_vlen = sizeof(pl_cli_ip_value);
  ot_payload* pl_cli_ip_payload = ot_payload_create(pl_cli_ip_msgtype, &pl_cli_ip_value, pl_cli_ip_vlen);

  uint8_t pl_exp_time_msgtype = PL_ETIME;
  uint32_t pl_exp_time_value = exp_time;
  uint8_t pl_exp_time_vlen = sizeof(pl_exp_time_value);
  ot_payload* pl_exp_time_payload = ot_payload_create(pl_exp_time_msgtype, &pl_exp_time_value, 
                                                      pl_exp_time_vlen);

  uint8_t pl_renew_time_msgtype = PL_RTIME;
  uint32_t pl_renew_time_value = renew_time;
  uint8_t pl_renew_time_vlen = sizeof(pl_renew_time_value);
  ot_payload* pl_renew_time_payload = ot_payload_create(pl_renew_time_msgtype, &pl_renew_time_value, 
                                                      pl_renew_time_vlen);

  tprv_reply->payload = ot_payload_append(tprv_reply->payload, pl_state_payload);
  tprv_reply->payload = ot_payload_append(tprv_reply->payload, pl_srv_ip_payload);
  tprv_reply->payload = ot_payload_append(tprv_reply->payload, pl_cli_ip_payload);
  tprv_reply->payload = ot_payload_append(tprv_reply->payload, pl_exp_time_payload);
  tprv_reply->payload = ot_payload_append(tprv_reply->payload, pl_renew_time_payload);
}
