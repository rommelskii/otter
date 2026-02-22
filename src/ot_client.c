#include "ot_context.h" 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <time.h>

#include "ot_packet.h"
#include "ot_server.h" //<< for def port

////////////////////////////////////////////////////////////////////////////////
// PRIVATE FUNCTIONS FOR PACKET BUILDING
////////////////////////////////////////////////////////////////////////////////
static int treq_send(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, 
                     uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

static int tren_send(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, 
                     uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

static int cpull_send(ot_pkt** reply_pkt, const char* uname, const int PORT, 
                      uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

////////////////////////////////////////////////////////////////////////////////
// PUBLIC API
////////////////////////////////////////////////////////////////////////////////
void ot_cli_auth(ot_cli_ctx* ctx)
{
  ot_pkt* tack_pkt = ot_pkt_create();
  int res = treq_send(&tack_pkt, 
                      DEF_PORT, 
                      ctx->header.srv_ip,
                      ctx->header.cli_ip,
                      ctx->header.srv_mac,
                      ctx->header.cli_mac
                      );
  if (res < 0 || tack_pkt == NULL)
  {
    fprintf(stderr, "failed to send treq to server\n");
    ot_pkt_destroy(&tack_pkt);
    return;
  }

  // Build parse table
  ht* ptable = ht_create(8);
  pl_parse_table_build(&ptable, tack_pkt->payload);
  
  // Header checks
  if (tack_pkt->header.srv_ip != ctx->header.srv_ip)
  {
    fprintf(stderr, "ot_cli_auth error: tack did not come from intended srv ip\n");
    goto cleanup;
  }
  if (tack_pkt->header.cli_ip != ctx->header.cli_ip)
  {
    fprintf(stderr, "ot_cli_auth error: inbound tack was not for this client ip\n");
    goto cleanup;
  }
  if (memcmp(tack_pkt->header.cli_mac, ctx->header.cli_mac, 6) != 0)
  {
    fprintf(stderr, "ot_cli_auth error: inbound tack was not for this client mac\n");
    goto cleanup;
  }


  // Get mandatory TACK entries
  ot_cli_state_t* pl_state = ht_get(ptable, "PL_STATE");
  uint32_t* pl_srv_ip = ht_get(ptable, "PL_SRV_IP");
  uint32_t* pl_cli_ip = ht_get(ptable, "PL_CLI_IP");
  uint32_t* pl_etime = ht_get(ptable, "PL_ETIME");
  uint32_t* pl_rtime = ht_get(ptable, "PL_RTIME");
  uint8_t* pl_srv_mac = ht_get(ptable, "PL_SRV_MAC");

  // Nullity checks
  if (pl_state == NULL) 
  {
    fprintf(stderr, "ot_cli_auth error: no state payload\n");
    goto cleanup;
  }
  if (pl_srv_ip == NULL) 
  {
    fprintf(stderr, "ot_cli_auth error: no srv ip payload\n");
    goto cleanup;
  }
  if (pl_cli_ip == NULL) 
  {
    fprintf(stderr, "ot_cli_auth error: no cli ip payload\n");
    goto cleanup;
  }
  if (pl_etime == NULL) 
  {
    fprintf(stderr, "ot_cli_auth error: no etime payload\n");
    goto cleanup;
  }
  if (pl_rtime == NULL) 
  {
    fprintf(stderr, "ot_cli_auth error: no rtime payload\n");
    goto cleanup;
  }
  if (pl_srv_mac == NULL) 
  {
    fprintf(stderr, "ot_cli_auth error: no srv_mac payload\n");
    goto cleanup;
  }

  // Check if reply pkt is TACK
  if (*pl_state != TACK) 
  {
    fprintf(stderr, "ot_cli_auth error: reply pkt is not tack\n");
    goto cleanup;
  }

  // Header comparison
  if (*pl_srv_ip != tack_pkt->header.srv_ip) 
  {
    fprintf(stderr, "ot_cli_auth error: srv ip payload mismatch with header\n");
    goto cleanup;
  }
  if (*pl_cli_ip != tack_pkt->header.cli_ip)
  {
    fprintf(stderr, "ot_cli_auth error: cli ip payload mismatch with header\n");
    goto cleanup;
  }
  if (memcmp(pl_srv_mac, tack_pkt->header.srv_mac, 6) != 0) 
  {
    fprintf(stderr, "ot_cli_auth error: srv mac payload mismatch with header\n");
    goto cleanup;
  }
  if (*pl_etime == 0)
  {
    fprintf(stderr, "ot_cli_auth error: improper exp time (<=0)\n");
    goto cleanup;
  }
  if (*pl_rtime == 0)
  {
    fprintf(stderr, "ot_cli_auth error: improper renew time (<=0)\n");
    goto cleanup;
  }

  // Packet is valid at this point

  // Get current time
  time_t now;
  time(&now); 

  // Update client context header info
  ctx->header.exp_time = *pl_etime;
  ctx->header.renew_time = *pl_rtime;

  // Update timestamps for expiry and renewal
  ctx->ctx_exp_time = now + *pl_etime;
  ctx->ctx_renew_time = now + *pl_rtime;

  // Replace server mac 
  memcpy(ctx->header.srv_mac, pl_srv_mac, 6);

cleanup:
  ot_pkt_destroy(&tack_pkt);
  ht_destroy(ptable);
  ptable = NULL;
  return;
}

void ot_cli_renew(ot_cli_ctx* ctx)
{
  ot_pkt* tprv_pkt = ot_pkt_create();
  int res = tren_send(&tprv_pkt, 
                      DEF_PORT, 
                      ctx->header.srv_ip,
                      ctx->header.cli_ip,
                      ctx->header.srv_mac,
                      ctx->header.cli_mac
                      );
  if (res < 0 || tprv_pkt == NULL)
  {
    fprintf(stderr, "failed to send treq to server\n");
    ot_pkt_destroy(&tprv_pkt);
    return;
  }

  // Build parse table
  ht* ptable = ht_create(8);
  pl_parse_table_build(&ptable, tprv_pkt->payload);
  
  // Header checks
  if (tprv_pkt->header.srv_ip != ctx->header.srv_ip)
  {
    fprintf(stderr, "ot_cli_renew error: tren did not come from intended srv ip\n");
    goto cleanup;
  }
  if (tprv_pkt->header.cli_ip != ctx->header.cli_ip)
  {
    fprintf(stderr, "ot_cli_renew error: inbound tprv was not for this client ip\n");
    goto cleanup;
  }
  if (memcmp(tprv_pkt->header.cli_mac, ctx->header.cli_mac, 6) != 0)
  {
    fprintf(stderr, "ot_cli_renew error: inbound tprv was not for this client mac\n");
    goto cleanup;
  }


  // Get mandatory TACK entries
  ot_cli_state_t* pl_state = ht_get(ptable, "PL_STATE");
  uint32_t* pl_srv_ip = ht_get(ptable, "PL_SRV_IP");
  uint32_t* pl_cli_ip = ht_get(ptable, "PL_CLI_IP");
  uint32_t* pl_etime = ht_get(ptable, "PL_ETIME");
  uint32_t* pl_rtime = ht_get(ptable, "PL_RTIME");

  // Nullity checks
  if (pl_state == NULL) 
  {
    fprintf(stderr, "ot_cli_renew error: no state payload\n");
    goto cleanup;
  }
  if (pl_srv_ip == NULL) 
  {
    fprintf(stderr, "ot_cli_renew error: no srv ip payload\n");
    goto cleanup;
  }
  if (pl_cli_ip == NULL) 
  {
    fprintf(stderr, "ot_cli_renew error: no cli ip payload\n");
    goto cleanup;
  }
  if (pl_etime == NULL) 
  {
    fprintf(stderr, "ot_cli_renew error: no etime payload\n");
    goto cleanup;
  }
  if (pl_rtime == NULL) 
  {
    fprintf(stderr, "ot_cli_renew error: no rtime payload\n");
    goto cleanup;
  }


  // Check if reply is TPRV
  if (*pl_state != TPRV) 
  {
    fprintf(stderr, "ot_cli_renew error: reply pkt is not tprv\n");
    goto cleanup;
  }

  // Header comparison
  if (*pl_srv_ip != tprv_pkt->header.srv_ip) 
  {
    fprintf(stderr, "ot_cli_renew error: srv ip payload mismatch with header\n");
    goto cleanup;
  }
  if (*pl_cli_ip != tprv_pkt->header.cli_ip)
  {
    fprintf(stderr, "ot_cli_renew error: cli ip payload mismatch with header\n");
    goto cleanup;
  }
  if (*pl_etime == tprv_pkt->header.exp_time)
  {
    fprintf(stderr, "ot_cli_renew error: exp time payload mismatch with header\n");
    goto cleanup;
  }
  if (*pl_rtime == tprv_pkt->header.renew_time)
  {
    fprintf(stderr, "ot_cli_renew error: renew time payload mismatch with header\n");
    goto cleanup;
  }
  if (*pl_etime == 0)
  {
    fprintf(stderr, "ot_cli_renew error: improper exp time (<=0)\n");
    goto cleanup;
  }
  if (*pl_rtime == 0)
  {
    fprintf(stderr, "ot_cli_renew error: improper renew time (<=0)\n");
    goto cleanup;
  }

  // TPRV is valid beyond this point

  // Get current time
  time_t now;
  time(&now); 

  // Update client context header info
  ctx->header.exp_time = *pl_etime;
  ctx->header.renew_time = *pl_rtime;

  // Update timestamps for expiry and renewal
  ctx->ctx_exp_time = now + *pl_etime;
  ctx->ctx_renew_time = now + *pl_rtime;

cleanup:
  ot_pkt_destroy(&tprv_pkt);
  ht_destroy(ptable);
  ptable = NULL;
  return;
}

void ot_cli_pull(ot_cli_ctx ctx, const char* uname, char** dest_psk)
{
  ot_pkt* cpush_pkt = ot_pkt_create();
  int res = cpull_send(&cpush_pkt, 
                       uname,
                       DEF_PORT, 
                       ctx.header.srv_ip,
                       ctx.header.cli_ip,
                       ctx.header.srv_mac,
                       ctx.header.cli_mac);
  if (res < 0 || cpush_pkt == NULL)
  {
    fprintf(stderr, "failed to send treq to server\n");
    ot_pkt_destroy(&cpush_pkt);
    return;
  }

  // Build parse table
  ht* ptable = ht_create(8);
  pl_parse_table_build(&ptable, cpush_pkt->payload);
  
  // Header checks
  if (cpush_pkt->header.srv_ip != ctx.header.srv_ip)
  {
    fprintf(stderr, "ot_cli_cpull error: cpush did not come from intended srv ip\n");
    goto cleanup;
  }
  if (cpush_pkt->header.cli_ip != ctx.header.cli_ip)
  {
    fprintf(stderr, "ot_cli_cpull error: inbound cpush was not for this client ip\n");
    goto cleanup;
  }
  if (memcmp(cpush_pkt->header.cli_mac, ctx.header.cli_mac, 6) != 0)
  {
    fprintf(stderr, "ot_cli_cpull error: inbound cpush was not for this client mac\n");
    goto cleanup;
  }


  // Get mandatory CPUSH entries
  ot_cli_state_t* pl_state = ht_get(ptable, "PL_STATE");
  uint32_t* pl_srv_ip = ht_get(ptable, "PL_SRV_IP");
  uint32_t* pl_cli_ip = ht_get(ptable, "PL_CLI_IP");
  char* pl_uname = ht_get(ptable, "PL_UNAME");
  char* pl_psk = ht_get(ptable, "PL_PSK");

  // Nullity checks
  if (pl_state == NULL) 
  {
    fprintf(stderr, "ot_cli_auth error: no pl_state payload\n");
    goto cleanup;
  }
  if (pl_srv_ip == NULL) 
  {
    fprintf(stderr, "ot_cli_auth error: no srv ip payload\n");
    goto cleanup;
  }
  if (pl_cli_ip == NULL) 
  {
    fprintf(stderr, "ot_cli_auth error: no cli ip payload\n");
    goto cleanup;
  }
  if (pl_uname == NULL) 
  {
    fprintf(stderr, "ot_cli_auth error: no uname payload\n");
    goto cleanup;
  }

  // Check if reply pkt is CPUSH
  if (*pl_state != CPUSH) 
  {
    fprintf(stderr, "ot_cli_cpull error: reply pkt is not cpush\n");
    goto cleanup;
  } 
  if (*pl_state == CINV) // User does not exist in database (dest_psk will be null)
  {
    goto cleanup;
  }

  // Header comparison / credential sanity checks
  if (*pl_srv_ip != cpush_pkt->header.srv_ip) 
  {
    fprintf(stderr, "ot_cli_cpull error: srv ip payload mismatch with header\n");
    goto cleanup;
  }
  if (*pl_cli_ip != cpush_pkt->header.cli_ip)
  {
    fprintf(stderr, "ot_cli_cpull error: cli ip payload mismatch with header\n");
    goto cleanup;
  }
  if (strlen(pl_uname) == 0) 
  {
    fprintf(stderr, "ot_cli_cpull error: uname payload is empty\n");
    goto cleanup;
  }
  if (strlen(pl_psk) == 0) 
  {
    fprintf(stderr, "ot_cli_cpull error: psk payload is empty\n");
    goto cleanup;
  }

  // Check if the payload is actually for the intended uname
  if (strcmp(pl_uname, uname) != 0) 
  {
    fprintf(stderr, "ot_cli_cpull error: payload uname does not match intended uname\n");
    goto cleanup;
  }

  // CPUSH is valid beyond this point
  *dest_psk = strdup(pl_psk);

cleanup:
  ot_pkt_destroy(&cpush_pkt);
  ht_destroy(ptable);
  ptable = NULL;
  return;

  return;
}

static int treq_send(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, 
                          uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac)
{
  // Build TREQ header 
  ot_pkt_header treq_hd = ot_pkt_header_create(SRV_IP, CLI_IP,  srv_mac, cli_mac, 0, 0);

  // Build TREQ pkt
  ot_pkt* treq_pkt = ot_pkt_create();
  treq_pkt->header = treq_hd;

  // Specify TREQ state payload
  uint8_t pl_state_type = (uint8_t)PL_STATE; //<< state to indicate that we are sending a TREQ packet
  uint8_t pl_state_value = (uint8_t)TREQ; 
  uint8_t pl_state_vlen = (uint8_t)sizeof(pl_state_value);

  ot_payload* pl_state_payload = ot_payload_create(pl_state_type, &pl_state_value, pl_state_vlen);

  // Specify TREQ srv_ip payload 
  uint8_t pl_srv_ip_type = (uint8_t)PL_SRV_IP;
  uint32_t pl_srv_ip_value = SRV_IP;
  uint8_t pl_srv_ip_vlen = (uint8_t)sizeof(pl_srv_ip_value);

  ot_payload* pl_srv_ip_payload = ot_payload_create(pl_srv_ip_type, &pl_srv_ip_value, pl_srv_ip_vlen);

  // Specify TREQ cli_ip payload 
  uint8_t pl_cli_ip_type = (uint8_t)PL_CLI_IP;
  uint32_t pl_cli_ip_value = CLI_IP;
  uint8_t pl_cli_ip_vlen = (uint8_t)sizeof(pl_cli_ip_value);

  ot_payload* pl_cli_ip_payload = ot_payload_create(pl_cli_ip_type, &pl_cli_ip_value, pl_cli_ip_vlen);

  // Specify TREQ cli_mac payload

  uint8_t pl_cli_mac_type = (uint8_t)PL_CLI_MAC;
  uint8_t pl_cli_mac_value[6] = {0}; 

  memcpy(pl_cli_mac_value, cli_mac, 6);

  uint8_t pl_cli_mac_vlen = (uint8_t)sizeof(cli_mac);

  ot_payload* pl_cli_mac_payload = ot_payload_create(pl_cli_mac_type, &pl_cli_mac_value, pl_cli_mac_vlen);

  // Create payload list in TREQ pkt
  treq_pkt->payload = ot_payload_append(treq_pkt->payload, pl_state_payload);
  treq_pkt->payload = ot_payload_append(treq_pkt->payload, pl_srv_ip_payload);
  treq_pkt->payload = ot_payload_append(treq_pkt->payload, pl_cli_ip_payload);
  treq_pkt->payload = ot_payload_append(treq_pkt->payload, pl_cli_mac_payload);

  // Serialize TREQ pkt
  ssize_t bytes_serialized = 0;
  uint8_t buf[2048] = {0xff}; //<< pre-set with 0xFF terminator
  if ( (bytes_serialized = ot_pkt_serialize(treq_pkt, buf, sizeof buf)) < 0) 
  {
    printf("serialization failed\n");
    return -1;
  } 
  
  // Begin TCP send
  int sockfd = 0;
  struct sockaddr_in serv_addr;
  
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
  {
    perror("socket failed");
    return -1;
  }
  
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);
  serv_addr.sin_addr.s_addr = SRV_IP;

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("FAILED\n");
    return -1;
  } 

  // Send the serialized TREQ to server
  send(sockfd, buf, bytes_serialized, 0);

  ssize_t bytes_received;
  // Wait for reply
  if ((bytes_received = read(sockfd, buf, sizeof buf)) < 0) 
  {
    perror("read failed");
    return -1;
  } 

  memset(&buf[bytes_received], 0xff, sizeof(buf) - bytes_received);

  // Finally, deserialize reply
  if (ot_pkt_deserialize(*reply_pkt, buf, sizeof buf) < 0) 
  {
    printf("deserialization failed\n");
    printf("FAILED\n");
    return -1;
  } 

  // Free the pkt we used for sending the TREQ
  ot_pkt_destroy(&treq_pkt);

  close(sockfd);

  return 1;
}


static int tren_send(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, 
                          uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac)
{
  // Build TREN header 
  ot_pkt_header tren_hd = ot_pkt_header_create(SRV_IP, CLI_IP,  srv_mac, cli_mac, 0, 0);

  // Build TREN pkt
  ot_pkt* tren_pkt = ot_pkt_create();
  tren_pkt->header = tren_hd;

  // Specify TREN state payload
  ot_pkt_msgtype_t pl_state_type = PL_STATE; //<< state to indicate that we are sending a TREN packet
  uint8_t pl_state_value = (uint8_t)TREN; 
  uint8_t pl_state_vlen = (uint8_t)sizeof(pl_state_value);

  ot_payload* pl_state_payload = ot_payload_create(pl_state_type, &pl_state_value, pl_state_vlen);

  // Specify TREN srv_ip payload 
  uint8_t pl_srv_ip_type = PL_SRV_IP;
  uint32_t pl_srv_ip_value = SRV_IP;
  uint8_t pl_srv_ip_vlen = (uint8_t)sizeof(pl_srv_ip_value);
  ot_payload* pl_srv_ip_payload = ot_payload_create(pl_srv_ip_type, &pl_srv_ip_value, pl_srv_ip_vlen);

  // Specify TREN cli_ip payload 
  uint8_t pl_cli_ip_type = PL_CLI_IP;
  uint32_t pl_cli_ip_value = CLI_IP;
  uint8_t pl_cli_ip_vlen = (uint8_t)sizeof(pl_cli_ip_value);
  ot_payload* pl_cli_ip_payload = ot_payload_create(pl_cli_ip_type, &pl_cli_ip_value, pl_cli_ip_vlen);

  // Specify TREN cli_mac payload 
  uint8_t pl_cli_mac_type = PL_CLI_MAC;

  uint8_t pl_cli_mac_value[6] = {0};
  memcpy(pl_cli_mac_value, cli_mac, 6);

  uint8_t pl_cli_mac_vlen = (uint8_t)sizeof(pl_cli_mac_value);
  ot_payload* pl_cli_mac_payload = ot_payload_create(pl_cli_mac_type, &pl_cli_mac_value, pl_cli_mac_vlen);


  // Create payload list in TREN pkt
  tren_pkt->payload = ot_payload_append(tren_pkt->payload, pl_state_payload);
  tren_pkt->payload = ot_payload_append(tren_pkt->payload, pl_srv_ip_payload);
  tren_pkt->payload = ot_payload_append(tren_pkt->payload, pl_cli_ip_payload);
  tren_pkt->payload = ot_payload_append(tren_pkt->payload, pl_cli_mac_payload);

  // Serialize TREN pkt
  ssize_t bytes_serialized = 0;
  uint8_t buf[2048] = {0xff}; //<< pre-set with 0xFF terminator
  if ( (bytes_serialized = ot_pkt_serialize(tren_pkt, buf, sizeof buf)) < 0) 
  {
    return -1;
  } 
  
  // Begin TCP send
  int sockfd = 0;
  struct sockaddr_in serv_addr;
  
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
  {
    perror("socket failed");
    return -1;
  }
  
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);
  serv_addr.sin_addr.s_addr = SRV_IP;

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("FAILED\n");
    return -1;
  } 

  // Send the serialized TREN to server
  send(sockfd, buf, bytes_serialized, 0);
  // Wait for reply
  if (read(sockfd, buf, sizeof buf) < 0) 
  {
    perror("read failed");
    return -1;
  } 

  // Finally, deserialize reply
  if (ot_pkt_deserialize(*reply_pkt, buf, sizeof buf) < 0) 
  {
    return -1;
  } 

  // Free the pkt we used for sending the TREN pkt
  ot_pkt_destroy(&tren_pkt);

  close(sockfd);

  return 0;
}

static int cpull_send(ot_pkt** reply_pkt, const char* uname, const int PORT, 
                           uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac)
{
  // Build CPULL header 
  ot_pkt_header cpull_hd = ot_pkt_header_create(SRV_IP, CLI_IP,  srv_mac, 
                                                cli_mac, DEF_EXP_TIME, DEF_EXP_TIME*0.75);

  // Build CPULL pkt
  ot_pkt* cpull_pkt = ot_pkt_create();
  cpull_pkt->header = cpull_hd;

  // Specify CPULL state payload
  uint8_t pl_state_type = PL_STATE; //<< state to indicate that we are sending a TREN packet
  uint8_t pl_state_value = (uint8_t)CPULL; 
  uint8_t pl_state_vlen = (uint8_t)sizeof(pl_state_value);

  ot_payload* pl_state_payload = ot_payload_create(pl_state_type, &pl_state_value, pl_state_vlen);


  // Specify CPULL srv_ip payload 
  uint8_t pl_srv_ip_type = PL_SRV_IP;
  uint32_t pl_srv_ip_value = SRV_IP;
  uint8_t pl_srv_ip_vlen = (uint8_t)sizeof(pl_srv_ip_value);

  ot_payload* pl_srv_ip_payload = ot_payload_create(pl_srv_ip_type, &pl_srv_ip_value, pl_srv_ip_vlen);


  // Specify TREN cli_ip payload 
  uint8_t pl_cli_ip_type = PL_CLI_IP;
  uint32_t pl_cli_ip_value = CLI_IP;
  uint8_t pl_cli_ip_vlen = (uint8_t)sizeof(pl_cli_ip_value);

  ot_payload* pl_cli_ip_payload = ot_payload_create(pl_cli_ip_type, &pl_cli_ip_value, pl_cli_ip_vlen);

  
  // Specify CPULL uname payload 
  uint8_t pl_uname_type = PL_UNAME;
  char* pl_uname_value = (char*)uname;
  uint8_t pl_uname_vlen = (uint8_t)strlen(pl_uname_value)+1;

  ot_payload* pl_uname_payload = ot_payload_create(pl_uname_type, pl_uname_value, pl_uname_vlen);
  
  // Create payload list in CPULL pkt
  cpull_pkt->payload = ot_payload_append(cpull_pkt->payload, pl_state_payload);
  cpull_pkt->payload = ot_payload_append(cpull_pkt->payload, pl_srv_ip_payload);
  cpull_pkt->payload = ot_payload_append(cpull_pkt->payload, pl_cli_ip_payload);
  cpull_pkt->payload = ot_payload_append(cpull_pkt->payload, pl_uname_payload);

  // Serialize CPULL pkt
  ssize_t bytes_serialized = 0;
  uint8_t buf[2048] = {0xff}; //<< pre-set with 0xFF terminator
  if ( (bytes_serialized = ot_pkt_serialize(cpull_pkt, buf, sizeof buf)) < 0) 
  {
    return -1;
  } 
  
  // Begin TCP send
  int sockfd = 0;
  struct sockaddr_in serv_addr;
  
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
  {
    perror("socket failed");
    return -1;
  }
  
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);
  serv_addr.sin_addr.s_addr = SRV_IP;

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    return -1;
  } 

  // Send the serialized CPULL to server
  send(sockfd, buf, bytes_serialized, 0);
  // Wait for reply
  if (read(sockfd, buf, sizeof buf) < 0) 
  {
    perror("read failed");
    return -1;
  } 

  // Finally, deserialize reply
  if (ot_pkt_deserialize(*reply_pkt, buf, sizeof buf) < 0) 
  {
    return -1;
  } 

  // Free the pkt we used for sending the CPULL pkt
  ot_pkt_destroy(&cpull_pkt);

  close(sockfd);

  return 0;
}
