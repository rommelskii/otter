/* Created by Rommel John H. Ronduen (rommel.ronduen2244@gmail.com)
*
* file: test_srv_runtime.c
*
* Contains test harnesses for testing the server runtime. The tests here are written similar to the perspective
* of the clientside. 
*/

#include "ot_server.h"
#include "testing_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

int tests_failed = 0;

/**
* PROTOTYPE FUNCTIONS
*/
static void pl_parse_table_build(ht** pt, ot_payload* pl_head)
{
  ot_payload* oti = reply_head;
  for(; oti!=NULL; oti=oti->next) 
  {
    ot_pkt_msgtype_t msgtype = (ot_pkt_msgtype_t)oti->type; //<< this will be converted to a string
    char msgtype_str[16];
    msgtype_to_str(msgtype, msgtype_str);

    void* value = oti->value;
    uint8_t vlen = oti->vlen;

    ht_set(pt, msgtype_str, (size_t)vlen);
  }
}
  
// test_treq_send(&reply_pkt, const int PORT, SRV_IP, CLI_IP);
static int test_treq_send(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP) 
{
  // Build TREQ header 
  uint8_t srv_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  uint8_t cli_mac[6] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa};
  ot_pkt_header treq_hd = ot_pkt_header_create(SRV_IP, CLI_IP,  srv_mac, cli_mac, 0, 0);

  // Build TREQ pkt
  ot_pkt* treq_pkt = ot_pkt_create();
  treq_pk->header = treq_hd;

  // Specify TREQ state payload
  ot_pkt_msgtype_t pl_state_type = PL_STATE; //<< state to indicate that we are sending a TREQ packet
  uint8_t pl_state_value = (uint8_t)TREQ; 
  uint8_t pl_state_vlen = (uint8_t)sizeof(pl_state_value);

  ot_payload* pl_state_payload = ot_payload_create(pl_state_type, pl_state_value, pl_state_vlen);

  // Specify TREQ cli_ip payload 
  ot_payload_type_t pl_cli_ip_type = PL_CLI_IP;
  uint32_t pl_cli_ip_value = CLI_IP;
  uint8_t pl_cli_ip_vlen = (uint8_t)sizeof(pl_cli_ip_value);

  ot_payload* pl_cli_ip_payload = ot_payload_create(pl_cli_ip_type, pl_cli_ip_value, pl_cli_ip_vlen);

  // Specify TREQ cli_mac payload
  // pl_create(PL_CLI_MAC, MAC*, sizeof(MAC))

  ot_pkt_msgtype_t pl_cli_mac_type = PL_CLI_MAC;
  uint8_t pl_cli_mac_value[6] = {0}; 

  memcpy(pl_cli_mac_value, cli_mac, sizeof(cli_mac));

  uint8_t pl_cli_mac_vlen = (uint8_t)sizeof(cli_mac);

  ot_payload* pl_cli_mac_payload = ot_payload_create(pl_cli_mac_type, pl_cli_mac_value, pl_cli_mac_vlen);

  // Create payload list in TREQ pkt
  ot_payload* treq_payload_head = treq_pkt->payload;
  treq_payload_head = ot_payload_append(pl_state_payload);
  treq_payload_head = ot_payload_append(pl_cli_ip_payload);
  treq_payload_head = ot_payload_append(pl_cli_mac_payload);

  // Serialize TREQ pkt
  printf("[treq send] serializing pkt... ")
  ssize_t bytes_serialized = 0;
  uint8_t buf[2048] = {0xff}; //<< pre-set with 0xFF terminator
  if ( (bytes_serialized = ot_pkt_serialize(treq_pkt, buf, sizeof buf)) < 0) 
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  
  // Begin TCP send
  int sockfd = 0;
  struct sockaddr_in serv_addr;
  
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
  {
    perror("socket failed");
    ++tests_failed;
    return -1;
  }
  
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);
  serv_addr.sin_addr.s_addr = SRV_IP;

  printf("[treq send] attempting to connect to server... ");
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");

  // Send the serialized TREQ to server
  printf("[treq send] sending bytes to server... ");
  send(sockfd, buf, bytes_serialized, 0);
  // Wait for reply
  if (read(sockfd, buf, sizeof buf) < 0) 
  {
    printf("FAILED\n");
    perror("read failed");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");

  // Finally, deserialize reply
  printf("[treq reply] deserializing reply... ");
  if (ot_pkt_deserialize(reply_pkt, buf, sizeof buf) < 0) 
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");

  // Free the pkt we used for sending the TREQ
  pkt_destroy(&treq_pkt);

  close(sockfd);

  return 0;
}


// TEST HARNESS: test_treq
//
// Test method for building a TREQ payload and sending it at SRV_IP on port PORT 
// Note: this also serves as a guide for creating methods for the clientside
//  
// For the clientside program API, it is better to create functions for extracing the information needed
// in the metadata. It will probably utilize some system calls for communicating with the kernel.
static void test_treq(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  // Receive the reply for a TREQ packet to server
  printf("[treq test] Performing pre-request preparation... ");
  ot_pkt* reply_pkt = NULL;
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP) < 0) 
  {
    printf("FAILED\n");
    return 1;
  } else printf("SUCCESS\n");
  
  printf("---- BEGIN TREQ TESTS ----\n");


  // Header checks
  EXPECT(reply_pkt != NULL, "[treq send] deserialization non-nullity test");

  ot_pkt_header reply_hd = reply_pkt.header;

  EXPECT(reply_hd.srv_ip == SRV_IP, "[treq reply] srv ip check");
  EXPECT(memcmp(reply_hd.srv_mac, srv_mac, 6) == 0, "[treq reply] srv mac check");

  EXPECT(reply_hd.cli_ip == CLI_IP, "[treq reply] cli ip check");
  EXPECT(memcmp(reply_hd.cli_mac, cli_mac, 6) == 0, "[treq reply] cli mac check");

  // Note: these values should be standardized in the entire codebase
  uint32_t actual_exp_time = 86400;
  uint32_t actual_renew_time = 86400 * 0.25;
  EXPECT(reply_hd.exp_time == actual_exp_time, "[treq reply] exp time check");
  EXPECT(reply_hd.renew_time == actual_renew_time, "[treq reply] renew time check");

  // Build parse table from reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing
  // Check expected TACK reply with TREQ input
  printf("[treq reply] checking for PL_STATE entry in parse table... ") 
  ot_cli_state_t* expected_tack = ht_get(parse_table, "PL_STATE");
  if (expected_tack == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_tack == TACK, "[treq reply] reply type (TACK) check");

  // Check expected srv ip (should be same as the one sent in the header of the TREQ pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  printf("[treq reply] checking for PL_SRV_IP entry in parse table... ") 
  if (expected_srv_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_srv_ip == SRV_IP, "[treq reply] srv ip check");

  // Check expected srv mac (also the same as the one in the header of the TREQ pkt)
  uint8_t* expected_srv_mac = ht_get(parse_table, "PL_SRV_MAC");
  printf("[treq reply] checking for PL_SRV_MAC entry in parse table... ") 
  if (expected_srv_mac == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(memcmp(expected_srv_mac, srv_mac, 6) == 0, "[treq reply] srv mac check");


  printf("---- END TREQ TESTS ----\n");

  // Perform cleanup
  ot_pkt_destroy(&reply_pkt);

  close(sockfd);
}

// To test TREN, the server must first identify the client via TREQ/TACK handshake. Here,
// we utilize a special MAC address 00:00:00:AB:AB:FF that will induce a 20-second expiry time 
// for the clients. Recall that an inbound TREN is valid only if the current time is within bounds 
// of the renewal time as per the recorded context.
static void test_tren(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
 
}

static void test_cpull()

int main(void) 
{
  pid_t pid = fork();  
  
  if (pid < 0) 
  {
    perror("fork failed");
    ++tests_failed;
    return 1;
  }

  const int PORT = 7192;
  const uint32_t SRV_IP = inet_addr("127.0.0.1");
  const uint32_t CLI_IP = inet_addr("127.0.0.1");

  if (pid == 0)
  {
    int srv_res = ot_srv_run(PORT, SRV_IP);
    printf("Running server...\n");
    exit(0);
  } else {
    // Valid tests
    test_treq(PORT, SRV_IP, CLI_IP);
    test_tren(PORT, SRV_IP, CLI_IP);
    test_cpull(PORT, SRV_IP, CLI_IP);

    // Error-handling tests
    errhan_test_tren(PORT, SRV_IP, CLI_IP);
    errhan_test_cpull(PORT, SRV_IP, CLI_IP);

    wait(NULL);
    printf("Child process for client has stopped\n");
  }

  if (tests_failed > 0) return 1;

  return 0;
}
