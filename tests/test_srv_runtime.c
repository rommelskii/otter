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
#include <assert.h>

int tests_failed = 0;

/**
* TEST HARNESSES
*/
int test_treq(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP);
int test_tren(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP);
int test_cpull(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP);

int test_expired_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP);
int test_expired_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP);

int test_invalid_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP);
int test_invalid_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP);

int test_unknown_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP);
int test_unknown_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP);

/**
* PRIVATE TEST FIXTURE FUNCTIONS
*/
// Normal client behavior
static int test_treq_send(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_tren_send(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_cpull_send(ot_pkt** reply_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

// Expired client behavior
static int test_expired_tren_send(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_expired_cpull_send(ot_pkt** reply_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

// Error-handling behavior
static int test_invalid_tren_send(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_invalid_cpull_send(ot_pkt** reply_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);


// MAIN ENTRYPOINT
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
    ot_srv_run(); //<< uncomment this after compiling for syntax errors
    printf("Running server...\n");
    exit(0);
  } else {
    sleep(2);
    // Valid tests
    test_treq(PORT, SRV_IP, CLI_IP);
    test_tren(PORT, SRV_IP, CLI_IP);
    test_cpull(PORT, SRV_IP, CLI_IP);

    // Error-handling tests
    test_invalid_tren(PORT, SRV_IP, CLI_IP);
    test_invalid_cpull(PORT, SRV_IP, CLI_IP);

    // Expired client tests
    test_expired_tren(PORT, SRV_IP, CLI_IP);
    test_expired_cpull(PORT, SRV_IP, CLI_IP);

    // Unknown client tests
    test_unknown_tren(PORT, SRV_IP, CLI_IP);
    test_unknown_cpull(PORT, SRV_IP, CLI_IP);

    wait(NULL);
    printf("Child process for client has stopped\n");
  }

  if (tests_failed > 0) return 1;

  return 0;
}

////////////////////////////////////////////////////START OF TEST HARNESSES/////////////////////////////////////////////////////////////
////////////////////////////////////////////////////START OF TEST HARNESSES/////////////////////////////////////////////////////////////
////////////////////////////////////////////////////START OF TEST HARNESSES/////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//// TEST HARNESS: test_treq
////
//// Test method for building a TREQ payload and sending it at SRV_IP on port PORT 
////  
//// For the clientside program API, it is better to create functions for extracing the information needed
//// in the metadata. It will probably utilize some system calls for communicating with the kernel.
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int test_treq(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  // Receive the reply for a TREQ packet to server
  uint8_t srv_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  uint8_t cli_mac[6] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa};
  printf("[treq test] Performing pre-request preparation... ");
  ot_pkt* reply_pkt = NULL;
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac) < 0) 
  {
    printf("FAILED\n");
    return 1;
  } else printf("SUCCESS\n");
  
  printf("---- BEGIN TREQ TESTS ----\n");


  // Header checks
  EXPECT(reply_pkt != NULL, "[treq test] deserialization non-nullity test");

  ot_pkt_header reply_hd = reply_pkt->header;

  EXPECT(reply_hd.srv_ip == SRV_IP, "[treq reply] srv ip check");
  EXPECT(memcmp(reply_hd.srv_mac, srv_mac, 6) == 0, "[treq reply] srv mac check");

  EXPECT(reply_hd.cli_ip == CLI_IP, "[treq reply] cli ip check");
  EXPECT(memcmp(reply_hd.cli_mac, cli_mac, 6) == 0, "[treq reply] cli mac check");

  // Note: these values should be standardized in the entire codebase
  uint32_t actual_exp_time = 86400;
  uint32_t actual_renew_time = 86400 * 0.75;
  EXPECT(reply_hd.exp_time == actual_exp_time, "[treq reply] exp time check");
  EXPECT(reply_hd.renew_time == actual_renew_time, "[treq reply] renew time check");

  // Build parse table from reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing
  // Check expected TACK reply with TREQ input
  printf("[treq reply] checking for PL_STATE entry in parse table... ");
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
  printf("[treq reply] checking for PL_SRV_IP entry in parse table... ");
  if (expected_srv_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_srv_ip == SRV_IP, "[treq reply] srv ip check");

  // Check expected srv mac (also the same as the one in the header of the TREQ pkt)
  uint8_t* expected_srv_mac = ht_get(parse_table, "PL_SRV_MAC");
  printf("[treq reply] checking for PL_SRV_MAC entry in parse table... ");
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
  return 0;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//// TEST HARNESS: test_tren
////
//// Test method for building a TREN payload and sending it at SRV_IP on port PORT 
////
//// To test TREN, the server must first identify the client via TREQ/TACK handshake. Here,
//// we utilize a special MAC address 00:00:00:AB:AB:FF that will induce a 20-second expiry time 
//// for the clients. Recall that an inbound TREN is valid only if the current time is within bounds 
//// of the renewal time as per the recorded context.
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int test_tren(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  uint8_t srv_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  uint8_t cli_mac[6] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa};

  // Perform TREQ/TACK handshake first to create context in server ctable
  printf("[tren test] Performing TREQ/TACK handshake... ");
  ot_pkt* reply_pkt = NULL;
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac) < 0) 
  {
    printf("FAILED\n");
    return 1;
  } else printf("SUCCESS\n");

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);
  
  printf("---- BEGIN TREN TESTS ----\n");

  // Send a TREN request to server and deserialize reply pkt 
  test_tren_send(&reply_pkt, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac); //<< we now use the debug cli mac

  // Wait 16 seconds (75% of 20 seconds) to reach renewal window
  printf("[tren test] waiting 16 seconds to hit renew window... ");
  sleep(16);
  printf("DONE\n");

  // Build parse table from possible TPRV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing
  // Check expected TACK reply with TREQ input
  printf("[tren reply] checking for PL_STATE entry in parse table... ");
  ot_cli_state_t* expected_tprv = ht_get(parse_table, "PL_STATE");
  if (expected_tprv == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_tprv == TPRV, "[tren reply] reply type (TPRV) check");

  // Check expected srv ip (should be same as the one sent in the header of the TREN pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  printf("[tren reply] checking for PL_SRV_IP entry in parse table... ");
  if (expected_srv_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_srv_ip == SRV_IP, "[tren reply] srv ip check");

  // Check expected srv mac (also the same as the one in the header of the TREN pkt)
  uint8_t* expected_srv_mac = ht_get(parse_table, "PL_SRV_MAC");
  printf("[tren reply] checking for PL_SRV_MAC entry in parse table... ");
  if (expected_srv_mac == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(memcmp(expected_srv_mac, srv_mac, 6) == 0, "[tren reply] srv mac check");


  printf("---- END TREN TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TPRV pkt
  ot_pkt_destroy(&reply_pkt);
  return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//// TEST HARNESS: test_cpull
////
//// For testing the CPULL functionality
////
//// To test CPULL, like with TREN, we first have to perform a TREQ/TACK handshake to create a context in the server.
//// After which, we send a valid CPULL packet to the server and we cross check with the expected values as usual.
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int test_cpull(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  uint8_t srv_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  uint8_t cli_mac[6] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa};

  const char* UNAME = "rommelwashere2496";
  const char* PSK = "WhatACoolPassword123";

  // Perform TREQ/TACK handshake first to create context in server ctable
  printf("[cpull test] Performing TREQ/TACK handshake... ");
  ot_pkt* reply_pkt = NULL;
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac) < 0)
  {
    printf("FAILED\n");
    return 1;
  } else printf("SUCCESS\n");

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);

  printf("---- BEGIN CPULL TESTS ----\n");

  // Send a CPULL request to server and deserialize reply pkt 
  test_cpull_send(&reply_pkt, UNAME, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac); //<< dont forget to indicate UNAME for CPULL pkts

  // Build parse table from possible CPUSH reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing

  // Check expected CPUSH reply with TREQ input
  printf("[cpull reply] checking for PL_STATE entry in parse table... ");
  ot_cli_state_t* expected_cpush = ht_get(parse_table, "PL_STATE");
  if (expected_cpush == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_cpush == CPUSH, "[cpull reply] reply type (CPUSH) check");


  // Check expected srv ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  printf("[cpull reply] checking for PL_SRV_IP entry in parse table... ");
  if (expected_srv_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_srv_ip == SRV_IP, "[cpull reply] srv ip check");


  // Check expected cli ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  printf("[cpull reply] checking for PL_CLI_IP entry in parse table... ");
  if (expected_cli_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_cli_ip == CLI_IP, "[cpull reply] cli ip check");


  // Check expected uname
  const char* expected_uname = ht_get(parse_table, "PL_UNAME");
  printf("[cpull reply] checking for PL_UNAME entry in parse table... ");
  if (expected_uname == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(strcmp(expected_uname, UNAME) == 0, "[cpull reply] uname check");

  
  // Check expected PSK
  const char* expected_psk = ht_get(parse_table, "PL_PSK");
  printf("[cpull reply] checking for PL_PSK entry in parse table... ");
  if (expected_psk == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(strcmp(expected_psk, PSK) == 0, "[cpull reply] psk check");

  printf("---- END CPULL TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TPRV pkt
  ot_pkt_destroy(&reply_pkt);

  return 0;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//// TEST HARNESS: test_expired_tren
////
//// Testing the server's error-handling function to expired clients that perform TREN requests
//// 
//// We simply modify the test_cpull harness and utilize the 20-second-inducing debug MAC to perform a TREN request
//// after the 20-second mark (the expiry time). Here, we expect a TINV reply from the server.
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int test_expired_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP)
{
  uint8_t srv_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  uint8_t debug_cli_mac[6] = {0x00, 0x00, 0x00, 0xab, 0xab, 0xff}; //<< utilize debug mac to achieve 20-second expiry time

  // Perform TREQ/TACK handshake first to create context in server ctable
  printf("[tren test] Performing TREQ/TACK handshake... ");
  ot_pkt* reply_pkt = NULL;
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, srv_mac, debug_cli_mac) < 0) 
  {
    printf("FAILED\n");
    return 1;
  } else printf("SUCCESS\n");

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);

  // Wait for client context to expire
  sleep(21);
  
  printf("---- BEGIN EXPIRED TREN TESTS ----\n");

  // Send a TREN request to server and deserialize reply pkt 
  test_tren_send(&reply_pkt, PORT, SRV_IP, CLI_IP, srv_mac, debug_cli_mac); //<< we now use the debug cli mac

  // Build parse table from possible TINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing
  // Check expected TINV reply with TREN input
  printf("[expired tren reply] checking for PL_STATE entry in parse table... ");
  ot_cli_state_t* expected_tinv = ht_get(parse_table, "PL_STATE");
  if (expected_tinv == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_tinv == TINV, "[expired tren reply] reply type (TINV) check");

  // Check expected srv ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  printf("[expired tren reply] checking for PL_SRV_IP entry in parse table... ");
  if (expected_srv_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_srv_ip == SRV_IP, "[expired tren reply] srv ip check");
  
  // Check expected cli ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  printf("[expired tren reply] checking for PL_CLI_IP entry in parse table... ");
  if (expected_srv_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_cli_ip == CLI_IP, "[expired tren reply] cli ip check");

  printf("---- END EXPIRED TREN TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TINV pkt
  ot_pkt_destroy(&reply_pkt);

  return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//// TEST HARNESS: test_expired_cpull
////
//// Testing the server's error-handling function to expired clients that perform CPULL requests
//// 
//// We simply modify the test_cpull harness and utilize the 20-second client MAC to perform a TREN request
//// after the 20-second mark (the expiry time). Here, we expect a TINV reply from the server.
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int test_expired_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP)
{
  uint8_t srv_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  uint8_t debug_cli_mac[6] = {0x00, 0x00, 0x00, 0xab, 0xab, 0xff};
  const char* UNAME = "rommelwashere2496";
  const char* PSK = "WhatACoolPassword123";

  // Perform TREQ/TACK handshake first to create context in server ctable
  printf("[cpull test] Performing TREQ/TACK handshake... ");
  ot_pkt* reply_pkt = NULL;
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, srv_mac, debug_cli_mac) < 0)
  {
    printf("FAILED\n");
    return 1;
  } else printf("SUCCESS\n");

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);

  // Wait until client context expires
  sleep(21);

  printf("---- BEGIN EXPIRED CPULL TESTS ----\n");

  // Send a CPULL request to server and deserialize reply pkt 
  test_cpull_send(&reply_pkt, UNAME, PORT, SRV_IP, CLI_IP, srv_mac, debug_cli_mac); //<< dont forget to indicate UNAME for CPULL pkts

  // Build parse table from possible CINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing

  // Check expected CINV reply with CPULL input
  printf("[expired cpull reply] checking for PL_STATE entry in parse table... ");
  ot_cli_state_t* expected_cinv = ht_get(parse_table, "PL_STATE");
  if (expected_cinv == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_cinv == CINV, "[expired cpull reply] reply type (CINV) check");


  // Check expected srv ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  printf("[expired cpull reply] checking for PL_SRV_IP entry in parse table... ");
  if (expected_srv_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_srv_ip == SRV_IP, "[expired cpull reply] srv ip check");

  // Check expected cli ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  printf("[expired cpull reply] checking for PL_CLI_IP entry in parse table... ");
  if (expected_cli_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_cli_ip == CLI_IP, "[expired cpull reply] cli ip check");


  // Check expected uname
  const char* expected_uname = ht_get(parse_table, "PL_UNAME");
  printf("[expired cpull reply] checking for PL_UNAME entry in parse table... ");
  if (expected_uname == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(strcmp(expected_uname, UNAME) == 0, "[expired cpull reply] uname check");


  printf("---- END EXPIRED CPULL TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TPRV pkt
  ot_pkt_destroy(&reply_pkt);

  return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//// TEST HARNESS: test_invalid_tren
////
//// Tests if the server can invalidate TREN requests from expired clients via TINV replies
//// 
//// We can just utilize the same logic as the test_tren harness but with an earlier renewal time
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int test_invalid_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP)
{
  uint8_t srv_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  uint8_t cli_mac[6] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa};

  // Perform TREQ/TACK handshake first to create context in server ctable
  printf("[invalid tren test] Performing TREQ/TACK handshake... ");
  ot_pkt* reply_pkt = NULL;
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac) < 0) 
  {
    printf("FAILED\n");
    return 1;
  } else printf("SUCCESS\n");

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);
  
  printf("---- BEGIN TREN TESTS ----\n");

  // Send a TREN request to server and deserialize reply pkt 
  test_tren_send(&reply_pkt, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac); //<< we now use the debug cli mac

  // Wait 3 seconds (forcefully not in renewal window yet) to reach renewal window
  printf("[invalid tren test] waiting 3 seconds to hit renew window... ");
  sleep(3);
  printf("DONE\n");

  // Build parse table from possible TINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing
  
  // Check expected TINV reply with TREN input
  printf("[invalid tren reply] checking for PL_STATE entry in parse table... ");
  ot_cli_state_t* expected_tinv = ht_get(parse_table, "PL_STATE");
  if (expected_tinv == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_tinv == TINV, "[invalid tren reply] reply type (TINV) check");

  // Check expected srv ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  printf("[invalid tren reply] checking for PL_SRV_IP entry in parse table... ");
  if (expected_srv_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_srv_ip == SRV_IP, "[expired tren reply] srv ip check");
  
  // Check expected cli ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  printf("[invalid tren reply] checking for PL_CLI_IP entry in parse table... ");
  if (expected_srv_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_cli_ip == CLI_IP, "[invalid tren reply] cli ip check");

  printf("---- END TREN TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TINV pkt
  ot_pkt_destroy(&reply_pkt);

  return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//// TEST HARNESS: test_invalid_cpull
////
//// Tests if the server can invalidate CPULL requests from expired clients via CINV replies
//// 
//// Again, just utilize the same logic as expired CPULL from the test_expired_cpull harness but with an UNKNOWN uname
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int test_invalid_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP)
{
  uint8_t srv_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  uint8_t cli_mac[6] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa};
  const char* UNAME = "ThisIsNotReallyAKnownUsername";

  // Perform TREQ/TACK handshake first to create context in server ctable
  printf("[invalid cpull test] Performing TREQ/TACK handshake... ");
  ot_pkt* reply_pkt = NULL;
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac) < 0)
  {
    printf("FAILED\n");
    return 1;
  } else printf("SUCCESS\n");

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);

  printf("---- BEGIN CPULL TESTS ----\n");

  // Send a CPULL request to server and deserialize reply pkt 
  test_cpull_send(&reply_pkt, UNAME, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac); //<< dont forget to indicate UNAME for CPULL pkts

  // Build parse table from possible CINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing

  // Check expected CINV reply with CPULL input
  printf("[invalid cpull reply] checking for PL_STATE entry in parse table... ");
  ot_cli_state_t* expected_cinv = ht_get(parse_table, "PL_STATE");
  if (expected_cinv == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_cinv == CINV, "[invalid cpull reply] reply type (CINV) check");


  // Check expected srv ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  printf("[invalid cpull reply] checking for PL_SRV_IP entry in parse table... ");
  if (expected_srv_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_srv_ip == SRV_IP, "[invalid cpull reply] srv ip check");

  // Check expected cli ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  printf("[invalid cpull reply] checking for PL_CLI_IP entry in parse table... ");
  if (expected_cli_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_cli_ip == CLI_IP, "[invalid cpull reply] cli ip check");


  // Check expected uname
  const char* expected_uname = ht_get(parse_table, "PL_UNAME");
  printf("[invalid cpull reply] checking for PL_UNAME entry in parse table... ");
  if (expected_uname == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(strcmp(expected_uname, UNAME) == 0, "[invalid cpull reply] uname check");


  printf("---- END INVALID CPULL TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TPRV pkt
  ot_pkt_destroy(&reply_pkt);

  return 0;
}


// NOTE FOR UNKNOWN CLIENT TESTS !!
// These harnesses are just the invalid tests but with no TACK/TREQ handshakes

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//// TEST HARNESS: test_unknown_tren 
////
//// Tests whether the server can respond with a TINV to a TREQ from an unknown client 
//// 
//// Utilizes re-used logic from test_invalid_tren but NOT PERFORM THE TREQ/TACK HANDSHAKE
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int test_unknown_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP)
{
  uint8_t srv_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  uint8_t cli_mac[6] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa};

  // No TREQ/TACK handshake here...
  
  printf("---- BEGIN UNKNOWN CLIENT TREN TESTS ----\n");

  ot_pkt* reply_pkt = NULL;

  // Send a TREN request to server and deserialize reply pkt 
  test_tren_send(&reply_pkt, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac); //<< we now use the debug cli mac

  // Build parse table from possible TINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing
  
  // Check expected TINV reply with TREN input
  printf("[unknown tren reply] checking for PL_STATE entry in parse table... ");
  ot_cli_state_t* expected_tinv = ht_get(parse_table, "PL_STATE");
  if (expected_tinv == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_tinv == TINV, "[unknown tren reply] reply type (TINV) check");

  // Check expected srv ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  printf("[unknown tren reply] checking for PL_SRV_IP entry in parse table... ");
  if (expected_srv_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_srv_ip == SRV_IP, "[unknown tren reply] srv ip check");
  
  // Check expected cli ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  printf("[unknown tren reply] checking for PL_CLI_IP entry in parse table... ");
  if (expected_srv_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_cli_ip == CLI_IP, "[unknown tren reply] cli ip check");

  printf("---- END UNKNOWN TREN TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TINV pkt
  ot_pkt_destroy(&reply_pkt);

  return 0;

}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//// TEST HARNESS: test_unknown_cpull
////
//// Tests whether the server can respond with a CINV to a CPULL from an unknown client 
//// 
//// Utilizes re-used logic from test_invalid_cpull and NOT PERFORM THE TREQ/TACK HANDSHAKE
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int test_unknown_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP)
{
  assert("[test_unknown_cpull] not yet implemented" && false);
  return 0;
}

////////////////////////////////////////////////////END OF TEST HARNESSES/////////////////////////////////////////////////////////////
////////////////////////////////////////////////////END OF TEST HARNESSES/////////////////////////////////////////////////////////////
////////////////////////////////////////////////////END OF TEST HARNESSES/////////////////////////////////////////////////////////////

static int test_treq_send(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac) 
{
  // Build TREQ header 
  //uint8_t srv_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  //uint8_t cli_mac[6] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa};
  ot_pkt_header treq_hd = ot_pkt_header_create(SRV_IP, CLI_IP,  srv_mac, cli_mac, 0, 0);

  // Build TREQ pkt
  ot_pkt* treq_pkt = ot_pkt_create();
  treq_pkt->header = treq_hd;

  // Specify TREQ state payload
  ot_pkt_msgtype_t pl_state_type = PL_STATE; //<< state to indicate that we are sending a TREQ packet
  uint8_t pl_state_value = (uint8_t)TREQ; 
  uint8_t pl_state_vlen = (uint8_t)sizeof(pl_state_value);

  ot_payload* pl_state_payload = ot_payload_create(pl_state_type, &pl_state_value, pl_state_vlen);

  // Specify TREQ cli_ip payload 
  ot_pkt_msgtype_t pl_cli_ip_type = PL_CLI_IP;
  uint32_t pl_cli_ip_value = CLI_IP;
  uint8_t pl_cli_ip_vlen = (uint8_t)sizeof(pl_cli_ip_value);

  ot_payload* pl_cli_ip_payload = ot_payload_create(pl_cli_ip_type, &pl_cli_ip_value, pl_cli_ip_vlen);

  // Specify TREQ cli_mac payload
  // pl_create(PL_CLI_MAC, MAC*, sizeof(MAC))

  ot_pkt_msgtype_t pl_cli_mac_type = PL_CLI_MAC;
  uint8_t pl_cli_mac_value[6] = {0}; 

  memcpy(pl_cli_mac_value, cli_mac, 6);

  uint8_t pl_cli_mac_vlen = (uint8_t)sizeof(cli_mac);

  ot_payload* pl_cli_mac_payload = ot_payload_create(pl_cli_mac_type, &pl_cli_mac_value, pl_cli_mac_vlen);

  // Create payload list in TREQ pkt
  ot_payload* treq_payload_head = treq_pkt->payload;
  treq_payload_head = ot_payload_append(treq_payload_head, pl_state_payload);
  treq_payload_head = ot_payload_append(treq_payload_head, pl_cli_ip_payload);
  treq_payload_head = ot_payload_append(treq_payload_head, pl_cli_mac_payload);

  // Serialize TREQ pkt
  printf("[treq test] serializing pkt... ");
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

  printf("[treq test] attempting to connect to server... ");
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");

  // Send the serialized TREQ to server
  printf("[treq test] sending bytes to server... ");
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
  if (ot_pkt_deserialize(*reply_pkt, buf, sizeof buf) < 0) 
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");

  // Free the pkt we used for sending the TREQ
  ot_pkt_destroy(&treq_pkt);

  close(sockfd);

  return 0;
}

static int test_tren_send(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac)
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
  ot_pkt_msgtype_t pl_srv_ip_type = PL_SRV_IP;
  uint32_t pl_srv_ip_value = SRV_IP;
  uint8_t pl_srv_ip_vlen = (uint8_t)sizeof(pl_srv_ip_value);

  ot_payload* pl_srv_ip_payload = ot_payload_create(pl_srv_ip_type, &pl_srv_ip_value, pl_srv_ip_vlen);


  // Specify TREN cli_ip payload 
  ot_pkt_msgtype_t pl_cli_ip_type = PL_CLI_IP;
  uint32_t pl_cli_ip_value = CLI_IP;
  uint8_t pl_cli_ip_vlen = (uint8_t)sizeof(pl_cli_ip_value);

  ot_payload* pl_cli_ip_payload = ot_payload_create(pl_cli_ip_type, &pl_cli_ip_value, pl_cli_ip_vlen);

  
  // Specify TREN exp_time payload 
  ot_pkt_msgtype_t pl_exp_time_type = PL_ETIME;
  uint32_t pl_exp_time_value = 86400;
  uint8_t pl_exp_time_vlen = (uint8_t)sizeof(pl_exp_time_value);

  ot_payload* pl_exp_time_payload = ot_payload_create(pl_exp_time_type, &pl_exp_time_value, pl_exp_time_vlen);
  

  // Specify TREN renew_time payload 
  ot_pkt_msgtype_t pl_renew_time_type = PL_RTIME;
  uint32_t pl_renew_time_value = 86400 * 0.75;
  uint8_t pl_renew_time_vlen = (uint8_t)sizeof(pl_renew_time_value);

  ot_payload* pl_renew_time_payload = ot_payload_create(pl_renew_time_type, &pl_renew_time_value, pl_renew_time_vlen);


  // Create payload list in TREN pkt
  ot_payload* tren_payload_head = tren_pkt->payload;
  tren_payload_head = ot_payload_append(tren_payload_head, pl_srv_ip_payload);
  tren_payload_head = ot_payload_append(tren_payload_head, pl_cli_ip_payload);
  tren_payload_head = ot_payload_append(tren_payload_head, pl_exp_time_payload);
  tren_payload_head = ot_payload_append(tren_payload_head, pl_renew_time_payload);

  // Serialize TREN pkt
  printf("[tren send] serializing pkt... ");
  ssize_t bytes_serialized = 0;
  uint8_t buf[2048] = {0xff}; //<< pre-set with 0xFF terminator
  if ( (bytes_serialized = ot_pkt_serialize(tren_pkt, buf, sizeof buf)) < 0) 
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

  printf("[tren send] attempting to connect to server... ");
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");

  // Send the serialized TREN to server
  printf("[tren send] sending bytes to server... ");
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
  printf("[tren reply] deserializing reply... ");
  if (ot_pkt_deserialize(*reply_pkt, buf, sizeof buf) < 0) 
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");

  // Free the pkt we used for sending the TREN pkt
  ot_pkt_destroy(&tren_pkt);

  close(sockfd);

  return 0;
}

static int test_cpull_send(ot_pkt** reply_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac) 
{
  // Build CPULL header 
  ot_pkt_header cpull_hd = ot_pkt_header_create(SRV_IP, CLI_IP,  srv_mac, cli_mac, 0, 0);

  // Build CPULL pkt
  ot_pkt* cpull_pkt = ot_pkt_create();
  cpull_pkt->header = cpull_hd;

  // Specify CPULL state payload
  ot_pkt_msgtype_t pl_state_type = PL_STATE; //<< state to indicate that we are sending a TREN packet
  uint8_t pl_state_value = (uint8_t)CPULL; 
  uint8_t pl_state_vlen = (uint8_t)sizeof(pl_state_value);

  ot_payload* pl_state_payload = ot_payload_create(pl_state_type, &pl_state_value, pl_state_vlen);


  // Specify CPULL srv_ip payload 
  ot_pkt_msgtype_t pl_srv_ip_type = PL_SRV_IP;
  uint32_t pl_srv_ip_value = SRV_IP;
  uint8_t pl_srv_ip_vlen = (uint8_t)sizeof(pl_srv_ip_value);

  ot_payload* pl_srv_ip_payload = ot_payload_create(pl_srv_ip_type, &pl_srv_ip_value, pl_srv_ip_vlen);


  // Specify TREN cli_ip payload 
  ot_pkt_msgtype_t pl_cli_ip_type = PL_CLI_IP;
  uint32_t pl_cli_ip_value = CLI_IP;
  uint8_t pl_cli_ip_vlen = (uint8_t)sizeof(pl_cli_ip_value);

  ot_payload* pl_cli_ip_payload = ot_payload_create(pl_cli_ip_type, &pl_cli_ip_value, pl_cli_ip_vlen);

  
  // Specify CPULL uname payload 
  ot_pkt_msgtype_t pl_uname_type = PL_UNAME;
  char* pl_uname_value = (char*)uname;
  uint8_t pl_uname_vlen = (uint8_t)strlen(pl_uname_value)+1;

  ot_payload* pl_uname_payload = ot_payload_create(pl_uname_type, pl_uname_value, pl_uname_vlen);
  


  // Create payload list in CPULL pkt
  ot_payload* cpull_payload_head = cpull_pkt->payload;
  cpull_payload_head = ot_payload_append(cpull_payload_head, pl_srv_ip_payload);
  cpull_payload_head = ot_payload_append(cpull_payload_head, pl_cli_ip_payload);
  cpull_payload_head = ot_payload_append(cpull_payload_head, pl_uname_payload);

  // Serialize CPULL pkt
  printf("[cpull send] serializing pkt... ");
  ssize_t bytes_serialized = 0;
  uint8_t buf[2048] = {0xff}; //<< pre-set with 0xFF terminator
  if ( (bytes_serialized = ot_pkt_serialize(cpull_pkt, buf, sizeof buf)) < 0) 
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

  printf("[cpull send] attempting to connect to server... ");
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");

  // Send the serialized CPULL to server
  printf("[cpull send] sending bytes to server... ");
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
  printf("[cpull reply] deserializing reply... ");
  if (ot_pkt_deserialize(*reply_pkt, buf, sizeof buf) < 0) 
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");

  // Free the pkt we used for sending the CPULL pkt
  ot_pkt_destroy(&cpull_pkt);

  close(sockfd);

  return 0;
}

