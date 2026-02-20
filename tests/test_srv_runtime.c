/* Created by Rommel John H. Ronduen (rommel.ronduen2244@gmail.com)
*
* file: test_srv_runtime.c
*
* Contains test harnesses for testing the server runtime. The tests here are written similar to 
* the perspective of the clientside. 
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
#include <signal.h>

int tests_failed = 0;

/**
* TEST HARNESSES
*/
int test_treq(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP,
              uint8_t* SRV_MAC, uint8_t* CLI_MAC);
int test_tren(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP,
              uint8_t* SRV_MAC, uint8_t* DBG_CLI_MAC);
int test_cpull(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP,
              uint8_t* SRV_MAC, uint8_t* CLI_MAC);

int test_expired_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP,
                      uint8_t* SRV_MAC, uint8_t* DBG_CLI_MAC);
int test_expired_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP,
                      uint8_t* SRV_MAC, uint8_t* DBG_CLI_MAC);

int test_invalid_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP,
                      uint8_t* SRV_MAC, uint8_t* DBG_CLI_MAC);
int test_invalid_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP,
                      uint8_t* SRV_MAC, uint8_t* CLI_MAC);

int test_unknown_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP,
                      uint8_t* SRV_MAC, uint8_t* CLI_MAC);
int test_unknown_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP,
                       uint8_t* SRV_MAC, uint8_t* CLI_MAC);


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
  
  const uint32_t SRV_IP = inet_addr("127.0.0.1");
  const uint32_t CLI_IP = inet_addr("127.0.0.1");

  uint8_t SRV_MAC[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  uint8_t CLI_MAC[6] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa};
  uint8_t DBG_CLI_MAC[6] = {0x00, 0x00, 0x00, 0xab, 0xab, 0xff};

  if (pid == 0)
  {
    ot_srv_run(SRV_IP, SRV_MAC); 
    exit(0);
  } else {
    sleep(2);
    // Valid tests
    if (test_treq(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC) != 0) goto kill_proc;
    if (test_tren(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) != 0) goto kill_proc;
    if (test_cpull(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC) != 0) goto kill_proc;

    // Error-handling tests
    if (test_invalid_tren(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) != 0) goto kill_proc;
    if (test_invalid_cpull(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC) != 0) goto kill_proc;

    // Expired client tests
    if (test_expired_tren(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) != 0) goto kill_proc;
    if (test_expired_cpull(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) != 0) goto kill_proc;

    // Unknown client tests
    if (test_unknown_tren(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC) != 0) goto kill_proc;
    if (test_unknown_cpull(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC) != 0) goto kill_proc;

kill_proc:
    if (kill(pid, SIGTERM) == -1) 
    {
      perror("kill failed");
    }

    int status;
    waitpid(pid, &status, 0);

    printf("[test srv runtime] killed %d srv process\n", pid);
  }

  if (tests_failed > 0) 
  {
    printf("[test srv runtime] one or more tests have failed! Exiting...\n");
    return 1;
  }

  printf("[test srv runtime] all tests passed!\n");

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
int test_treq(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP,
              uint8_t* SRV_MAC, uint8_t* CLI_MAC)
{
  ot_pkt* reply_pkt = ot_pkt_create();
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC) < 0) 
  {
    printf("[test_treq] failed to send treq pkt to server\n");
    return 1;
  } 
  
  printf("\n---- BEGIN TREQ TESTS ----\n");

  // Header checks
  EXPECT(reply_pkt != NULL, "[treq reply] deserialization non-nullity test");

  ot_pkt_header reply_hd = reply_pkt->header;

  EXPECT(reply_hd.srv_ip == SRV_IP, "[treq reply] srv ip check");
  EXPECT(memcmp(reply_hd.srv_mac, SRV_MAC, 6) == 0, "[treq reply] srv mac check");

  EXPECT(reply_hd.cli_ip == CLI_IP, "[treq reply] cli ip check");
  EXPECT(memcmp(reply_hd.cli_mac, CLI_MAC, 6) == 0, "[treq reply] cli mac check");

  // Note: these values should be standardized in the entire codebase
  uint32_t actual_exp_time = DEF_EXP_TIME;
  uint32_t actual_renew_time = DEF_EXP_TIME * 0.75;
  EXPECT(reply_hd.exp_time == actual_exp_time, "[treq reply] exp time check");
  EXPECT(reply_hd.renew_time == actual_renew_time, "[treq reply] renew time check");

  // Build parse table from reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing
  // Check expected TACK reply with TREQ input
  ot_cli_state_t* expected_tack = ht_get(parse_table, "PL_STATE");
  if (expected_tack == NULL)
  {
    printf("[FAILED] [treq reply] reply type (TACK) check");
    ++tests_failed;
  } 
  EXPECT(*expected_tack == TACK, "[treq reply] reply type (TACK) check");

  // Check expected srv ip (should be same as the one sent in the header of the TREQ pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  if (expected_srv_ip == NULL)
  {
    printf("[FAILED] [treq reply] srv ip check");
    ++tests_failed;
  } 
  EXPECT(*expected_srv_ip == SRV_IP, "[treq reply] srv ip check");

  uint8_t* expected_srv_mac = ht_get(parse_table, "PL_SRV_MAC");
  if (expected_srv_mac == NULL)
  {
    printf("[FAILED] [treq reply] srv mac check");
    ++tests_failed;
  } 
  EXPECT(memcmp(expected_srv_mac, SRV_MAC, 6) == 0, "[treq reply] srv mac check");

  // Check expected cli ip (should be same as the one sent in the header of the TREQ pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  if (expected_cli_ip == NULL)
  {
    printf("[FAILED] [treq reply] cli ip check");
    ++tests_failed;
  } 
  EXPECT(*expected_cli_ip == CLI_IP, "[treq reply] cli ip check");

  uint32_t* expected_exp_time = ht_get(parse_table, "PL_ETIME");
  if (expected_exp_time == NULL)
  {
    printf("[FAILED] [treq reply] exp time check");
    ++tests_failed;
  } 
  EXPECT(*expected_exp_time == DEF_EXP_TIME, "[treq reply] exp time check");

  uint32_t* expected_renew_time = ht_get(parse_table, "PL_RTIME");
  if (expected_renew_time == NULL)
  {
    printf("[FAILED] [treq reply] renew time check");
    ++tests_failed;
  } 
  EXPECT(*expected_renew_time == DEF_EXP_TIME*0.75, "[treq reply] renew time check");

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
int test_tren(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP,
              uint8_t* SRV_MAC, uint8_t* DBG_CLI_MAC)
{
  printf("---- BEGIN TREN TESTS ----\n");
  // Perform TREQ/TACK handshake first to create context in server ctable
  ot_pkt* reply_pkt = ot_pkt_create();
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) < 0) 
  {
    printf("[test_treq] failed to send treq pkt to server\n");
    return 1;
  } 

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);
  
  printf("[tren test] waiting 16 seconds to hit renew window...\n");
  // Wait 16 seconds (75% of 20 seconds) to reach renewal window
  sleep(17);
  printf("DONE\n");

  // Send a TREN request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create();
  test_tren_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC); 

  // Build parse table from possible TPRV reply pkt payloads
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_pkt->payload);

  // Start payload parsing
  // Check expected TACK reply with TREQ input
  ot_cli_state_t* expected_tprv = ht_get(parse_table, "PL_STATE");
  EXPECT(expected_tprv != NULL, "[tprv reply] pl_state presence");
  EXPECT(*expected_tprv == TPRV, "[tprv reply] pl_state value check");

  // Check expected srv ip (should be same as the one sent in the header of the TREN pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[tprv reply] pl_srv_ip presence");
  EXPECT(*expected_srv_ip == SRV_IP, "[tprv reply] pl_srv_ip value");

  // Check expected cli ip
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[tprv reply] pl_cli_ip presence");
  EXPECT(*expected_cli_ip == reply_pkt->header.cli_ip, "[tprv reply] pl_cli_ip value");

  // Check expected expiry time
  uint32_t* expected_exp_time = ht_get(parse_table, "PL_ETIME");
  EXPECT(expected_exp_time != NULL, "[tprv reply] pl_etime presence");
  EXPECT(*expected_exp_time == DEF_EXP_TIME, "[tprv reply] pl_etime value");

  // Check expected expiry time
  uint32_t* expected_renew_time = ht_get(parse_table, "PL_RTIME");
  EXPECT(expected_renew_time != NULL, "[tprv reply] pl_rtime presence");
  EXPECT(*expected_renew_time == DEF_EXP_TIME*0.75, "[tprv reply] pl_rtime value");

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
int test_cpull(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP,
               uint8_t* SRV_MAC, uint8_t* CLI_MAC)
{
  printf("---- BEGIN CPULL TESTS ----\n");
  uint8_t srv_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  uint8_t cli_mac[6] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa};

  const char* UNAME = "rommelrond";
  const char* PSK = "WowHello";

  // Perform TREQ/TACK handshake first to create context in server ctable
  ot_pkt* reply_pkt = ot_pkt_create();
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac) < 0)
  {
    printf("[FAILED] [cpull tack] failed to establish TREQ/TACK handshake with server\n");
    return -1;
  } 

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);

  // Send a CPULL request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create();
  test_cpull_send(&reply_pkt, UNAME, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac); 

  // Build parse table from possible CPUSH reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing

  // Check expected CPUSH reply 
  printf("[cpull reply] checking for PL_STATE entry in parse table... ");
  ot_cli_state_t* expected_cpush = ht_get(parse_table, "PL_STATE");
  EXPECT(expected_cpush != NULL, "[cpush reply] pl_state presence");
  EXPECT(*expected_cpush == CPUSH, "[cpush reply] pl_state value");

  // Check expected srv ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[cpush reply] pl_srv_ip presence");
  EXPECT(*expected_srv_ip == SRV_IP, "[cpull reply] pl_srv_ip value");

  // Check expected cli ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[cpush reply] pl_cli_ip presence");
  EXPECT(*expected_cli_ip == CLI_IP, "[cpush reply] pl_cli_ip value");

  // Check expected uname
  const char* expected_uname = ht_get(parse_table, "PL_UNAME");
  EXPECT(expected_uname != NULL, "[cpush reply] pl_uname presence");
  EXPECT(strcmp(expected_uname, UNAME) == 0, "[cpull reply] pl_uname value");

  // Check expected PSK
  const char* expected_psk = ht_get(parse_table, "PL_PSK");
  EXPECT(expected_psk != NULL, "[cpush reply] pl_psk presence");
  EXPECT(strcmp(expected_psk, PSK) == 0, "[cpush reply] pl_psk value");

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
int test_expired_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, 
                      uint8_t* SRV_MAC, uint8_t* DBG_CLI_MAC)
{
  printf("---- BEGIN EXPIRED TREN TESTS ----\n");
  // Perform TREQ/TACK handshake first to create context in server ctable
  ot_pkt* reply_pkt = ot_pkt_create();
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) < 0) 
  {
    printf("[FAILED] [expired tren tack] failed to establish TREQ/TACK handshake with server\n");
    return 1;
  } 

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);

  printf("[expired tren tack] waiting 21 seconds for client to expire...\n");
  // Wait for client context to expire
  sleep(21);
  printf("DONE\n");
  

  // Send a TREN request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create();
  test_tren_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC); //<< we now use the debug cli mac

  // Build parse table from possible TINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing
  // Check expected TINV reply with TREN input
  ot_cli_state_t* expected_tinv = ht_get(parse_table, "PL_STATE");
  EXPECT(expected_tinv != NULL, "[expired tinv reply] pl_state presence");
  EXPECT(*expected_tinv == TINV, "[expired tinv reply] pl_state value");

  // Check expected srv ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[expired tinv reply] pl_srv_ip presence");
  EXPECT(*expected_srv_ip == SRV_IP, "[expired tinv reply] pl_srv_ip value");
  
  // Check expected cli ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[expired tinv reply] pl_cli_ip presence");
  EXPECT(*expected_cli_ip == CLI_IP, "[expired tinv reply] pl_cli_ip value");

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
int test_expired_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP,
                       uint8_t* SRV_MAC, uint8_t* DBG_CLI_MAC)
{
  const char* UNAME = "rommelrond";
  const char* PSK = "WowHello";

  // Perform TREQ/TACK handshake first to create context in server ctable
  ot_pkt* reply_pkt = ot_pkt_create();
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) < 0)
  {
    printf("[FAILED] [expired cpull tack] failed to establish TREQ/TACK handshake with server\n");
    return 1;
  } 

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);

  // Wait until client context expires
  sleep(21);

  printf("---- BEGIN EXPIRED CPULL TESTS ----\n");

  // Send a CPULL request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create();
  test_cpull_send(&reply_pkt, UNAME, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC); 
  EXPECT(reply_pkt != NULL, "[expired cinv reply] recv cinv from server");

  // Build parse table from possible CINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing

  // Check expected CINV reply with CPULL input
  ot_cli_state_t* expected_cinv = ht_get(parse_table, "PL_STATE");
  EXPECT(expected_cinv != NULL, "[expired cinv reply] pl_state presence");
  EXPECT(*expected_cinv == CINV, "[expired cinv reply] pl_state value");


  // Check expected srv ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[expired cinv reply] pl_srv_ip presence");
  EXPECT(*expected_srv_ip == SRV_IP, "[expired cinv reply] pl_srv_ip value");

  // Check expected cli ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[expired cinv reply] pl_cli_ip presence");
  EXPECT(*expected_cli_ip == CLI_IP, "[expired cinv reply] pl_cli_ip value");


  // Check expected uname
  const char* expected_uname = ht_get(parse_table, "PL_UNAME");
  EXPECT(expected_uname != NULL, "[expired cinv reply] pl_uname presence");
  EXPECT(strcmp(expected_uname, UNAME) == 0, "[expired cinv reply] pl_uname value");

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
int test_invalid_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, 
                      uint8_t* SRV_MAC, uint8_t* DBG_CLI_MAC)
{
  // Perform TREQ/TACK handshake first to create context in server ctable
  ot_pkt* reply_pkt = ot_pkt_create();
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) < 0) 
  {
    printf("[FAILED] [invalid tren tack] failed to establish TREQ/TACK handshake with server\n");
    return 1;
  } 

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);
  
  printf("---- BEGIN INVALID TREN TESTS ----\n");

  // Send a TREN request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create();
  test_tren_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC); //<< we now use the debug cli mac
  EXPECT(reply_pkt != NULL, "[invalid tinv reply] recv cinv from server");

  // Wait 3 seconds (forcefully not in renewal window yet) to reach renewal window
  printf("[invalid tren test] waiting 3 seconds to hit renew window... \n");
  sleep(3);
  printf("DONE\n");

  // Build parse table from possible TINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing
  
  // Check expected TINV reply with TREN input
  ot_cli_state_t* expected_tinv = ht_get(parse_table, "PL_STATE");
  EXPECT(expected_tinv != NULL, "[invalid tinv reply] pl_state presence");
  EXPECT(*expected_tinv == TINV, "[invalid tinv reply] pl_state value");

  // Check expected srv ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[invalid tinv reply] pl_srv_ip presence");
  EXPECT(*expected_srv_ip == SRV_IP, "[invalid tinv reply] srv ip check");
  
  // Check expected cli ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[invalid tinv reply] pl_cli_ip presence");
  EXPECT(*expected_cli_ip == CLI_IP, "[invalid tinv reply] pl_cli_ip value");

  printf("---- END INVALID TREN TESTS ----\n");

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
int test_invalid_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP,
                       uint8_t* SRV_MAC, uint8_t* CLI_MAC)
{
  const char* UNAME = "ThisIsNotReallyAKnownUsername";

  // Perform TREQ/TACK handshake first to create context in server ctable
  ot_pkt* reply_pkt = ot_pkt_create();
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC) < 0)
  {
    printf("[FAILED] [invalid tren tack] failed to establish TREQ/TACK handshake with server\n");
    return 1;
  } 

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);

  printf("---- BEGIN INVALID CPULL TESTS ----\n");

  // Send a CPULL request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create();
  test_cpull_send(&reply_pkt, UNAME, PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC); 
  EXPECT(reply_pkt != NULL, "[invalid cinv reply] recv cinv from server");

  // Build parse table from possible CINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing

  // Check expected CINV reply with CPULL input
  ot_cli_state_t* expected_cinv = ht_get(parse_table, "PL_STATE");
  EXPECT(expected_cinv != NULL, "[invalid cinv reply] pl_state presence");
  EXPECT(*expected_cinv == CINV, "[invalid cinv reply] pl_state value");


  // Check expected srv ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[invalid cinv reply] pl_srv_ip presence");
  EXPECT(*expected_srv_ip == SRV_IP, "[invalid cpull reply] pl_srv_ip value");

  // Check expected cli ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[invalid cinv reply] pl_cli_ip presence");
  EXPECT(*expected_cli_ip == CLI_IP, "[invalid cinv reply] pl_cli_ip value");

  // Check expected uname
  const char* expected_uname = ht_get(parse_table, "PL_UNAME");
  EXPECT(expected_uname != NULL, "[invalid cinv reply] pl_uname presence");
  EXPECT(strcmp(expected_uname, UNAME) == 0, "[invalid cinv reply] pl_uname value");

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
int test_unknown_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, 
                      uint8_t* SRV_MAC, uint8_t* CLI_MAC)
{
  // No TREQ/TACK handshake here...
  
  printf("---- BEGIN UNKNOWN TREN TESTS ----\n");

  ot_pkt* reply_pkt = ot_pkt_create();

  // Send a TREN request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create();
  test_tren_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC); //<< we now use the debug cli mac
  EXPECT(reply_pkt != NULL, "[unknown tinv reply] recv tinv from server");

  // Build parse table from possible TINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing
  
  // Check expected TINV reply with TREN input
  ot_cli_state_t* expected_tinv = ht_get(parse_table, "PL_STATE");
  EXPECT(expected_tinv != NULL, "[unknown tinv reply] pl_state presence");
  EXPECT(*expected_tinv == TINV, "[unknown tinv reply] pl_state value");

  // Check expected srv ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[unknown tinv reply] pl_srv_ip presence");
  EXPECT(*expected_srv_ip == SRV_IP, "[unknown tinv reply] pl_srv_ip value");
  
  // Check expected cli ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[unknown tren reply] pl_cli_ip presence");
  EXPECT(*expected_cli_ip == CLI_IP, "[unknown tren reply] pl_cli_ip value");

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
int test_unknown_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP,
                       uint8_t* SRV_MAC, uint8_t* CLI_MAC)
{
  const char* UNAME = "ThisUsernameWouldntPassAnyway";

  // No TACK/TREQ handshake

  printf("---- BEGIN UNKNOWN CPULL TESTS ----\n");

  // Send a CPULL request to server and deserialize reply pkt 
  ot_pkt* reply_pkt = ot_pkt_create();
  test_cpull_send(&reply_pkt, UNAME, PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC); 
  EXPECT(reply_pkt != NULL, "[unknown cinv reply] recv cinv from server");

  // Build parse table from possible CINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing

  // Check expected CINV reply with CPULL input
  ot_cli_state_t* expected_cinv = ht_get(parse_table, "PL_STATE");
  EXPECT(expected_cinv != NULL, "[unknown cpull reply] pl_state presence");
  EXPECT(*expected_cinv == CINV, "[unknown cpull reply] pl_state value");


  // Check expected srv ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[unknown cpull reply] pl_srv_ip presence");
  EXPECT(*expected_srv_ip == SRV_IP, "[unknown cpull reply] pl_srv_ip value");

  // Check expected cli ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[unknown cpull reply] pl_cli_ip presence");
  EXPECT(*expected_cli_ip == CLI_IP, "[unknown cpull reply] pl_cli_ip value");

  // Check expected uname
  const char* expected_uname = ht_get(parse_table, "PL_UNAME");
  EXPECT(expected_uname != NULL, "[unknown cpull reply] pl_uname presence");
  EXPECT(strcmp(expected_uname, UNAME) == 0, "[unknown cpull reply] pl_uname value");

  printf("---- END UNKNOWN CPULL TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TPRV pkt
  ot_pkt_destroy(&reply_pkt);

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
  uint8_t pl_state_type = (uint8_t)PL_STATE; //<< state to indicate that we are sending a TREQ packet
  uint8_t pl_state_value = (uint8_t)TREQ; 
  uint8_t pl_state_vlen = (uint8_t)sizeof(pl_state_value);

  ot_payload* pl_state_payload = ot_payload_create(pl_state_type, &pl_state_value, pl_state_vlen);

  // Specify TREQ cli_ip payload 
  uint8_t pl_cli_ip_type = (uint8_t)PL_CLI_IP;
  uint32_t pl_cli_ip_value = CLI_IP;
  uint8_t pl_cli_ip_vlen = (uint8_t)sizeof(pl_cli_ip_value);

  ot_payload* pl_cli_ip_payload = ot_payload_create(pl_cli_ip_type, &pl_cli_ip_value, pl_cli_ip_vlen);

  // Specify TREQ cli_mac payload
  // pl_create(PL_CLI_MAC, MAC*, sizeof(MAC))

  uint8_t pl_cli_mac_type = (uint8_t)PL_CLI_MAC;
  uint8_t pl_cli_mac_value[6] = {0}; 

  memcpy(pl_cli_mac_value, cli_mac, 6);

  uint8_t pl_cli_mac_vlen = (uint8_t)sizeof(cli_mac);

  ot_payload* pl_cli_mac_payload = ot_payload_create(pl_cli_mac_type, &pl_cli_mac_value, pl_cli_mac_vlen);

  // Create payload list in TREQ pkt
  treq_pkt->payload = ot_payload_append(treq_pkt->payload, pl_state_payload);
  treq_pkt->payload = ot_payload_append(treq_pkt->payload, pl_cli_ip_payload);
  treq_pkt->payload = ot_payload_append(treq_pkt->payload, pl_cli_mac_payload);

  // Serialize TREQ pkt
  ssize_t bytes_serialized = 0;
  uint8_t buf[2048] = {0xff}; //<< pre-set with 0xFF terminator
  if ( (bytes_serialized = ot_pkt_serialize(treq_pkt, buf, sizeof buf)) < 0) 
  {
    ++tests_failed;
    printf("serialization failed\n");
    return -1;
  } 
  
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

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } 

  // Send the serialized TREQ to server
  send(sockfd, buf, bytes_serialized, 0);

  ssize_t bytes_received;
  // Wait for reply
  if ((bytes_received = read(sockfd, buf, sizeof buf)) < 0) 
  {
    perror("read failed");
    ++tests_failed;
    return -1;
  } 

  memset(&buf[bytes_received], 0xff, sizeof(buf) - bytes_received);

  // Finally, deserialize reply
  if (ot_pkt_deserialize(*reply_pkt, buf, sizeof buf) < 0) 
  {
    printf("deserialization failed\n");
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } 

  // Free the pkt we used for sending the TREQ
  ot_pkt_destroy(&treq_pkt);

  close(sockfd);

  return 1;
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
    ++tests_failed;
    return -1;
  } 
  
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

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } 

  // Send the serialized TREN to server
  send(sockfd, buf, bytes_serialized, 0);
  // Wait for reply
  if (read(sockfd, buf, sizeof buf) < 0) 
  {
    perror("read failed");
    ++tests_failed;
    return -1;
  } 

  // Finally, deserialize reply
  if (ot_pkt_deserialize(*reply_pkt, buf, sizeof buf) < 0) 
  {
    ++tests_failed;
    return -1;
  } 

  // Free the pkt we used for sending the TREN pkt
  ot_pkt_destroy(&tren_pkt);

  close(sockfd);

  return 0;
}

static int test_cpull_send(ot_pkt** reply_pkt, const char* uname, const int PORT, 
                           uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac) 
{
  // Build CPULL header 
  ot_pkt_header cpull_hd = ot_pkt_header_create(SRV_IP, CLI_IP,  srv_mac, cli_mac, DEF_EXP_TIME, DEF_EXP_TIME*0.75);

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
    ++tests_failed;
    return -1;
  } 
  
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

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    ++tests_failed;
    return -1;
  } 

  // Send the serialized CPULL to server
  send(sockfd, buf, bytes_serialized, 0);
  // Wait for reply
  if (read(sockfd, buf, sizeof buf) < 0) 
  {
    perror("read failed");
    ++tests_failed;
    return -1;
  } 

  // Finally, deserialize reply
  if (ot_pkt_deserialize(*reply_pkt, buf, sizeof buf) < 0) 
  {
    ++tests_failed;
    return -1;
  } 

  // Free the pkt we used for sending the CPULL pkt
  ot_pkt_destroy(&cpull_pkt);

  close(sockfd);

  return 0;
}

