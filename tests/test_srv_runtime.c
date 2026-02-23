/* Otter Protocol (C) Rommel John Ronduen 2026
 *
 * Contains test harnesses for testing the server runtime. 
 *
 * Notes: 
 * 1. This test suite is required by the run_tests.sh script to test the Otter server functionality. 
 * 2. The "special MAC" is the client MAC 00:00:00:ab:ab:ff that induces a 20-second expiry time
 *    on the serverside for testing purposes.
 *
 * Unit tests:
 * - test_treq: 
 *    send TREQ to srv and expect TACK. Fulfills the TREQ/TACK handshake
 * - test_tren: 
 *    perform TREQ/TACK hdsk with special MAC, wait until renew time, then send TREN and 
 *    expect TPRV
 * - test_cpull 
 *    perform TREQ/TACK hdsk, send CPULL with valid uname, expect CPUSH with corresponding 
 *    psk to uname
 * - test_expired_tren:
 *    perform TREQ/TACK hdsk with special MAC, wait until client expires (21 seconds), then send
 *    TREN and expect TINV reply
 * - test_expired_cpull:
 *    perform TREQ/TACK hdsk with special MAC, wait until client expires (21 seconds), then send
 *    CPULL and expect CINV reply
 * - test_invalid_tren:
 *    attempts TREN but not within renewal bounds. Expects TINV reply
 * - test_invalid_cpull:
 *    attempts CPULL but the uname does not have a corresponding entry in the serverside database.
 *    Expects CINV reply
 * - test_unknown_tren:
 *    attempts TREN with no preceding TREQ/TACK hdsk. Expects TINV reply
 * - test_unknown_cpull:
 *    attempts CPULL with no preceding TREQ/TACK hdsk. Expects CINV reply
 */

// 
// Project Headers
//
#include "ot_server.h"
#include "ot_packet.h"
#include "testing_utils.h"

// 
// Standard Library Headers
//
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <assert.h>

// 
// Global Variables
//
int tests_failed = 0; //<< for EXPECT()

//
// Unit Test Prototypes
//
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


//
// Internal Packet Builders
// Note: These are for structuring reply packets under the appropriate unit test
//
static int test_treq_send(ot_pkt** reply_pkt, const int PORT, 
                          uint32_t SRV_IP, uint32_t CLI_IP, 
                          uint8_t* srv_mac, uint8_t* cli_mac);

static int test_tren_send(ot_pkt** reply_pkt, const int PORT, 
                          uint32_t SRV_IP, uint32_t CLI_IP, 
                          uint8_t* srv_mac, uint8_t* cli_mac);

static int test_cpull_send(ot_pkt** reply_pkt, const char* uname, 
                           const int PORT, uint32_t SRV_IP,
                           uint32_t CLI_IP, uint8_t* srv_mac, 
                           uint8_t* cli_mac);

static int test_expired_tren_send(ot_pkt** reply_pkt, const int PORT, 
                                  uint32_t SRV_IP, uint32_t CLI_IP, 
                                  uint8_t* srv_mac, uint8_t* cli_mac);

static int test_expired_cpull_send(ot_pkt** reply_pkt, const char* uname, 
                                   const int PORT, uint32_t SRV_IP, 
                                   uint32_t CLI_IP, uint8_t* srv_mac, 
                                   uint8_t* cli_mac);

static int test_invalid_tren_send(ot_pkt** reply_pkt, const int PORT,
                                  uint32_t SRV_IP, uint32_t CLI_IP, 
                                  uint8_t* srv_mac, uint8_t* cli_mac);

static int test_invalid_cpull_send(ot_pkt** reply_pkt, const char* uname, 
                                   const int PORT, uint32_t SRV_IP, 
                                   uint32_t CLI_IP, uint8_t* srv_mac, 
                                   uint8_t* cli_mac);


//
// Test Suite Entrypoint
//
int main(void) 
{
  // Local IPs for now
  const uint32_t SRV_IP = inet_addr("127.0.0.1");
  const uint32_t CLI_IP = inet_addr("127.0.0.1");

  // Test MACs
  uint8_t SRV_MAC[6] = {0x12,0x23,0x44,0x55,0x66,0x77};
  uint8_t CLI_MAC_TREQ[6] = {0x01,0xee,0xdd,0xcc,0xbb,0xaa};
  uint8_t CLI_MAC_CPULL[6] = {0x03,0xee,0xdd,0xcc,0xbb,0xaa};
  uint8_t INV_CLI_MAC_CPULL[6] = {0x04,0xee,0xdd,0xcc,0xbb,0xaa};
  uint8_t UNK_CLI_MAC_TREN[6] = {0x05,0xee,0xdd,0xcc,0xbb,0xaa};
  uint8_t UNK_CLI_MAC_CPULL[6] = {0x06,0xee,0xdd,0xcc,0xbb,0xaa};
  uint8_t DBG_CLI_MAC[6] = {0x00, 0x00, 0x00, 0xab, 0xab, 0xff};

  sleep(2); //<< just in case server hasn't run yet

  // Normal tests
  if (test_treq(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC_TREQ) != 0) goto check;
  if (test_tren(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) != 0) goto check;
  if (test_cpull(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC_CPULL) != 0) goto check;

  // Error-handling tests
  if (test_invalid_tren(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) != 0) goto check;
  if (test_invalid_cpull(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, INV_CLI_MAC_CPULL) != 0) goto check;

  // Expired client tests
  if (test_expired_tren(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) != 0) goto check;
  if (test_expired_cpull(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) != 0) goto check;

  // Unknown client tests
  if (test_unknown_tren(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, UNK_CLI_MAC_TREN) != 0) goto check;
  if (test_unknown_cpull(DEF_PORT, SRV_IP, CLI_IP, SRV_MAC, UNK_CLI_MAC_CPULL) != 0) goto check;

check:
  if (tests_failed > 0) 
  {
    printf("[test srv runtime] one or more tests have failed! Exiting...\n");
    return 1;
  }

  printf("[test srv runtime] all tests passed!\n");

  return 0;
}

//
// Unit Test: test_treq
//
int test_treq(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP,
              uint8_t* SRV_MAC, uint8_t* CLI_MAC)
{
  // Send TREQ to server
  ot_pkt* reply_pkt = ot_pkt_create(); //<< allocate memory for the server reply packet
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC) < 0) 
  {
    fprintf(stderr, "[test_treq] failed to send treq pkt to server\n");
    return -1;
  } 
  
  printf("\n---- BEGIN TREQ TESTS ----\n");

  // Build parse table from reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Check expected TACK reply with TREQ input
  uint8_t* raw_expected_tack = ht_get(parse_table, "PL_STATE");
  EXPECT(raw_expected_tack != NULL, "[tack reply] pl_state presence");
  if (raw_expected_tack == NULL) return -1;
  ot_cli_state_t expected_tack = *raw_expected_tack;
  EXPECT(expected_tack == TACK, "[treq reply] reply type (TACK) check");

  // Check expected srv ip 
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[tack reply] pl_srv_ip presence");
  if (expected_srv_ip == NULL) return -1;
  EXPECT(*expected_srv_ip == SRV_IP, "[treq reply] srv ip check");

  // Check expected srv mac 
  uint8_t* expected_srv_mac = ht_get(parse_table, "PL_SRV_MAC");
  EXPECT(expected_srv_mac != NULL, "[tack reply] pl_srv_mac presence");
  if (expected_srv_mac == NULL) return -1;
  EXPECT(memcmp(expected_srv_mac, SRV_MAC, 6) == 0, "[tack reply] srv mac check");

  // Check expected cli ip 
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[tack reply] pl_cli_ip presence");
  if (expected_cli_ip == NULL) return -1;
  EXPECT(*expected_cli_ip == CLI_IP, "[treq reply] cli ip check");

  // Check expected expiry time
  uint32_t* expected_exp_time = ht_get(parse_table, "PL_ETIME");
  EXPECT(expected_exp_time != NULL, "[tack reply] pl_etime presence");
  if (expected_exp_time == NULL) return -1;
  EXPECT(*expected_exp_time == DEF_EXP_TIME, "[tack reply] pl_etime value");

  // Check expected renewal time
  uint32_t* expected_renew_time = ht_get(parse_table, "PL_RTIME");
  EXPECT(expected_exp_time != NULL, "[tack reply] pl_rtime presence");
  if (expected_renew_time == NULL) return -1;
  EXPECT(*expected_renew_time == DEF_EXP_TIME*0.75, "[tack reply] pl_rtime value");

  printf("---- END TREQ TESTS ----\n");

  // Perform cleanup
  ot_pkt_destroy(&reply_pkt);
  ht_destroy(parse_table);
  parse_table = NULL;

  return 0;
}

int test_tren(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP,
              uint8_t* SRV_MAC, uint8_t* DBG_CLI_MAC)
{
  printf("---- BEGIN TREN TESTS ----\n");

  // Perform TREQ/TACK hdsk with server first
  ot_pkt* reply_pkt = ot_pkt_create();
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) < 0) 
  {
    fprintf(stderr, "[test_tren] failed to send treq pkt to server for treq/tack hdsk\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  } 

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);
  
  printf("[tren test] waiting 16 seconds to hit renew window...\n");
  // Wait 16+1 seconds (75% of 20 seconds) to reach renewal window
  sleep(17);
  printf("DONE\n");

  // Send a TREN request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create(); //<< reallocate memory after TREQ/TACK hdsk
  if (test_tren_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) < 0) 
  {
    fprintf(stderr, "test_tren_send: failed to deserialize reply from srv\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  }

  // Build parse table from possible TPRV reply pkt payloads
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_pkt->payload);

  // Start payload parsing
  // Check expected TACK reply with TREQ input
  uint8_t* raw_expected_tprv = ht_get(parse_table, "PL_STATE");
  EXPECT(raw_expected_tprv != NULL, "[tprv reply] pl_state presence");
  if (raw_expected_tprv == NULL) return -1;
  ot_cli_state_t expected_tprv = *raw_expected_tprv; 
  EXPECT(expected_tprv == TPRV, "[tprv reply] pl_state value check");

  // Check expected srv ip (should be same as the one sent in the header of the TREN pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[tprv reply] pl_srv_ip presence");
  if (expected_srv_ip == NULL) return -1;
  EXPECT(*expected_srv_ip == SRV_IP, "[tprv reply] pl_srv_ip value");

  // Check expected cli ip
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[tprv reply] pl_cli_ip presence");
  if (expected_cli_ip == NULL) return -1;
  EXPECT(*expected_cli_ip == reply_pkt->header.cli_ip, "[tprv reply] pl_cli_ip value");

  // Check expected expiry time
  uint32_t* expected_exp_time = ht_get(parse_table, "PL_ETIME");
  EXPECT(expected_exp_time != NULL, "[tprv reply] pl_etime presence");
  if (expected_exp_time == NULL) return -1;
  EXPECT(*expected_exp_time == DEF_EXP_TIME, "[tprv reply] pl_etime value");

  // Check expected expiry time
  uint32_t* expected_renew_time = ht_get(parse_table, "PL_RTIME");
  EXPECT(expected_renew_time != NULL, "[tprv reply] pl_rtime presence");
  if (expected_renew_time == NULL) return -1;
  EXPECT(*expected_renew_time == DEF_EXP_TIME*0.75, "[tprv reply] pl_rtime value");

  printf("---- END TREN TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TPRV pkt
  ot_pkt_destroy(&reply_pkt);
  ht_destroy(parse_table);
  parse_table = NULL;

  return 0;
}

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
    fprintf(stderr, "[test_cpull] failed to send treq pkt to server for treq/tack hdsk\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  } 

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);

  // Send a CPULL request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create();
  if (test_cpull_send(&reply_pkt, UNAME, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac) < 0) 
  {
    fprintf(stderr, "test_cpull_send: failed to deserialize reply from srv\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  }

  // Build parse table from possible CPUSH reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Check expected CPUSH reply 
  printf("[cpull reply] checking for PL_STATE entry in parse table... ");
  uint8_t* raw_expected_cpush = ht_get(parse_table, "PL_STATE");
  EXPECT(raw_expected_cpush != NULL, "[cpush reply] pl_state presence");
  if (raw_expected_cpush == NULL) return -1;
  ot_cli_state_t expected_cpush = *raw_expected_cpush;
  EXPECT(expected_cpush == CPUSH, "[cpush reply] pl_state value");

  // Check expected srv ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[cpush reply] pl_srv_ip presence");
  if (expected_srv_ip == NULL) return -1;
  EXPECT(*expected_srv_ip == SRV_IP, "[cpush reply] pl_srv_ip value");

  // Check expected cli ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[cpush reply] pl_cli_ip presence");
  if (expected_cli_ip == NULL) return -1;
  EXPECT(*expected_cli_ip == CLI_IP, "[cpush reply] pl_cli_ip value");

  // Check expected uname
  const char* expected_uname = ht_get(parse_table, "PL_UNAME");
  EXPECT(expected_uname != NULL, "[cpush reply] pl_uname presence");
  if (expected_uname == NULL) return -1;
  EXPECT(strcmp(expected_uname, UNAME) == 0, "[cpush reply] pl_uname value");

  // Check expected PSK
  const char* expected_psk = ht_get(parse_table, "PL_PSK");
  EXPECT(expected_psk != NULL, "[cpush reply] pl_psk presence");
  if (expected_psk == NULL) return -1;
  EXPECT(strcmp(expected_psk, PSK) == 0, "[cpush reply] pl_psk value");

  printf("---- END CPULL TESTS ----\n");

  // Finally clean up reply pkt used for receiving the CPUSH pkt
  ot_pkt_destroy(&reply_pkt);
  ht_destroy(parse_table);
  parse_table = NULL;

  return 0;
}

int test_expired_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, 
                      uint8_t* SRV_MAC, uint8_t* DBG_CLI_MAC)
{
  printf("---- BEGIN EXPIRED TREN TESTS ----\n");
  // Perform TREQ/TACK handshake first to create context in server ctable
  ot_pkt* reply_pkt = ot_pkt_create();
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) < 0) 
  {
    fprintf(stderr, "[test_expired_tren] failed to send treq pkt to server for treq/tack hdsk\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  } 

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);

  printf("[test_expired_tren] waiting 21 seconds for client to expire...\n");
  // Wait for client context to expire
  sleep(21);
  printf("DONE\n");
  

  // Send a TREN request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create();
  if (test_tren_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) < 0) 
  {
    fprintf(stderr, "test_tren_send: failed to deserialize reply from srv\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  }

  // Build parse table from possible TINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing
  // Check expected TINV reply with TREN input
  uint8_t* raw_expected_tinv = ht_get(parse_table, "PL_STATE");
  EXPECT(raw_expected_tinv != NULL, "[expired tinv reply] pl_state presence");
  if (raw_expected_tinv == NULL) return -1;
  ot_cli_state_t expected_tinv = *raw_expected_tinv;
  EXPECT(expected_tinv == TINV, "[expired tinv reply] pl_state value");

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
  ht_destroy(parse_table);
  parse_table = NULL;

  return 0;
}

int test_expired_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP,
                       uint8_t* SRV_MAC, uint8_t* DBG_CLI_MAC)
{
  const char* UNAME = "rommelrond";
  const char* PSK = "WowHello";

  // Perform TREQ/TACK handshake first to create context in server ctable
  ot_pkt* reply_pkt = ot_pkt_create();
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) < 0)
  {
    fprintf(stderr, "[test_expired_cpull] failed to send treq pkt to server for treq/tack hdsk\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  } 

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);

  // Wait until client context expires
  sleep(21);

  printf("---- BEGIN EXPIRED CPULL TESTS ----\n");

  // Send a CPULL request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create();
  if (test_cpull_send(&reply_pkt, UNAME, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) < 0) 
  {
    fprintf(stderr, "test_cpull_send: failed to deserialize reply from srv\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  }

  // Build parse table from possible CINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing

  // Check expected CINV reply with CPULL input
  uint8_t* raw_expected_cinv = ht_get(parse_table, "PL_STATE");
  EXPECT(raw_expected_cinv != NULL, "[expired cinv reply] pl_state presence");
  if (raw_expected_cinv == NULL) return -1;
  ot_cli_state_t expected_cinv = *raw_expected_cinv;
  EXPECT(expected_cinv == CINV, "[expired cinv reply] pl_state value");


  // Check expected srv ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[expired cinv reply] pl_srv_ip presence");
  if (expected_srv_ip == NULL) return -1;
  EXPECT(*expected_srv_ip == SRV_IP, "[expired cinv reply] pl_srv_ip value");

  // Check expected cli ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[expired cinv reply] pl_cli_ip presence");
  if (expected_cli_ip == NULL) return -1;
  EXPECT(*expected_cli_ip == CLI_IP, "[expired cinv reply] pl_cli_ip value");


  // Check expected uname
  const char* expected_uname = ht_get(parse_table, "PL_UNAME");
  EXPECT(expected_uname != NULL, "[expired cinv reply] pl_uname presence");
  if (expected_uname == NULL) return -1;
  EXPECT(strcmp(expected_uname, UNAME) == 0, "[expired cinv reply] pl_uname value");

  printf("---- END EXPIRED CPULL TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TPRV pkt
  ot_pkt_destroy(&reply_pkt);
  ht_destroy(parse_table);
  parse_table = NULL;

  return 0;
}

int test_invalid_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, 
                      uint8_t* SRV_MAC, uint8_t* DBG_CLI_MAC)
{
  // Perform TREQ/TACK handshake first to create context in server ctable
  ot_pkt* reply_pkt = ot_pkt_create();
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) < 0) 
  {
    fprintf(stderr, "[test_invalid_tren] failed to send treq pkt to server for treq/tack hdsk\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  } 

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);
  
  printf("---- BEGIN INVALID TREN TESTS ----\n");

  // Send a TREN request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create();
  if (test_tren_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, DBG_CLI_MAC) < 0) 
  {
    fprintf(stderr, "test_invalid_tren: failed to deserialize reply from srv\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  }

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
  uint8_t* raw_expected_tinv = ht_get(parse_table, "PL_STATE");
  EXPECT(raw_expected_tinv != NULL, "[invalid tinv reply] pl_state presence");
  if (raw_expected_tinv == NULL) return -1;
  ot_cli_state_t expected_tinv = *raw_expected_tinv;
  EXPECT(expected_tinv == TINV, "[invalid tinv reply] pl_state value");

  // Check expected srv ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[invalid tinv reply] pl_srv_ip presence");
  if (expected_srv_ip == NULL) return -1;
  EXPECT(*expected_srv_ip == SRV_IP, "[invalid tinv reply] srv ip check");
  
  // Check expected cli ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[invalid tinv reply] pl_cli_ip presence");
  if (expected_cli_ip == NULL) return -1;
  EXPECT(*expected_cli_ip == CLI_IP, "[invalid tinv reply] pl_cli_ip value");

  printf("---- END INVALID TREN TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TINV pkt
  ot_pkt_destroy(&reply_pkt);
  ht_destroy(parse_table);
  parse_table = NULL;

  return 0;
}

int test_invalid_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP,
                       uint8_t* SRV_MAC, uint8_t* CLI_MAC)
{
  const char* UNAME = "ThisIsNotReallyAKnownUsername";

  // Perform TREQ/TACK handshake first to create context in server ctable
  ot_pkt* reply_pkt = ot_pkt_create();
  if (test_treq_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC) < 0)
  {
    fprintf(stderr, "[test_invalid_cpull] failed to send treq pkt to server for treq/tack hdsk\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  } 

  // Clean up reply pkt from TREQ/TACK handshake
  ot_pkt_destroy(&reply_pkt);

  printf("---- BEGIN INVALID CPULL TESTS ----\n");

  // Send a CPULL request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create();
  if (test_cpull_send(&reply_pkt, UNAME, PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC) < 0) 
  {
    fprintf(stderr, "test_cpull_send: failed to deserialize reply from srv\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  }

  // Build parse table from possible CINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing

  // Check expected CINV reply with CPULL input
  uint8_t* raw_expected_cinv = ht_get(parse_table, "PL_STATE");
  EXPECT(raw_expected_cinv != NULL, "[invalid cinv reply] pl_state presence");
  if (raw_expected_cinv == NULL) return -1;
  ot_cli_state_t expected_cinv = *raw_expected_cinv;
  EXPECT(expected_cinv == CINV, "[invalid cinv reply] pl_state value");


  // Check expected srv ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[invalid cinv reply] pl_srv_ip presence");
  if (expected_srv_ip == NULL) return -1;
  EXPECT(*expected_srv_ip == SRV_IP, "[invalid cpull reply] pl_srv_ip value");

  // Check expected cli ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[invalid cinv reply] pl_cli_ip presence");
  if (expected_cli_ip == NULL) return -1;
  EXPECT(*expected_cli_ip == CLI_IP, "[invalid cinv reply] pl_cli_ip value");

  // Check expected uname
  const char* expected_uname = ht_get(parse_table, "PL_UNAME");
  EXPECT(expected_uname != NULL, "[invalid cinv reply] pl_uname presence");
  if (expected_uname == NULL) return -1;
  EXPECT(strcmp(expected_uname, UNAME) == 0, "[invalid cinv reply] pl_uname value");

  printf("---- END INVALID CPULL TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TPRV pkt
  ot_pkt_destroy(&reply_pkt);
  ht_destroy(parse_table);
  parse_table = NULL;

  return 0;
}

int test_unknown_tren(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, 
                      uint8_t* SRV_MAC, uint8_t* CLI_MAC)
{
  // No TREQ/TACK handshake here...
  
  printf("---- BEGIN UNKNOWN TREN TESTS ----\n");

  ot_pkt* reply_pkt = ot_pkt_create();

  // Send a TREN request to server and deserialize reply pkt 
  reply_pkt = ot_pkt_create();
  if (test_tren_send(&reply_pkt, PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC) < 0) 
  {
    fprintf(stderr, "test_unknown_tren: failed to deserialize reply from srv\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  }

  // Build parse table from possible TINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing
  
  // Check expected TINV reply with TREN input
  uint8_t* raw_expected_tinv = ht_get(parse_table, "PL_STATE");
  EXPECT(raw_expected_tinv != NULL, "[unknown tinv reply] pl_state presence");
  if (raw_expected_tinv == NULL) return -1;
  ot_cli_state_t expected_tinv = *raw_expected_tinv;
  EXPECT(expected_tinv == TINV, "[unknown tinv reply] pl_state value");

  // Check expected srv ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[unknown tinv reply] pl_srv_ip presence");
  if (expected_srv_ip == NULL) return -1;
  EXPECT(*expected_srv_ip == SRV_IP, "[unknown tinv reply] pl_srv_ip value");
  
  // Check expected cli ip (should be same as the one sent in the header of the expired TREN pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[unknown tren reply] pl_cli_ip presence");
  if (expected_cli_ip == NULL) return -1;
  EXPECT(*expected_cli_ip == CLI_IP, "[unknown tren reply] pl_cli_ip value");

  printf("---- END UNKNOWN TREN TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TINV pkt
  ot_pkt_destroy(&reply_pkt);
  ht_destroy(parse_table);
  parse_table = NULL;

  return 0;

}

int test_unknown_cpull(const int PORT, uint32_t SRV_IP, uint32_t CLI_IP,
                       uint8_t* SRV_MAC, uint8_t* CLI_MAC)
{
  // No TACK/TREQ handshake

  const char* UNAME = "ThisUsernameWouldntPassAnyway"; //<< this uname does not exist in the serverside db

  printf("---- BEGIN UNKNOWN CPULL TESTS ----\n");

  // Send a CPULL request to server and deserialize reply pkt 
  ot_pkt* reply_pkt = ot_pkt_create();
  if (test_cpull_send(&reply_pkt, UNAME, PORT, SRV_IP, CLI_IP, SRV_MAC, CLI_MAC) < 0) 
  {
    fprintf(stderr, "test_unknown_cpull: failed to deserialize reply from srv\n");
    ot_pkt_destroy(&reply_pkt);
    return -1;
  }


  // Build parse table from possible CINV reply pkt payloads
  ot_payload* reply_head = reply_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing

  // Check expected CINV reply with CPULL input
  uint8_t* raw_expected_cinv = ht_get(parse_table, "PL_STATE");
  EXPECT(raw_expected_cinv != NULL, "[unknown cpull reply] pl_state presence");
  if (raw_expected_cinv == NULL) return -1;
  ot_cli_state_t expected_cinv = *raw_expected_cinv;
  EXPECT(expected_cinv == CINV, "[unknown cpull reply] pl_state value");


  // Check expected srv ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_srv_ip = ht_get(parse_table, "PL_SRV_IP");
  EXPECT(expected_srv_ip != NULL, "[unknown cpull reply] pl_srv_ip presence");
  if (expected_srv_ip == NULL) return -1;
  EXPECT(*expected_srv_ip == SRV_IP, "[unknown cpull reply] pl_srv_ip value");

  // Check expected cli ip (should be same as the one sent in the header of the CPULL pkt)
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  EXPECT(expected_cli_ip != NULL, "[unknown cpull reply] pl_cli_ip presence");
  if (expected_cli_ip == NULL) return -1;
  EXPECT(*expected_cli_ip == CLI_IP, "[unknown cpull reply] pl_cli_ip value");

  // Check expected uname
  const char* expected_uname = ht_get(parse_table, "PL_UNAME");
  EXPECT(expected_uname != NULL, "[unknown cpull reply] pl_uname presence");
  if (expected_uname == NULL) return -1;
  EXPECT(strcmp(expected_uname, UNAME) == 0, "[unknown cpull reply] pl_uname value");

  printf("---- END UNKNOWN CPULL TESTS ----\n");

  // Finally clean up reply pkt used for receiving the TPRV pkt
  ot_pkt_destroy(&reply_pkt);
  ht_destroy(parse_table);
  parse_table = NULL;

  return 0;

}

static int test_treq_send(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac) 
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

