/* Created by Rommel John H. Ronduen (rommel.ronduen2244@gmail.com)
*
* file: test_srv.c
*
* Contains unit tests for Otter server functionalities.
*/

#include "ot_server.h"
#include "testing_utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

int tests_failed = 0;

/*
// Frees a server context and its ctable to memory
void ot_srv_ctx_destroy(ot_srv_ctx** os);

// Runs the server loop
void ot_srv_run(); //<< insert the packet logic here
*/

int main(void) 
{
  int TEST_PORT = 7192;

  uint8_t TEST_BYTES_SRV_MAC[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  uint8_t TEST_BYTES_CLI_MAC[6] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa};

  const char* TEST_STR_SRV_MAC = "aa:bb:cc:dd:ee:ff";
  const char* TEST_STR_CLI_MAC = "ff:ee:dd:cc:bb:aa";

  uint64_t TEST_EXP_TIME = 1770967837;
  uint64_t TEST_RENEW_TIME = 1770967837 - 3600;

  uint32_t TEST_SRV_IP = inet_addr("192.168.100.1");
  uint32_t TEST_CLI_IP = inet_addr("1.100.168.192");

  ot_pkt_header TEST_HEADER = ot_pkt_header_create(TEST_SRV_IP, TEST_CLI_IP,  TEST_BYTES_SRV_MAC, TEST_BYTES_CLI_MAC, TEST_EXP_TIME, TEST_RENEW_TIME);
  ot_cli_state_t TEST_STATE = TACK;

  printf("---- BEGIN SRV TESTS ----\n");


  // Client context creation
  ot_cli_ctx* cli_ctx_res = ot_cli_ctx_create(TEST_HEADER, TEST_STATE);
  EXPECT(memcmp(&(cli_ctx_res->header), &TEST_HEADER, sizeof(ot_pkt_header)) == 0, "[cli ctx] header initialization");
  EXPECT(cli_ctx_res->state == TEST_STATE, "[cli ctx] state initialization");

  // Server context creation
  ot_srv_ctx* srv_ctx_res = ot_srv_ctx_create(TEST_PORT, TEST_SRV_IP, TEST_BYTES_SRV_MAC);
  EXPECT(srv_ctx_res->port == TEST_PORT, "[srv ctx] port initialization");
  EXPECT(srv_ctx_res->sockfd == 0, "[srv ctx] sockfd initialization");

  EXPECT(srv_ctx_res->ctable != NULL, "[cli ctx] ctable initialization");
  EXPECT(srv_ctx_res->otable != NULL, "[cli ctx] otable initialization");

  EXPECT(srv_ctx_res->srv_ip == TEST_SRV_IP, "[cli ctx] srv ip initialization");
  EXPECT(memcmp(srv_ctx_res->srv_mac, TEST_BYTES_SRV_MAC, 6) == 0, "[cli ctx] srv mac initialization");

  // ctable functionality 
  const char* cli_ctx_set_res = ot_srv_set_cli_ctx(srv_ctx_res, TEST_STR_SRV_MAC, *cli_ctx_res);
  EXPECT(cli_ctx_set_res == TEST_STR_SRV_MAC, "[ctable] set functionality");

  ot_cli_ctx cli_ctx_get_res = ot_srv_get_cli_ctx(srv_ctx_res, TEST_STR_SRV_MAC);
  EXPECT(memcmp(&cli_ctx_get_res, cli_ctx_res, sizeof(ot_cli_ctx)) == 0, "[ctable] get functionality");

  // Destructor tests
  ot_srv_ctx_destroy(&srv_ctx_res);
  EXPECT(srv_ctx_res == NULL, "[srv ctx destructor] nullity test");

  // Runtime tests

  // TODO: add the runtime tests here after finishing the payload adjustments and stuff

  printf("---- END SRV TESTS ----\n");

  if (tests_failed > 0) return 1;
  return 0;
}
