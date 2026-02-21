//////////////////////////////////////////////////////////////////////////////
// file: test_client.c
//
// Tests the Otter client API in authenticating and pulling information from an existing
// server
//
// The simple way of testing the functionality of the API is to examine the client context and the resulting
// changes to the client context or through the changed variables.
//////////////////////////////////////////////////////////////////////////////

#include "testing_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "ot_context.h"
#include "ot_client.h"
#include "ot_packet.h"

int tests_failed = 0;

int main(void) 
{
  // Fixture variables
  const char* UNAME = "rommelrond";
  const uint32_t SRV_IP = inet_addr("127.0.0.1");
  const uint32_t CLI_IP = inet_addr("127.0.0.1");
  uint8_t CLI_MAC[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  uint8_t DBG_CLI_MAC[6] = {0x00, 0x00, 0x00, 0xab, 0xab, 0xff};
  uint8_t EMPTY_MAC[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
  ot_pkt_header hd = ot_pkt_header_create(SRV_IP, CLI_IP, EMPTY_MAC, DBG_CLI_MAC, 0, 0);
  ot_cli_ctx cli_ctx = ot_cli_ctx_create(hd, 0, 0);

  printf("\n----BEGIN CLIENT OPERATION TESTS----\n");

  ot_cli_auth(&cli_ctx);
  EXPECT(memcmp(cli_ctx.header.srv_mac, EMPTY_MAC, 6) != 0, "[ot cli auth] non-empty srv mac");
  EXPECT(cli_ctx.header.exp_time != 0, "[ot cli auth] new exp time");
  EXPECT(cli_ctx.header.renew_time != 0, "[ot cli auth] new renew time");

  // Wait for expiry
  printf("[ot cli] waiting for initial client to reach renewal...\n");
  sleep(17);
  printf("DONE\n");
  ot_cli_renew(&cli_ctx);

  printf("[ot cli] verifying non-expiry...\n");
  sleep(4); //<< 21 seconds should have passed

  char psk_buf[256] = {0};
  ot_cli_pull(cli_ctx, UNAME, psk_buf);
  EXPECT(strlen(psk_buf) != 0, "[ot cli renew] cpull+renewal test");

  printf("\n----END CLIENT OPERATION TESTS----\n");


  if (tests_failed > 0) return 1;

  return 0;
}



