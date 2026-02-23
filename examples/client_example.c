#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "ot_packet.h"
#include "ot_client.h"
#include "ot_context.h"

int main(void) 
{
  printf("Otter Client Demo (pre-release)\n\n");
  printf("use existing account: uname=rommelrond psk=WowHello\n\n\n");

  uint32_t srv_ip = inet_addr("127.0.0.1"); //<< assuming locally hosted Otter server

  uint32_t dummy_cli_ip = inet_addr("127.0.0.1");
  uint8_t dummy_cli_mac[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  uint8_t empty_mac[6] = {0,0,0,0,0,0};

  ot_pkt_header hd = ot_pkt_header_create(srv_ip, dummy_cli_ip, empty_mac, dummy_cli_mac, 0, 0);
  ot_cli_ctx cc = ot_cli_ctx_create(hd, 0, 0);

  if (!ot_cli_auth(&cc)) 
  {
    //char ipbuf[INET_ADDRSTRLEN] = {0};
    //fprintf(stderr, "ot_cli_auth error: failed to authenticate with srv=%s\n",
           // inet_ntop(AF_INET, &srv_ip, (char*)ipbuf, INET_ADDRSTRLEN));
    return 1;
  }

  char buf[2048] = {0};
  char* psk_buf = NULL;

  for (;;) 
  {
    printf("enter uname: ");

    fgets(buf, sizeof buf, stdin);
    buf[strcspn(buf, "\n")] = '\0';

    if (!ot_cli_pull(cc, buf, &psk_buf)) 
    {
      printf("user %s not found in database\n", buf);
      continue;
    } else {
      printf("psk: %s\n", psk_buf);
    }

    free(psk_buf);
    psk_buf = NULL;
  }
  return 0;
}
