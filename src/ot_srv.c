#include <stdbool.h>
#include <assert.h> // Required for assert

#include <arpa/inet.h>

#include "ot_server.h"

int main(void) 
{
  uint8_t srv_mac[6] = {0x12,0x23,0x44,0x55,0x66,0x77};
  uint32_t srv_ip = inet_addr("127.0.0.1");

  ot_srv_run(srv_ip, srv_mac);

  return 0;
}
