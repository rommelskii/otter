#include <stdbool.h>
#include <arpa/inet.h>
#include "ot_server.h"

int main(void) 
{
  // Change these accordingly to the device
  // todo: provide api for extracting these from device itself
  uint8_t srv_mac[6] = {0x12,0x23,0x44,0x55,0x66,0x77};
  uint32_t srv_ip = inet_addr("192.168.100.76");

  // Start server
  ot_srv_run(srv_ip, srv_mac);

  return 0;
}
