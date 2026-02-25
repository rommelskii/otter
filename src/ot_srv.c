/* 
 * Otter Protocol (C) Rommel John Ronduen 2026
 *
 * file: ot_srv.c
 *
 * Runs an otserver based on provided server metadata in the main entrypoint
 *
 * Note: DO NOT MODIFY THIS PROGRAM. this function is also utilized for the run_tests.sh script. 
 *       i'll modify this when i get better at software design and maybe when i get employed lol
 */

// Project Headers
#include "ot_server.h"

// Standard Library Headers
#include <stdbool.h>
#include <arpa/inet.h>

int main(void) 
{
  // Change these accordingly to the device
  // todo: provide api for extracting these from device itself
  uint8_t srv_mac[6] = {0x12,0x23,0x44,0x55,0x66,0x77};
  uint32_t srv_ip = inet_addr("127.0.0.1"); //<< just operate on all interfaces for simplicity (make the unit tests happy)

  const char* path = "/home/mels/projects/otter/tests/files/test.ot";

  // Start server
  ot_srv_run(srv_ip, srv_mac, path);

  return 0;
}
