/**************************************************************************************************
* Otter Server: Pre-release
*
* (C) Rommel John Ronduen (rommel.ronduen2244@gmail.com)
* 
* file: ot_server.c
* usage: ./ot_server.c <PATH_TO_OTFILE>
* 
* Contains entrypoint for the server. 
*
* It utilizes the tokenization (tk) and hash table (ht) libraries to load otfiles (.ot files)
* into memory via hash tables for quick lookups. 
**************************************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h> // Required for assert
//
#include <arpa/inet.h>

#include "ht.h" // for creating the credential table
#include "otfile_utils.h" // for otfile_build
#include "ot_packet.h" // for ot pkt stuff
#include "ot_server.h"

int main(void) 
{
  uint8_t srv_mac[6] = {0x12,0x23,0x44,0x55,0x66,0x77};
  uint32_t srv_ip = inet_addr("127.0.0.1");

  ot_srv_run(srv_ip, srv_mac);

  return 0;
}
