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

int main(int argc, char** argv) 
{
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
    return 1;
  }
  
  // Initialize the hash table for storing otfile entries
  struct ht* cred_table = ht_create(16); 

  // Load otfile into memory
  otfile_build(argv[1], &cred_table); 

  printf("Successfully loaded %zu entries from %s.\n", ht_length(cred_table), argv[1]);

  //////////////////////////////////////////////////
  // Insert server logic here...
  //////////////////////////////////////////////////

  // Free hash table to memory after business logic
  ht_destroy(cred_table);

  printf("Freed hash table to memory.\n");
  printf("Server closing...\n");

  return 0;
}
