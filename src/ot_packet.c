#include "ot_packet.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/**
  * Private prototypes
  */
// Returns the tail of the payload linked list
static ot_pkt* ot_payload_next(ot_pkt* o);

/**
  * Public implementations
  */
ot_pkt_header ot_pkt_header_create(uint32_t srv_ip, uint32_t cli_ip, uint8_t* src_mac, uint8_t* cli_mac, uint64_t exp_time, uint64_t renew_time)
{
  ot_pkt_header res;

  return res;
}

ot_pkt* ot_pkt_create()
{
  
  return NULL;
}

ot_payload* ot_payload_create(ot_pkt_type_t t, void* v, size_t vl)
{
  
  return NULL;
}

ot_pkt* ot_payload_append(ot_payload* head, ot_payload* add) 
{
  
  return NULL;
}

ssize_t ot_pkt_serialize(struct ot_pkt* pkt, uint8_t* buf)
{
  
  return -1;
}

ssize_t ot_pkt_deserialize(struct ot_pkt* pkt, uint8_t* buf) 
{
  
  return -1;
}

void ot_pkt_destroy(ot_pkt** o)
{
  return;
}

void macstr_to_bytes(const char* macstr, uint8_t* macbytes) 
{
  return;
}

void bytes_to_macstr(uint8_t* macbytes, const char* macstr) 
{
  return;
}

/**
  * Private implementations 
  */
static ot_pkt* ot_payload_next(ot_pkt* o)
{
  return NULL;
}

