#include "ot_packet.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/**
  * Private prototypes
  */
static ssize_t ot_pkt_serialize_pack_header(ot_pkt_header h, uint8_t* buf, size_t buflen);
static ssize_t ot_pkt_serialize_pack_payload(ot_payload* head, uint8_t* buf, size_t buflen);
static ssize_t ot_pkt_deserialize_unpack_header(ot_pkt_header* h, uint8_t* buf, size_t buflen);
static ssize_t ot_pkt_deserialize_unpack_payload(ot_payload* head, uint8_t* buf, size_t buflen);
/**
  * Public implementations
  */
ot_pkt_header ot_pkt_header_create(uint32_t srv_ip, uint32_t cli_ip, uint8_t* src_mac, uint8_t* cli_mac, uint64_t exp_time, uint64_t renew_time)
{
  ot_pkt_header res;
  
  res.srv_ip = srv_ip;
  res.cli_ip = cli_ip;
  memcpy(res.src_mac, src_mac, 6);
  memcpy(res.cli_mac, cli_mac, 6);
  res.exp_time = exp_time;
  res.renew_time = renew_time;
  
  return res;
}

ot_pkt* ot_pkt_create()
{
  ot_pkt* res = malloc(sizeof(ot_pkt));
  if (res == NULL) return NULL;

  return res;
}

ot_payload* ot_payload_create(ot_pkt_type_t t, void* v, size_t vl)
{
  ot_payload* res = malloc(sizeof(ot_payload));
  if (res == NULL) return NULL;
  
  res->value = malloc(vl);
  memcpy(res->value, v, vl);

  res->type = t;

  res->next = NULL;

  return NULL;
}

ot_payload* ot_payload_append(ot_payload* head, ot_payload* add) 
{
  if (head == NULL || add == NULL) return NULL;
  
  ot_payload* oti = head;
  for(; oti->next != NULL; oti = oti->next);

  oti->next = add;

  return oti;
}

/*
#pragma pack(push, 1)
typedef struct ot_pkt_header
{
  uint32_t  srv_ip;
  uint32_t  cli_ip;
  uint8_t   srv_mac[6];
  uint8_t   cli_mac[6];
  uint64_t  exp_time;
  uint64_t  renew_time;
} ot_pkt_header;
#pragma pack(pop)

// Singly-linked list for payload entries in an Otter packet
typedef struct ot_payload
{
  ot_pkt_type_t               type; 
  void*                     value;
  uint8_t                    vlen;
  struct ot_payload*    next;
} ot_payload;
 */

ssize_t ot_pkt_serialize(struct ot_pkt* pkt, uint8_t* buf, size_t buflen)
{
  if (pkt == NULL || buf == NULL || buflen == 0) return -1;
  
  ssize_t bytes_serialized = 0;

  if ( (bytes_serialized += ot_pkt_serialize_pack_header(ot_pkt->header, buf, buflen)) < 0 ) return -1;
  if ( (bytes_serialized += ot_pkt_serialize_pack_payload(ot_pkt->payload, buf, buflen)) < 0 ) return -1;

  return bytes_serialized;
}

ssize_t ot_pkt_deserialize(struct ot_pkt* pkt, uint8_t* buf, size_t buflen) 
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
static ssize_t ot_pkt_serialize_pack_header(ot_pkt_header h, uint8_t* buf, size_t buflen)
{
  if (buf == NULL || buflen == 0) return -1;

  if (sizeof(ot_pkt_header) > buflen) return -1;

  memcpy(&buf[0], &h, sizeof(ot_pkt_header));

  return (ssize_t)sizeof(ot_pkt_header);
}

static ssize_t ot_pkt_serialize_pack_payload(ot_payload* head, uint8_t* buf, size_t buflen) 
{
  if(head == NULL || buf == NULL || buflen == 0) return -1;
  
  size_t offset = sizeof(ot_pkt_header); //<< we start after we serialize the header

  // Iterate over all payload entries
  ot_payload* oti = head;
  for(; oti != NULL; oti=oti->next) 
  {
    // Check if we can still serialize within buffer bounds
    if (offset + sizeof(oti->type) + oti->vlen >= buflen) return -1; 
    
    //Serialize type
    memcpy(&buf[offset], &(oti->type), sizeof(oti->type));
    offset += sizeof(oti->type); //<< advance to first byte of vlen

    //Serialize value length
    buf[offset] = oti->vlen;
    offset++; //<< advance to first byte of value
   
    //Serialize value itself 
    memcpy(&buf[offset], oti->value, oti->vlen);
    offset += oti->vlen;
  }

  // Populate rest of buffer with the terminator
  memset(&buf[offset], 0xFF, buflen - offset);

  return offset-sizeof(ot_pkt_header); //<< return bytes we serialized excluding header size
}

static ssize_t ot_pkt_deserialize_unpack_header(ot_pkt_header* h, uint8_t* buf, size_t buflen)
{
  if (h == NULL || buf == NULL || buflen == 0) return -1;

  if (sizeof(ot_pkt_header) > buflen) return -1;

  memcpy(h, &buf[0], sizeof(ot_pkt_header));

  return sizeof(ot_pkt_header);
}

static ssize_t ot_pkt_deserialize_unpack_payload(ot_payload* head, uint8_t* buf, size_t buflen)
{
  if(head == NULL || buf == NULL || buflen == 0) return -1;
  
  // Iterate over the buffer 
  size_t offset = sizeof(ot_pkt_header); //<< we start after we serialize the header
  while (offset < buflen)
  {
    if (buf[offset] == 0xFF) break;                                   //<< stop iterating if we find the terminator (type=0xFF)
    if (offset + sizeof(oti->type) + oti->vlen >= buflen) return -1;  //<< if out of bounds, immediately return -1 (FREE THE PAYLOAD FROM CALLER!!)

    // Extract type
    ot_type_t t;
    memcpy(&t, &buf[offset], sizeof(ot_type_t));
    offset += sizeof(ot_type_t); //<< point to first byte of vlen

    // Extract value length
    size_t vl;
    vl = buf[offset];
    offset++; //<< point to first byte of value

    // Allocate memory for value
    void* v = malloc(oti->vlen);
    if (v == NULL) return -1; //<< return to caller if out of memory (free the payload!!);
    
    // Extract the value from buffer
    memcpy(v, &buf[offset], oti->vlen);
    offset += oti->vlen; //<< point to next value type

    if (ot_payload_append(head, ot_payload_create(t,v,vl)) == NULL) return -1; //<< append; exit if we cant do so
  }

  return offset-sizeof(ot_pkt_header); //<< return bytes deserialized as usual
}
