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
static ssize_t ot_pkt_deserialize_unpack_payload(ot_payload** phead, uint8_t* buf, size_t buflen);

static void ot_payload_destroy(ot_payload** pp);
/**
  * Public implementations
  */
ot_pkt_header ot_pkt_header_create(uint32_t srv_ip, uint32_t cli_ip, uint8_t* srv_mac, uint8_t* cli_mac, uint64_t exp_time, uint64_t renew_time)
{
  ot_pkt_header res;
  
  res.srv_ip = srv_ip;
  res.cli_ip = cli_ip;
  memcpy(res.srv_mac, srv_mac, 6);
  memcpy(res.cli_mac, cli_mac, 6);
  res.exp_time = exp_time;
  res.renew_time = renew_time;
  
  return res;
}

ot_pkt* ot_pkt_create()
{
  ot_pkt* res = malloc(sizeof(ot_pkt));

  if (res == NULL) {
    return NULL;
  }

  res->payload = NULL;

  return res;
}

ot_payload* ot_payload_create(uint8_t t, void* v, uint8_t vl)
{
  ot_payload* res = malloc(sizeof(ot_payload));
  if (res == NULL) return NULL;

  res->value = malloc(vl);
  if (res->value == NULL) {
    free(res); 
    return NULL;
  }

  memcpy(res->value, v, vl);
  res->type = t;
  res->vlen = vl; 
  res->next = NULL;

  return res; // Return the pointer to the newly created object
}

ot_payload* ot_payload_append(ot_payload* head, ot_payload* add) 
{
  // If there's nothing to add, just return the current list as-is
  if (add == NULL) return head;

  // If the list is empty, the new node becomes the head
  if (head == NULL) {
    return add;
  }

  // Traverse to the end of the list
  ot_payload* oti = head;
  while (oti->next != NULL) {
    oti = oti->next;
  }

  // Attach the new node/sublist
  oti->next = add;

  // Return the original head so the caller doesn't lose the list start
  return head;
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
  uint8_t                     type; 
  void*                       value;
  uint8_t                     vlen;
  struct ot_payload*          next;
} ot_payload;
 */

ssize_t ot_pkt_serialize(struct ot_pkt* pkt, uint8_t* buf, size_t buflen)
{
  if (pkt == NULL || buf == NULL || buflen == 0) return -1;
  
  ssize_t bytes_serialized = 0;

  if ( (bytes_serialized += ot_pkt_serialize_pack_header(pkt->header, buf, buflen)) < 0 ) 
  {
    fprintf(stderr, "pkt serialization failed: cannot serialize header\n");
    return -1;
  }
  if ( (bytes_serialized += ot_pkt_serialize_pack_payload(pkt->payload, buf, buflen)) < 0 )
  {
    fprintf(stderr, "pkt serialization failed: cannot serialize payload\n");
    return -1;
  }

  return bytes_serialized;
}

ssize_t ot_pkt_deserialize(struct ot_pkt* pkt, uint8_t* buf, size_t buflen) 
{
  if (pkt == NULL || buf == NULL || buflen == 0) return -1;
  
  ssize_t bytes_deserialized = 0;

  if ( (bytes_deserialized += ot_pkt_deserialize_unpack_header(&(pkt->header), buf, buflen)) < 0 ) 
  {
    fprintf(stderr, "pkt deserialization failed: cannot deserialize header\n");
    if (pkt->payload != NULL)
    {
      
    }
    return -1;
  }
  if ( (bytes_deserialized += ot_pkt_deserialize_unpack_payload(&(pkt->payload), buf, buflen)) < 0 ) 
  {
    fprintf(stderr, "pkt deserialization failed: cannot deserialize payload\n");
    return -1;
  }

  return bytes_deserialized;
}

void ot_pkt_destroy(ot_pkt** o)
{
  ot_pkt* pkt = *o;

  ot_payload_destroy(&(pkt->payload));

  free(*o);
  *o = NULL;

  return;
}

void macstr_to_bytes(const char* macstr, uint8_t* macbytes) 
{
  // Use an int array to avoid pointer-size issues with %x in sscanf
  unsigned int bytes[6];

  if (sscanf(macstr, "%02x:%02x:%02x:%02x:%02x:%02x", 
             &bytes[0], &bytes[1], &bytes[2], 
             &bytes[3], &bytes[4], &bytes[5]) == 6) 
  {
    for (int i = 0; i < 6; i++) {
      macbytes[i] = (uint8_t)bytes[i];
    }
  }

  return;
}

void bytes_to_macstr(uint8_t* macbytes, char* macstr) 
{
  // %02X ensures two-digit uppercase hex with leading zeros
  sprintf(macstr, "%02x:%02x:%02x:%02x:%02x:%02x", 
          macbytes[0], macbytes[1], macbytes[2], 
          macbytes[3], macbytes[4], macbytes[5]);

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
    if (offset + 1 + oti->vlen >= buflen) return -1; 
    
    //Serialize type
    memcpy(&buf[offset], &(oti->type), sizeof(oti->type));
    offset++; //<< advance to first byte of vlen

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

  return (ssize_t)sizeof(ot_pkt_header);
}

static ssize_t ot_pkt_deserialize_unpack_payload(ot_payload** phead, uint8_t* buf, size_t buflen)
{
  if(phead == NULL || buf == NULL || buflen == 0) return -1;
  
  // Iterate over the buffer 
  size_t offset = sizeof(ot_pkt_header); //<< we start after we serialize the header
  while (offset < buflen)
  {
    if (buf[offset] == 0xFF) break;       //<< stop iterating if we find the terminator (type=0xFF)
    if (offset + 1 >= buflen) return -1;  //<< if out of bounds, immediately return -1 

    // Extract type
    uint8_t t;
    t = buf[offset];
    offset++; //<< point to first byte of vlen

    // Extract value length
    uint8_t vl;
    vl = buf[offset];
    if (offset + vl >= buflen) return -1;
    offset++; //<< point to first byte of value

    // Allocate memory for value
    void* v = malloc(vl);
    if (v == NULL) return -1; //<< return to caller if out of memory (free the payload!!);
    
    // Extract the value from buffer
    memcpy(v, &buf[offset], vl);
    offset += vl; //<< point to next value type

    if ((*phead = ot_payload_append(*phead, ot_payload_create(t,v,vl))) == NULL) return -1; //<< append; exit if we cant do so
  }

  return offset-sizeof(ot_pkt_header); //<< return bytes deserialized as usual
}

static void ot_payload_destroy(ot_payload** pp)
{
  if (pp == NULL) return;

  ot_payload* head = *pp;

  while (head != NULL)
  {
    ot_payload* tmp = head;
    head = head->next;
    free(tmp->value);
    free(tmp);
  }
  
  *pp = NULL;

  return;
}
