#ifndef OT_PACKET_H
#define OT_PACKET_H

#include <stdio.h>
#include <stdlib.h>

typedef enum 
{
  TREQ,
  TACK,
  TINV,
  TREN,
  CPULL,
  CPUSH,
  CINV
} ot_pkt_type;

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
  ot_pkt_type               type; 
  void*                     value;
  size_t                    vlen;
  struct ot_pkt_payload*    next;
} ot_payload;

typedef struct ot_pkt 
{
  ot_pkt_header header;
  ot_payload *payload; 
} ot_pkt;

// Allocates memory for a ot_pkt
ot_pkt* ot_pkt_create();

// Allocates memory for a payload node and sets its fields
ot_pkt* ot_payload_create(ot_pkt_type t, void* v, size_t vl);

// Appends a payload node to the end of a payload list
ot_pkt* ot_payload_append(ot_payload* head, ot_payload* add);

// Serializes an ot_pkt structure to a byte buffer and returns bytes serialized
ssize_t ot_pkt_serialize(uint8_t* buf, struct ot_pkt pkt);

// Deserializes/unpacks an ot_pkt structure from a byte buffer and returns bytes deserialized
ssize_t ot_pkt_deserialize(uint8_t* buf, struct ot_pkt pkt);

// Frees an Otter packet to memory 
void ot_pkt_destroy(ot_pkt** o);

/*
* STATIC STUFF BELOW
* PUT THEM TO IMPLEMENTATION
*/

// Returns the tail of the payload linked list
static ot_pkt* ot_payload_next(ot_pkt* o);


#endif //OT_PACKET_H
