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

// Note: ot_pkt stores ip and times in network order. 
//       Ensure that these are converted to host order when 
//       performing logic on them.

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

typedef struct ot_pkt_payload 
{
  ot_pkt_type               type; 
  void*                     value;
  size_t                    vlen;
  struct ot_pkt_payload*    next;
} ot_pkt_payload;

typedef struct ot_pkt 
{
  struct ot_pkt_header header;
  struct ot_pkt_payload *payload;
} ot_pkt;

// Serializes an ot_pkt structure to a byte buffer
ssize_t ot_pkt_serialize(uint8_t* buf, struct ot_pkt pkt);

// Deserializes/unpacks an ot_pkt structure from a byte buffer
ssize_t ot_pkt_deserialize(uint8_t* buf, struct ot_pkt pkt);


#endif //OT_PACKET_H
