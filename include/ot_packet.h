#ifndef OT_PACKET_H
#define OT_PACKET_H

#include "ht.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define OT_PKT_TERMINATOR 0xFF

#pragma pack(push, 1)
typedef struct ot_pkt_header
{
  uint8_t   srv_mac[6];
  uint8_t   cli_mac[6];
  uint32_t  srv_ip;
  uint32_t  cli_ip;
  uint32_t  exp_time;
  uint32_t  renew_time;
} ot_pkt_header;
#pragma pack(pop)

// Singly-linked list for payload entries in an Otter packet
typedef struct ot_payload
{
  uint8_t                     type; 
  uint8_t                     vlen;
  struct ot_payload*          next;
  void*                       value;
} ot_payload;

typedef struct ot_pkt 
{
  ot_pkt_header header;
  ot_payload *payload; 
} ot_pkt;

typedef enum 
{
  TREQ,
  TACK,
  TINV,
  TREN,
  TPRV,
  CPULL,
  CPUSH,
  CINV,
  UNKN
} ot_cli_state_t;

typedef enum {
  PL_STATE,
  PL_SRV_IP,
  PL_SRV_MAC,
  PL_CLI_IP,
  PL_CLI_MAC,
  PL_ETIME,
  PL_RTIME,
  PL_UNAME,
  PL_PSK,
  PL_UNKN,
} ot_pkt_msgtype_t;

// Creates a Otter packet header
ot_pkt_header ot_pkt_header_create(uint32_t srv_ip, uint32_t cli_ip, uint8_t* srv_mac, uint8_t* cli_mac, uint32_t exp_time, uint32_t renew_time);

// Allocates memory for a ot_pkt
ot_pkt* ot_pkt_create();

// Allocates memory for a payload node and sets its fields
ot_payload* ot_payload_create(uint8_t t, void* v, uint8_t vl);

// Appends a payload node to the end of a payload list
ot_payload* ot_payload_append(ot_payload* head, ot_payload* add);

// Serializes an ot_pkt structure to a byte buffer and returns bytes serialized
ssize_t ot_pkt_serialize(struct ot_pkt* pkt, uint8_t* buf, size_t buflen);

// Deserializes/unpacks an ot_pkt structure from a byte buffer and returns bytes deserialized
ssize_t ot_pkt_deserialize(struct ot_pkt* pkt, uint8_t* buf, size_t buflen);

// Frees an Otter packet to memory 
void ot_pkt_destroy(ot_pkt** o);

// Converts a MAC string to a MAC byte buffer
void macstr_to_bytes(const char* macstr, uint8_t* macbytes);

// Converts a MAC byte buffer to a string
void bytes_to_macstr(uint8_t* macbytes, char* macstr);

// Converts a msgtype to a string
void msgtype_to_str(ot_pkt_msgtype_t msgtype, char* str_msgtype);

void pl_parse_table_build(ht** pt, ot_payload* pl_head); //<< could be implemented in ot packet library

#endif //OT_PACKET_H
