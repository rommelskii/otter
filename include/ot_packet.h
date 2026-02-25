/* 
 * Otter Protocol (C) Rommel John Ronduen 2026
 *
 * file: ot_packet.h
 *
 * Contains public API for Otter packets
 *
 * The protocol operates on the ot_pkt data type that groups a header (ot_pkt_header) and payloads in the form
 * of a singly linked list (ot_payload*). This ot_pkt object is serialized and deserialized throughout the
 * protocol's operation as information is transferred in between client and server.
 *
 * OTTER HEADERS
 * The header (ot_pkt_header) contains data regarding the relationship between a client and server via
 * IP and MAC addresses as well as the expiry and renewal times. This header object is used for storing 
 * context data (see ot_context.h). It is also a security measure for verifying the source and integrity 
 * of the payloads.
 *
 * OTTER PAYLOADS
 * The payloads (ot_payload) are structured as singly linked lists that consist of several types defined by 
 * the ot_pkt_msgtype_t enum or just msgtype for short. The msgtype is what defines the value stored in the
 * payload alongside its corresponding size (vlen).
 *
 * PAYLOAD MSGTYPES AND CLIENT STATES
 * Otter packets are normally classified by the state (ot_cli_state_t) that the sender conveys to the receiver 
 * via the payload with msgtype PL_STATE. Recall that in the protocol, the client has to tether to the server. 
 * Packets that facilitate the tether process are the TREQ, TACK, TREN, TPRV, and TINV packets. On the other 
 * hand, the packets that deal with credentials are the CPULL, CPUSH, and CINV packets.
 */

#ifndef OT_PACKET_H_
#define OT_PACKET_H_

// Project Headers
#include "ht.h" //<< for hash table functionalities

// Standard Library Headers
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

// Otter Packet Header
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

// Otter Payload Node
typedef struct ot_payload
{
  uint8_t                     type; 
  uint8_t                     vlen;
  struct ot_payload*          next;
  void*                       value;
} ot_payload;

// Otter Packet Object
typedef struct ot_pkt 
{
  ot_pkt_header header;
  ot_payload *payload; 
} ot_pkt;

// Payload Message Type (msgtype) 
typedef enum {
  PL_STATE,     //<< ot_cli_state_t
  PL_SRV_IP,    //<< uint32_t server ip in network order
  PL_SRV_MAC,   //<< 6-byte server MAC address as a uint8_t array in network order
  PL_CLI_IP,    //<< uint32_t client ip in network order
  PL_CLI_MAC,   //<< 6-byte client MAC address as a uint8_t array in network order
  PL_ETIME,     //<< uint32_t time offset to indicate expiry time
  PL_RTIME,     //<< uint32_t time offset to indicate renewal time
  PL_UNAME,     //<< null-terminated string to indicate usernames
  PL_PSK,       //<< null-terminated string to indicate passwords
  PL_UNKN,      //<< indicating a parse error during serialization/deserialization
} ot_pkt_msgtype_t;

// Client States
typedef enum 
{
  TREQ,         //<< Tether Request from client
  TACK,         //<< Tether Acknowledge from server
  TREN,         //<< Tether Renewal from client
  TPRV,         //<< Tether Provide from server
  TINV,         //<< Tether Invalid from server
  //CPULL,        DEPRECATED//<< Credential Pull from client
  //CPUSH,        DEPRECATED//<< Credential Push from server
  CSEND,        //<< Credential Send (sends the hashed credentials)
  CVAL,         //<< Credential Valid (acknowledges that the credentials exist)
  CINV,         //<< Credential Invalid from server
  UNKN          //<< Parse error type
} ot_cli_state_t;

// Creates a Otter packet header
ot_pkt_header 
ot_pkt_header_create(uint32_t srv_ip, uint32_t cli_ip, 
                     uint8_t* srv_mac, uint8_t* cli_mac, 
                     uint32_t exp_time, uint32_t renew_time);

// Allocates memory for an ot_pkt
ot_pkt* 
ot_pkt_create();

// Allocates memory for a payload node and sets its fields
ot_payload* 
ot_payload_create(uint8_t t, void* v, uint8_t vl);

// Appends a payload node to the end of a payload list
ot_payload* 
ot_payload_append(ot_payload* head, ot_payload* add);

// Serializes an ot_pkt structure to a byte buffer and returns bytes serialized
ssize_t 
ot_pkt_serialize(struct ot_pkt* pkt, uint8_t* buf, size_t buflen);

// Deserializes/unpacks an ot_pkt structure from a byte buffer and returns bytes deserialized
ssize_t 
ot_pkt_deserialize(struct ot_pkt* pkt, uint8_t* buf, size_t buflen);

// Frees an ot_pkt to memory and sets the pointer to NULL on the caller's side
void 
ot_pkt_destroy(ot_pkt** o);

// Converts a MAC string to a MAC byte buffer
void 
macstr_to_bytes(const char* macstr, uint8_t* macbytes);

// Converts a MAC byte buffer to a string
void 
bytes_to_macstr(uint8_t* macbytes, char* macstr);

// Converts a msgtype to a string
void 
msgtype_to_str(ot_pkt_msgtype_t msgtype, char* str_msgtype);

// Wrapper around the ht library.
// Builds an ht from the payload list
void 
pl_parse_table_build(ht** pt, ot_payload* pl_head); 

#endif //OT_PACKET_H
