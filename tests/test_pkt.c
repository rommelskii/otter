/* Created by Rommel John H. Ronduen (rommel.ronduen2244@gmail.com)
*
* file: test_pkt.c
*
* Contains unit tests for Otter packet functionalities.
*/

#include "ot_packet.h"
#include "testing_utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

int tests_failed = 0;

int main(void) 
{
  uint8_t TEST_BYTES_SRV_MAC[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  uint8_t TEST_BYTES_CLI_MAC[6] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa};

  const char* TEST_STR_SRV_MAC = "aa:bb:cc:dd:ee:ff";
  const char* TEST_STR_CLI_MAC = "ff:ee:dd:cc:bb:aa";

  uint64_t TEST_EXP_TIME = 1770967837;
  uint64_t TEST_RENEW_TIME = 1770967837 - 3600;

  //ot_pkt* ot_payload_create(ot_pkt_type t, void* v, size_t vl);
  ot_pkt_type_t TEST_PAYLOAD_TYPE = TACK;
  // cannot be compile time constants smh
  uint32_t TEST_SRV_IP = inet_addr("192.168.100.1");
  uint32_t TEST_CLI_IP = inet_addr("1.100.168.192");
  uint32_t TEST_PAYLOAD_VALUE = inet_addr("203.118.16.2");
  uint8_t TEST_PAYLOAD_VLEN = (uint8_t)sizeof(TEST_PAYLOAD_VALUE);

  printf("---- BEGIN PKT TESTS ----\n");
  
  // Begin string/byte formatter tests
  char srvmac_str[256];
  char climac_str[256];
  bytes_to_macstr(TEST_BYTES_SRV_MAC, srvmac_str);
  bytes_to_macstr(TEST_BYTES_CLI_MAC, climac_str);
  
  EXPECT( strcmp(TEST_STR_SRV_MAC, srvmac_str) == 0, "(str to bytes) srv mac");
  EXPECT( strcmp(TEST_STR_CLI_MAC, climac_str) == 0, "(str to bytes) cli mac");

  uint8_t srvmac[6];
  uint8_t climac[6];
  macstr_to_bytes(TEST_STR_SRV_MAC, srvmac);
  macstr_to_bytes(TEST_STR_CLI_MAC, climac);

  EXPECT(memcmp(srvmac, TEST_BYTES_SRV_MAC, 6*sizeof(uint8_t)) == 0, "(bytes to str) srv mac");
  EXPECT(memcmp(climac, TEST_BYTES_CLI_MAC, 6*sizeof(uint8_t)) == 0, "(bytes to str) cli mac");
  // End of string/byte formatter tests

  // Begin header tests
  ot_pkt_header header = ot_pkt_header_create(TEST_SRV_IP, TEST_CLI_IP,  TEST_BYTES_SRV_MAC, TEST_BYTES_CLI_MAC, TEST_EXP_TIME, TEST_RENEW_TIME);

  EXPECT(TEST_SRV_IP == header.srv_ip, "(pkt header) srv ip");
  EXPECT(TEST_CLI_IP == header.cli_ip, "(pkt header) cli ip");
  EXPECT(memcmp(TEST_BYTES_SRV_MAC, header.srv_mac, 6*sizeof(uint8_t)) == 0, "(pkt header) srv mac");
  EXPECT(memcmp(TEST_BYTES_CLI_MAC, header.cli_mac, 6*sizeof(uint8_t)) == 0, "(pkt header) cli mac");
  EXPECT(TEST_EXP_TIME == header.exp_time, "(pkt header) exp time");
  EXPECT(TEST_RENEW_TIME == header.renew_time, "(pkt header) renew time");
  // End header test
  
  // Begin packet tests
  ot_pkt* o = ot_pkt_create();
  EXPECT(&(o->header) != NULL, "(pkt) header init");
  EXPECT(o->payload == NULL, "(pkt) payload init");
  
  o->header = header;
  EXPECT(memcmp(&header, &(o->header), sizeof(header)) == 0, "(pkt) header set");

  //ot_payload* test_payload = ot_payload_create(TEST_PAYLOAD_TYPE, &TEST_PAYLOAD_VALUE, TEST_PAYLOAD_VLEN);
  o->payload = ot_payload_append(o->payload, ot_payload_create(TEST_PAYLOAD_TYPE, &(uint32_t){TEST_PAYLOAD_VALUE}, TEST_PAYLOAD_VLEN));
  ot_payload_append(o->payload, ot_payload_create(TEST_PAYLOAD_TYPE, &(uint32_t){TEST_PAYLOAD_VALUE}, TEST_PAYLOAD_VLEN));
  ot_payload_append(o->payload, ot_payload_create(TEST_PAYLOAD_TYPE, &(uint32_t){TEST_PAYLOAD_VALUE}, TEST_PAYLOAD_VLEN));

  size_t count = 0;
  ot_payload* iter = o->payload;
  for(; iter != NULL; iter=iter->next)
  {
    uint32_t* value = (uint32_t*)iter->value;
    if (TEST_PAYLOAD_TYPE != iter->type) continue;
    if (TEST_PAYLOAD_VALUE != *value) continue;
    if (TEST_PAYLOAD_VLEN != iter->vlen) continue;
    ++count; 
  }
  EXPECT(count == 3, "(pkt) payload append & integrity test");
  // End packet tests

  // Begin pkt serialization tests
  ot_pkt* deser_res = ot_pkt_create();
  uint8_t buf[2048];

  ssize_t ser_bytes = ot_pkt_serialize(o, buf, sizeof buf);
  EXPECT(ser_bytes != -1, "(pkt serialization) serialization test");

  ssize_t deser_bytes = ot_pkt_deserialize(deser_res, buf, sizeof buf);
  EXPECT(deser_bytes != -1, "(pkt serialization) deserialization test");

  EXPECT(ser_bytes == deser_bytes, "(pkt serialization) serialization/deserialization bytes equality");

  struct ot_payload* oti = deser_res->payload;
  size_t res_payload_count = 0;
  while (oti != NULL)
  {
    uint32_t* value = oti->value;
    if (oti->type != TEST_PAYLOAD_TYPE) 
    {
      oti = oti->next;
      continue;
    }
    if (*value != TEST_PAYLOAD_VALUE) 
    {
      oti = oti->next;
      continue;
    }
    if (oti->vlen != TEST_PAYLOAD_VLEN) 
    {
      oti = oti->next;
      continue;
    }
    ++res_payload_count;
      oti = oti->next;
  }
  EXPECT(res_payload_count == count, "(pkt serialization) structure equality test");
  if (tests_failed > 0)
  {
    printf("serialized payload count: %zu => deserialized payload count: %zu\n", count, res_payload_count);
  }
  // End pkt serialization tests

  // Begin destructor tests
  ot_pkt_destroy(&o);
  EXPECT(o == NULL, "(pkt destructor) nullity test");
  // End destructor tests

  // Other cleanup
  ot_pkt_destroy(&deser_res); //<< also destroy;

  printf("---- END PKT TESTS ----\n");

  if (tests_failed > 0) 
  {
    fprintf(stderr, "One or more tests have failed! Exiting...\n");
    return 1;
  }

  return 0;
}
