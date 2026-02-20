#ifndef OT_SERVER_H_
#define OT_SERVER_H_

#include <stdlib.h>
#include <time.h>

#include "ot_packet.h"
#include "ht.h"

#define DEF_PORT 7192
#define DEF_EXP_TIME 86400  //<< default expiry is 1 day

#define SRV_PORT 7192
#define MAX_RECV_SIZE 2048

// Runs the server loop
void ot_srv_run(uint32_t SRV_IP, uint8_t* SRV_MAC); //<< insert the packet logic here

#endif //OT_SERVER_H_


