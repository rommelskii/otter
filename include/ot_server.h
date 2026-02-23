/* 
 * Otter Protocol (C) Rommel John Ronduen 2026
 *
 * file: ot_server.h
 *
 * Contains public API for Otter server
 *
 * The API simply consists of an ot_srv_run entrypoint that utilizes the server IP and MAC, and path to
 * the desired otfile.
 *
 * Also found here are the variables for configuring the Otter server
 */
#ifndef OT_SERVER_H_
#define OT_SERVER_H_

#include <stdint.h> //<< for uint32_t, uint8_t

#define DEF_PORT 7192
#define DEF_EXP_TIME 86400  //<< default expiry is 1 day

#define SRV_PORT 7192
#define MAX_RECV_SIZE 2048

// Runs the server loop
void ot_srv_run(uint32_t SRV_IP, uint8_t* SRV_MAC); 

#endif //OT_SERVER_H_


