/* Created by Rommel John H. Ronduen (rommel.ronduen2244@gmail.com)
*
* file: test_cli_runtime.c
*
* Contains the test suite for testing the client runtime and the contents of inbound TREQ, TREN, and CPULL requests and its
* invalid and expired cases.
*
* CLIENT CHILD PROCESSES
* There will be 7 child processes whose PID is stored in an array called pid_t ch_pids[7]. At the end of main() entrypoint, this array
* is iterated over to kill. 
*
* The chain of processes is as follows: TREQ, TREN, CPULL, expTREN, expCPULL, invTREN, invCPULL.
*
* Contrary to the server runtime tests, the harnesses are written from the perspective of the server. As such, the child process is the 
* client. The business logic of the test harnesses mimic that of the server itself. The main() entrypoint of this program contains a 
* server context (ot_srv_ctx) that will be utilized by the harnesses. 
*
* MAIN ENTRYPOINT
* The main function running all the harnesses operate in a chain of requests (TREQ/TREN handshake and CPULL/CPUSH interaction). With regards
* to the TREN and expired versions of the TREN and CPULL harnesses, we utilize the debug MAC address that will invoke a 20 second expiry
* time to the harness context. The rest of the harnesses left will be the invalid versions.
*
* TIMING
* The last thing to note regarding this test suite is the usage of timing in between tests: THE HARNESS MUST RUN FIRST BEFORE THE CLIENT, 
* which means that there has to be a specific delay from the server child process to allow the correct harness to listen. In this case,
* we will utilize a 3-second interval in between client requests.
*/

#include "ot_server.h"
#include "testing_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <signal.h>

int tests_failed = 0;


/**
 * MACROS
 */
#define NUM_CHILDREN 7
#define CLI_REQ_DELAY 3 

/**
* PRIVATE TEST FIXTURE FUNCTIONS
*/
// Normal client behavior
static int test_treq_recv(ot_srv_ctx** ctable, ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_tren_recv(ot_srv_ctx** ctable, ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_cpull_recv(ot_srv_ctx** ctable, ot_pkt** reply_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

// Expired client behavior
static int test_expired_tren_recv(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_expired_cpull_recv(ot_srv_ctx** ctable, ot_pkt** reply_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

// Error-handling behavior
static int test_invalid_tren_recv(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_invalid_cpull_recv(ot_pkt** reply_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//// TEST HARNESS: test_treq
////
//// Test method for receiving an inbound TREQ from the client process
////  
//// This harness listens for the client's inbound request after some set time. The expected packet to be received
//// contains a msgtype payload of TREQ with its contents being the cli_ip and cli_mac payloads.
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int test_treq(ot_srv_ctx** ctable, const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  assert("test_treq: not yet implemented" && false);
  return 0;
}

int test_tren(ot_srv_ctx** ctable, const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  assert("test_tren: not yet implemented" && false);
  return 0;
}

int test_cpull(ot_srv_ctx** ctable, const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  assert("test_cpull: not yet implemented" && false);
  return 0;
}

int test_expired_tren(ot_srv_ctx** ctable, const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  assert("test_expired_tren: not yet implemented" && false);
  return 0;
}

int test_expired_cpull(ot_srv_ctx** ctable, const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  assert("test_expired_cpull: not yet implemented" && false);
  return 0;
}

int test_invalid_tren(ot_srv_ctx** ctable, const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  assert("test_invalid_tren: not yet implemented" && false);
  return 0;
}

int test_invalid_cpull(ot_srv_ctx** ctable, const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  assert("test_invalid_cpull: not yet implemented" && false);
  return 0;
}

int main(void) 
{
  // Create child processes
  pid_t pids[NUM_CHILDREN+1];

  assert("[test cli runtime] implement all functions first" && false);

  size_t i=0;
  for(; i<NUM_CHILDREN;++i) 
  {
    pid_t pid = fork();

    if (pid<0) 
    {
      perror("fork failed");
      return 1;
    } else if (pid == 0) 
    {
      // Child processes
      switch(i)
      { 
        case 0: // TREQ HARNESS
          printf("[test cli runtime] spawned treq client (%d)\n", getpid());
          sleep(CLI_REQ_DELAY);
          break;
        case 1: // TREN HARNESS
          printf("[test cli runtime] spawned tren client (%d)\n", getpid());
          sleep(CLI_REQ_DELAY);
          break;
        case 2: // CPULL HARNESS
          printf("[test cli runtime] spawned cpull client (%d)\n", getpid());
          sleep(CLI_REQ_DELAY);
          break;
        case 3: // EXPIRED TREN HARNESS
          printf("[test cli runtime] spawned expired tren client (%d)\n", getpid());
          sleep(CLI_REQ_DELAY);
          break;
        case 4: // EXPIRED CPULL HARNESS
          printf("[test cli runtime] spawned expired cpull client (%d)\n", getpid());
          sleep(CLI_REQ_DELAY);
          break;
        case 5: // INVALID TREN HARNESS
          printf("[test cli runtime] invalid tren client (%d)\n", getpid());
          sleep(CLI_REQ_DELAY);
          break;
        case 6: // INVALID CPULL HARNESS
          printf("[test cli runtime] invalid cpull client (%d)\n", getpid());
          sleep(CLI_REQ_DELAY);
          break;
      }
    } else {
    }
  }

  // Environment variables
  const int PORT = 7192;
  uint32_t  SRV_IP = inet_addr("127.0.0.1");
  uint8_t   SRV_MAC[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  uint32_t  CLI_IP = inet_addr("127.0.0.1");
  uint8_t   CLI_MAC[6] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa};

  // Create testing server context
  ot_srv_ctx_mdata test_srv_mdata = ot_srv_ctx_mdata_create(PORT, SRV_IP, SRV_MAC);
  ot_srv_ctx* test_srv_ctable = ot_srv_ctx_create(test_srv_mdata);

  // Begin test harnesses
  test_treq(&test_srv_ctable, PORT, SRV_IP, CLI_IP);
  test_tren(&test_srv_ctable, PORT, SRV_IP, CLI_IP);
  test_cpull(&test_srv_ctable, PORT, SRV_IP, CLI_IP);

  test_expired_tren(&test_srv_ctable, PORT, SRV_IP, CLI_IP);
  test_expired_cpull(&test_srv_ctable, PORT, SRV_IP, CLI_IP);

  test_invalid_tren(&test_srv_ctable, PORT, SRV_IP, CLI_IP);
  test_invalid_cpull(&test_srv_ctable, PORT, SRV_IP, CLI_IP);

  // Cleanup
  ot_srv_ctx_destroy(&test_srv_ctable);
  
  i=0;
  for(; i<NUM_CHILDREN;++i)
  {
    kill(pids[i], SIGTERM);
    printf("[test cli runtime] killed client (%d)\n", getpid());
  }

  if (tests_failed > 0) return 1;

  return 0;
}

// Normal client behavior
static int test_treq_recv(ot_srv_ctx** ctable, ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_tren_recv(ot_srv_ctx** ctable, ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_cpull_recv(ot_srv_ctx** ctable, ot_pkt** reply_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

// Expired client behavior
static int test_expired_tren_recv(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_expired_cpull_recv(ot_srv_ctx** ctable, ot_pkt** reply_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

// Error-handling behavior
static int test_invalid_tren_recv(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_invalid_cpull_recv(ot_pkt** reply_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

