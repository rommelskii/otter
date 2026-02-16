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
 * PRIVATE TEST SUITE FUNCTIONS
 */
static int test_cli_listen(const int PORT, uint8_t* buf, size_t buflen);

/**
* PRIVATE TEST FIXTURE FUNCTIONS
*/
// Normal client behavior
static int test_treq_recv(ot_pkt** recv_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_tren_recv(ot_pkt** recv_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_cpull_recv(ot_pkt** recv_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

// Expired client behavior
static int test_expired_tren_recv(ot_pkt** recv_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_expired_cpull_recv(ot_pkt** recv_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

// Error-handling behavior
static int test_invalid_tren_recv(ot_pkt** recv_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);
static int test_invalid_cpull_recv(ot_pkt** recv_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac);

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
  // Receive the reply for a TREQ packet to server
  uint8_t srv_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  uint8_t cli_mac[6] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa};
  printf("[treq test] Performing pre-request preparation... ");
  ot_pkt* recv_pkt = NULL;
  if (test_treq_recv(ctable, &recv_pkt, PORT, SRV_IP, CLI_IP, srv_mac, cli_mac) < 0) 
  {
    printf("FAILED\n");
    return 1;
  } else printf("SUCCESS\n");
  
  printf("---- BEGIN TREQ TESTS ----\n");

  // Header checks
  EXPECT(recv_pkt != NULL, "[treq test] deserialization non-nullity test");

  ot_pkt_header reply_hd = recv_pkt->header;

  EXPECT(reply_hd.srv_ip == SRV_IP, "[treq recv] srv ip check");
  EXPECT(memcmp(reply_hd.srv_mac, srv_mac, 6) == 0, "[treq recv] srv mac check");

  EXPECT(reply_hd.cli_ip == CLI_IP, "[treq recv] cli ip check");
  EXPECT(memcmp(reply_hd.cli_mac, cli_mac, 6) == 0, "[treq recv] cli mac check");

  // Note: these values should be standardized in the entire codebase
  uint32_t actual_exp_time = 86400;
  uint32_t actual_renew_time = 86400 * 0.75;
  EXPECT(reply_hd.exp_time == actual_exp_time, "[treq recv] exp time check");
  EXPECT(reply_hd.renew_time == actual_renew_time, "[treq recv] renew time check");

  // Build parse table from reply pkt payloads
  ot_payload* reply_head = recv_pkt->payload;
  ht* parse_table = ht_create(8);
  pl_parse_table_build(&parse_table, reply_head);

  // Start payload parsing
  // Check expected TACK reply with TREQ input
  printf("[treq recv] checking for PL_STATE entry in parse table... ");
  ot_cli_state_t* expected_treq = ht_get(parse_table, "PL_STATE");
  if (expected_treq == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_treq == TREQ, "[treq recv] reply type (TREQ) check");

  // Check expected cli ip from received TREQ pkt
  uint32_t* expected_cli_ip = ht_get(parse_table, "PL_CLI_IP");
  printf("[treq recv] checking for PL_CLI_IP entry in parse table... ");
  if (expected_cli_ip == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(*expected_cli_ip == CLI_IP, "[treq recv] cli ip check");

  // Check expected cli mac (also the same as the one in the header of the TREQ pkt)
  uint8_t* expected_cli_mac = ht_get(parse_table, "PL_CLI_MAC");
  printf("[treq rcev] checking for PL_CLI_MAC entry in parse table... ");
  if (expected_cli_mac == NULL)
  {
    printf("FAILED\n");
    ++tests_failed;
    return -1;
  } else printf("SUCCESS\n");
  EXPECT(memcmp(expected_cli_mac, cli_mac, 6) == 0, "[treq recv] cli mac check");

  printf("---- END TREQ TESTS ----\n");

  // Perform cleanup
  ot_pkt_destroy(&recv_pkt);
  return 0;
}

int test_tren(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  assert("test_tren: not yet implemented" && false);
  return 0;
}

int test_cpull(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  assert("test_cpull: not yet implemented" && false);
  return 0;
}

int test_expired_tren(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  assert("test_expired_tren: not yet implemented" && false);
  return 0;
}

int test_expired_cpull(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  assert("test_expired_cpull: not yet implemented" && false);
  return 0;
}

int test_invalid_tren(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
{
  assert("test_invalid_tren: not yet implemented" && false);
  return 0;
}

int test_invalid_cpull(const int PORT, const uint32_t SRV_IP, const uint32_t CLI_IP)
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
static int test_treq_recv(ot_pkt** recv_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac)
{
  int listen_fd, recv_fd;
  struct sockaddr_in servaddr;
  int opt=1;
  int addrlen = sizeof(servaddr);
  uint8_t buf[2048] = {0xff};

  // Listen to client process 
  printf("[test treq] listening to client... ");
  if (test_cli_listen(PORT, buf, sizeof buf) < 0) 
  {
    printf("FAILED\n");
    return -1;
  } else printf("SUCCESS");
  
  // Deserialize recv pkt 
  printf("[test treq] deserializing recv pkt... ");
  if (ot_pkt_deserialize(*recv_pkt, buf, sizeof buf) < 0) 
  {
    printf("FAILED\n");
    return -1;    
  } else printf("SUCCESS\n");

  return 0;
}

static int test_cli_listen(const int PORT, uint8_t* buf, size_t buflen)
{
  int listen_fd, recv_fd;
  struct sockaddr_in servaddr;
  int opt=1;
  int addrlen = sizeof(servaddr);

  // Listen to client process 
  if (test_cli_listen(buf) < 0) 
  {
    return -1;
  } 

  if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
  {
    perror("socket failed");
    return -1;
  }

  if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
  {
    perror("setsockopt failed");
    return -1;
  }

  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(PORT);
  servaddr.sin_addr.s_addr = INADDR_ANY;

  if (bind(listen_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
  {
    perror("bind failed");
    return -1;
  }

  if (listen(listen_fd, 3) < 0) //<< 3 is the maximum for pending packets
  {
    perror("listen failed");
    return -1;
  }

  printf("[treq recv] Harness running at port %d in all interfaces\n", PORT);

  if ((recv_fd = accept(listen_fd, (struct sockaddr*)&servaddr, (socklen_t*)&addrlen)) < 0) 
  {
    perror("accept failed");
    return -1;
  }

  ssize_t bytes_received = read(recv_fd, buf, sizeof buf);
  if (bytes_received < 0)
  {
    perror("read failed");
    return -1;
  }

  printf("[treq recv] successfully received %zu bytes\n", bytes_received);

  close(recv_fd);
  close(listen_fd);
}

static int test_tren_recv(ot_srv_ctx** ctable, ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac)
{
  assert("test_tren_recv: not yet implemented" && false);
  return 0;
}

static int test_cpull_recv(ot_srv_ctx** ctable, ot_pkt** reply_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac)
{
  assert("test_cpull_recv: not yet implemented" && false);
  return 0;
}

// Expired client behavior
static int test_expired_tren_recv(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac)
{
  assert("test_expired_tren_recv: not yet implemented" && false);
  return 0;
}

static int test_expired_cpull_recv(ot_srv_ctx** ctable, ot_pkt** reply_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac)
{
  assert("test_expired_cpull_recv: not yet implemented" && false);
  return 0;
}

// Error-handling behavior
static int test_invalid_tren_recv(ot_pkt** reply_pkt, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac)
{
  assert("test_invalid_tren_recv: not yet implemented" && false);
  return 0;
}

static int test_invalid_cpull_recv(ot_pkt** reply_pkt, const char* uname, const int PORT, uint32_t SRV_IP, uint32_t CLI_IP, uint8_t* srv_mac, uint8_t* cli_mac)
{
  assert("test_invalid_cpull_recv: not yet implemented" && false);
  return 0;
}

