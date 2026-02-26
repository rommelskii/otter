#include "otfile_utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ht.h"
#include "tk.h"

static uint64_t cred_hash(const char* c, size_t clen)
{
  uint64_t retval = 0;

  size_t i = 0;
  for (; i<clen; ++i)
  {
    retval += (uint64_t)c[i];
  }

  return retval;
}

void otfile_build(const char* PATH, struct ht** ptable) 
{
  struct ht* table = *ptable;

  FILE* fptr = fopen(PATH, "r");
  if (fptr == NULL) {
    perror("Error opening file");
    return;
  }

  char lbuf[2048]; 
  struct TkL* list = NULL;

  while ( fgets(lbuf, sizeof lbuf, fptr) != NULL )
  {
    lbuf[strcspn(lbuf, "\r\n")] = 0;

    list = tkl_initialize(1024);
    tkl_process_string(list, lbuf);

    char* uname = list->head->ct;
    char* psk = list->head->next->ct;

    uint64_t hash = cred_hash(uname, strlen(uname))+cred_hash(psk, strlen(psk));

    char hashbuf[16] = {0};
    snprintf(hashbuf, sizeof hashbuf, "%llx", hash);

    printf("[otfile utils] entry set with hash=%s\n", hashbuf);

    ht_set(ptable, hashbuf, hashbuf, strlen(hashbuf)+1);

    tkl_free(list);
  }

  fclose(fptr);
}

bool extract_next_token(char* tbuf, const char* lbuf, size_t lbuf_len, size_t *start, size_t *end, const char delim)  
{
  while ( (*end < lbuf_len) && (lbuf[*end] == delim) ) ++(*end);

  if (*end >= lbuf_len) return false;

  *start = *end;

  while ( (*end < lbuf_len) && (lbuf[*end] != delim) ) ++(*end);

  size_t token_len = *end - *start;
  if (token_len > 0) {
    memcpy(tbuf, &lbuf[*start], token_len);
    tbuf[token_len] = '\0'; // Ensure null-termination explicitly
    return true; // We found a token, return true to process it
  }

  return false;
}

