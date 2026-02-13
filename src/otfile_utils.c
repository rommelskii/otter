#include "otfile_utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ht.h"
#include "tk.h"

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

    ht_set(ptable, list->head->ct, (char*)list->head->next->ct, strlen(list->head->next->ct)+1);

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

