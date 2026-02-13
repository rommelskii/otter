#include "tk.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "otfile_utils.h"
  
struct Tk* tk_create(const char* ct, size_t len_ct) 
{
  struct Tk* ret = (struct Tk*)malloc(sizeof(struct Tk));

  ret->ct = (char*)malloc(sizeof(ct)*len_ct+1);
  memcpy(ret->ct, ct, len_ct+1);
    
  ret->next = NULL;

  return ret;
}

void tk_free(struct Tk* tok) 
{
  if (tok == NULL) 
  {
    return;
  }

  free(tok->ct);
  free(tok);
  return;
}

struct Tk* tkl_append(struct TkL* list, struct Tk* add) 
{
  if (list == NULL || add == NULL) 
  {
    fprintf(stderr, "Error: add or list cannot be null\n");
    return NULL;
  } 
  if (list->length >= list->capacity)
  {
    fprintf(stderr, "Error: list length at full capacity\n");
    return NULL;
  }
  
  if (list->length == 0)  
  {
    list->tail = add; 
    list->head = list->tail;
    ++(list->length);
  } else {
    list->tail->next = add;
    list->tail = list->tail->next;
    ++(list->length);
  }
  
  return list->tail;
}

struct Tk* tkl_remove_by_ct(struct TkL* list, const char* ct) {
  if (list == NULL || ct == NULL || list->length == 0) {
    return (list) ? list->tail : NULL;
  }

  struct Tk *curr = list->head;
  struct Tk *prev = NULL;

  while (curr != NULL) {
    if (strcmp(curr->ct, ct) == 0) {
      struct Tk *to_delete = curr;

      if (prev == NULL) { // if this is the first iteration
        list->head = curr->next;
      } else { // we are in the middle
        prev->next = curr->next; 
      }

      if (to_delete == list->tail) {
        list->tail = prev;
      }

      curr = curr->next;

      tk_free(to_delete);
      list->length--;

    } else {
      prev = curr;
      curr = curr->next;
    }
  }

  return list->tail;
}

struct TkL* tkl_initialize(const size_t CAPACITY)
{
  struct TkL* list = (struct TkL*)malloc(sizeof(struct TkL));
  list->head = NULL;
  list->tail = NULL;
  list->length = 0;
  list->capacity = CAPACITY;

  return list;
}

struct TkL* process_string(const char* input_dir, size_t max_tokens)
{
  if (input_dir == NULL)
  {
    return NULL;
  }
  if (strlen(input_dir) == 0) 
  {
    return NULL;
  }

  size_t start = 0;
  size_t end = 0;
  char buf[1024];
  memset(buf, 0, sizeof buf);

  struct TkL* list = tkl_initialize(max_tokens); //< initialize max cap of 100 tokens

  while ( end < strlen(input_dir) ) 
  {
    while ( (end < strlen(input_dir)) && (input_dir[end] == ' ') ) ++end; // skip slashes
    start = end;
    while ( (end < strlen(input_dir)) && (input_dir[end] != ' ') ) ++end; // find end of token
    
    memcpy(buf, &input_dir[start], end - start); // copy the token to the buffer and print
    
    tkl_append(list, tk_create(buf, strlen(buf)));

    memset(buf, 0, sizeof buf); // clear the buffer after
  }

  return list;
}

void tkl_free(struct TkL* list) 
{
  if (list == NULL) return;

  struct Tk* tmp = NULL;
  while (list->head != NULL) 
  {
    tmp = list->head->next; 
    tk_free(list->head);
    list->head = tmp;
  }
  free(list);
  list = NULL;

  return;
}

void tkl_process_string(struct TkL* list, const char* lbuf) 
{
  char tbuf[256];

  size_t start = 0;
  size_t end = 0;
  size_t len = strlen(lbuf);

  memset(tbuf, 0, sizeof tbuf); 
  while (extract_next_token(tbuf, lbuf, len, &start, &end, ' '))
  {
    tkl_append(list, tk_create(tbuf, strlen(tbuf)));
    memset(tbuf, 0, sizeof tbuf); 
  }
}
