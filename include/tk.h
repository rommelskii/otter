#ifndef TK_H_
#define TK_H_

#include <stdlib.h>

struct Tk {
  char* ct;
  struct Tk* next;
};

struct TkL 
{
  struct Tk* head;
  struct Tk* tail;
  size_t length;
  size_t capacity;
};

  
// Creates a token instance (allocates memory for it)
struct Tk* tk_create(const char* ct, size_t len_ct);

// Frees a token and its content
void tk_free(struct Tk* tok);

// Inserts an entry at the end of a linked list
struct Tk* tkl_append(struct TkL* list, struct Tk* add);

// Removes an entry in a linked list by the token content
struct Tk* tkl_remove_by_ct(struct TkL* list, const char* ct); 

// Creates a token list instance
struct TkL* tkl_initialize(const size_t CAPACITY);

// Converts a space-delimited string into a string tokens 
struct TkL* process_string(const char* input_dir, size_t max_tokens);

// Frees a token list
void tkl_free(struct TkL* list);

// Tokenizes a line into a token list
void tkl_process_string(struct TkL* list, const char* lbuf);

#endif //TK_H_
