#ifndef OTFILE_UTILS_H
#define OTFILE_UTILS_H

#include <stdbool.h>
#include <stdlib.h>

#include "ht.h"

// Builds a hash table out of a valid otfile
void otfile_build(const char* PATH, struct ht** ptable);

// Iterates through a line buffer (lbuf) and extracts the tokens to a token buffer (tbuf) 
bool extract_next_token(char* tbuf, const char* lbuf, size_t lbuf_len, size_t *start, size_t *end, const char delim);



#endif //OTFILE_UTILS_H
