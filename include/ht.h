#ifndef HT_H
#define HT_H

#include <stddef.h>

// Opaque type definition
typedef struct ht ht;

// Prototypes
ht* ht_create(const size_t CAPACITY);
void ht_destroy(ht* table);
const char* ht_set(ht** table, const char* key, void* value, size_t value_len);
void* ht_get(ht* table, const char* key);

size_t ht_length(ht* table);
size_t ht_capacity(ht* table);

#endif
