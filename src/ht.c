#include "ht.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*******************************************
* Internal Structures
*******************************************/

typedef struct {
    char* key;
    void* value;
    size_t vlen; 
} ht_entry;

struct ht {
    size_t size;
    size_t capacity;
    ht_entry* entries;
};

/*******************************************
* Internal use functions
*******************************************/

// FNV-1a Hash Algorithm 
static uint32_t hash(const char* key, size_t len) 
{
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)key[i];
        hash *= 16777619u;
    }
    return hash;
}

static void warn_collision(const char* key)
{
    printf("warn_collision: collision with key `%s`\n", key);
    return;
}

// Internal function for setting an entry (Used by ht_set and ht_extend)
static const char* ht_set_entry(ht_entry* entries, size_t capacity, const char* key, void* value, size_t value_len, size_t* plength)
{
    uint32_t computed_hash = hash(key, strlen(key));
    size_t idx = computed_hash % capacity;

    while (entries[idx].key != NULL)
    {
        if (strcmp(entries[idx].key, key) == 0)
        {
            warn_collision(key);
            
            // Allocate new memory first
            void* new_val = malloc(value_len);
            if (!new_val) return NULL;
            memcpy(new_val, value, value_len);

            // Free old memory
            free(entries[idx].value);

            // Update entry
            entries[idx].value = new_val;
            entries[idx].vlen = value_len; // Update stored length
            return entries[idx].key;
        }
        idx++;
        if (idx >= capacity)
        {
            idx = 0;
        }
    }

    // New Entry Logic
    if (plength != NULL) 
    {
        (*plength)++;
    }

    void* value_cpy = malloc(value_len);
    if (!value_cpy) return NULL;
    memcpy(value_cpy, value, value_len);

    entries[idx].key = strdup(key);
    entries[idx].value = value_cpy;
    entries[idx].vlen = value_len; // Save length

    return entries[idx].key;
}

/*******************************************
* Public API
*******************************************/

// Creates an instance of a hash table
ht* ht_create(const size_t CAPACITY)
{
    ht* ret = malloc(sizeof(ht));
    if (!ret) return NULL;

    ret->size = 0;
    ret->capacity = CAPACITY;
    ret->entries = calloc(CAPACITY, sizeof(ht_entry));

    if (!ret->entries) {
        free(ret);
        return NULL;
    }

    return ret;
}

// Frees a table to memory
void ht_destroy(ht* table) 
{
    if (table == NULL) return;

    for (size_t i = 0; i < table->capacity; ++i)
    {
        if (table->entries[i].key != NULL)
        {
            free(table->entries[i].key);
            free(table->entries[i].value); // Free the value too!
        }
    }

    free(table->entries);
    free(table);
}

// Extends a hashmap to double its size (Pointer Move Implementation)
void ht_extend(ht** table)
{
    ht* old = *table;

    // 1. Allocate new table shell
    ht* new_table = malloc(sizeof(ht));
    if (!new_table) return; // Note: Caller should technically handle this failure

    new_table->capacity = old->capacity * 2;
    new_table->size = old->size; // Size remains the same
    new_table->entries = calloc(new_table->capacity, sizeof(ht_entry));

    if (!new_table->entries) {
        free(new_table);
        return;
    }

    // 2. MOVE pointers from old to new (Rehashing)
    for (size_t i = 0; i < old->capacity; ++i)
    {
        if (old->entries[i].key == NULL) continue;

        // Recalculate hash for the NEW capacity
        uint32_t computed_hash = hash(old->entries[i].key, strlen(old->entries[i].key));
        size_t idx = computed_hash % new_table->capacity;

        // Linear probing for collisions in the NEW table
        while (new_table->entries[idx].key != NULL) {
            idx++;
            if (idx >= new_table->capacity) idx = 0;
        }

        // 3. COPY THE STRUCT, NOT THE DATA
        // We simply copy the pointers. The actual data on the heap stays where it is.
        new_table->entries[idx] = old->entries[i]; 
    }

    // 4. Free ONLY the old array wrapper, NOT the keys/values
    free(old->entries); 
    free(old);

    *table = new_table;
}

// Public function for setting entries in a hash table
const char* ht_set(ht** ptable, const char* key, void* value, size_t value_len) 
{
    if (ptable == NULL || *ptable == NULL || key == NULL || value == NULL) return NULL;

    ht* table = *ptable;

    // Resize if load factor >= 0.5
    if (table->size >= table->capacity / 2) 
    {
        ht_extend(ptable);
        table = *ptable; // Update local pointer
    }

    return ht_set_entry(table->entries, table->capacity, key, value, value_len, &table->size);
}

// Gets a value with a matching key if present
void* ht_get(ht* table, const char* key)
{
    if (table == NULL || key == NULL) return NULL;

    uint32_t computed_hash = hash(key, strlen(key));
    size_t idx = computed_hash % table->capacity;

    while (table->entries[idx].key != NULL)
    {
        if (strcmp(table->entries[idx].key, key) == 0) // Found
        {
            return table->entries[idx].value;
        }
        idx++;
        if (idx >= table->capacity) 
        {
            idx = 0;
        }
    }

    return NULL;
}

// Deletes the entry indexed by the key 
const char* ht_delete(ht* table, const char* key)
{
  if (table == NULL || key == NULL) return NULL;
  
  int idx = hash(key, strlen(key)) % table->capacity;

  // If key doesn't exist in the first place, return NULL
  if (table->entries[idx].key == NULL) return NULL;

  free(table->entries[idx].key); //<< otherwise, free the key

  // Free if the entry value is not null
  if (table->entries[idx].value != NULL) 
  {
    free(table->entries[idx].value);
  }
  
  // Set the entry vlen to 0
  table->entries[idx].vlen = 0;

  table->size--;

  return key;
}

size_t ht_length(ht* table) {
    return table ? table->size : 0;
}

size_t ht_capacity(ht* table) {
    return table ? table->capacity : 0;
}
