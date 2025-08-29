
#pragma once

#include <assert.h>
#include <stdalign.h>
#include <stdint.h>

#include "parameters.h"

struct FreeNode {
  // Next free index
  uint16_t next;
  // Free index
  uint16_t index;
};

struct FreeList {
  // Internal list
  // Max use case is T length array
  struct FreeNode list[T];
  // Head
  uint16_t head;
  // Tail
  uint16_t tail;
  // Length
  uint16_t len;
};

void ll_free(struct FreeList *list, uint16_t index);
uint16_t ll_alloc(struct FreeList *list);
