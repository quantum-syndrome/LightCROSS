
#include "linked_list.h"

void ll_free(struct FreeList *list, uint16_t index) {
  // Wrap around
  struct FreeNode tail = list->list[list->tail];
  struct FreeNode val = {.index = index};
  val.next = tail.next == (T - 1) ? 0 : tail.next + 1;
  list->list[tail.next] = val;
  list->tail = tail.next;
  list->len++;
}

uint16_t ll_alloc(struct FreeList *list) {
  struct FreeNode ret = list->list[list->head];
  list->head = ret.next;
  list->len--;
  return ret.index;
}
