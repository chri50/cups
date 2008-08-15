#ifndef _BITSET_H
#define _BITSET_H

#include <stdlib.h>

typedef int * BITSET;

static inline void bit_set(BITSET bs,int num)
{
  bs[num/(8*sizeof(int))]|=1<<(num%(8*sizeof(int)));
}

static inline int bit_check(BITSET bs,int num)
{
  return bs[num/(8*sizeof(int))]&1<<(num%(8*sizeof(int)));
}

// use free() when done. returns NULL on bad_alloc
static inline BITSET bitset_new(int size)
{
  return (BITSET)calloc(1,((size+31)&~31)/8);
}

#endif
