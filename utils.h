#ifndef _headerguard_utils_h_
#define _headerguard_utils_h_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* allocate zero-initialised */
#define zalloc(len) calloc(1,len)

/* volatile memset to try & avoid optmising it away */
static void * (* const volatile volatile_memset)(void *,  int, size_t) = memset;
#define memzero(ptr, size)       volatile_memset(   ptr,    0,   size)
#define memfill(ptr, size, fill) volatile_memset(   ptr, fill,   size)

/* shorthand for zeroing, freeing and NULLing pointers */
#define nullpointer(ptr, size) if (ptr != NULL) { memzero(ptr, size); free(ptr); ptr = NULL; }


/* check if a string is not zero and not empty */
extern int strnzero (const char *str);

/* prompt for user input */
extern void prompt (const char *prmt, char *fn, size_t fn_len, const char *dfn);

/* print contents of a string similar to hexdump */
extern void debugbuf (const char *name, const unsigned char *buf, size_t buf_len);

#endif