#ifndef _SDM_H_
#define _SDM_H_
#include <stdio.h>
// #define _sDM_ 1 // enable _sDM_
#ifdef _sDM_
#include "gem5/sdmmalloc.h"
// #define calloc(x,y) sdmmalloc((x)*(y))
// #define malloc(x) sdmmalloc(x)
// #define realloc(x,y) sdmrealloc(x,y)
// #define free(x) sdmfree(x)
#endif
#endif