#pragma once

#include <unistd.h>
#include <stdbool.h>
#include "gem5/m5ops.h"

#define PAGE_ALIGN_MASK 0xfffffffffffff000 // 转换为页面对齐地址  , +by psj:PAGE mask错误
#define sDM_PAGE_SIZE 4096
#define CL_SIZE 64

// #define _SDM_DBG_ 1 // 打印调试信息

void *sdmmalloc(size_t len);
void *sdmrealloc(void *__ptr, size_t __size);
void *sdmcalloc(size_t len);
bool sdmfree(void *ptr);