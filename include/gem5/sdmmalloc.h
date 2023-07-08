#pragma once
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <unordered_map>
#include "gem5/m5ops.h"

#define PAGE_ALIGN_MASK 0xfffffffffffff000 // 转换为页面对齐地址  , +by psj:PAGE mask错误
#define sDM_PAGE_SIZE 4096
#define CL_SIZE 64

using namespace std;

void *sdmmalloc(size_t len);
bool sdmfree(void *ptr);