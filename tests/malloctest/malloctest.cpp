#include <stdio.h>
#include <stdlib.h>
#include "gem5/sdmmalloc.h"
const char pat[] = "Hello,sDM";
#define test_size PAGE_SIZE * 1024 // 4MB
int main()
{
    // int *p = (int *)sdmmalloc(sizeof(int) * 1023 );
    char *p = (char *)sdmmalloc(sizeof(char) * test_size);
    // 内存安全测试
    printf("test ret ptr %p\n", p);
    for (int i = 0; i < test_size; i += CL_SIZE)
        for (int j = 0; j < 9; j++)
            p[i + j] = pat[j];
    printf("mytest:%x\n", p[0]); // 越界:4096->0
    sdmfree(p);
    return 0;
}