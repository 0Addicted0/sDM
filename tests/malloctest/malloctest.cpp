#include <stdio.h>
#include <stdlib.h>
#include "gem5/sdmmalloc.h"
const char pat[] = "Hello,sDM";
#define test_size PAGE_SIZE  // 4MB
int main()
{
    // int *p = (int *)sdmmalloc(sizeof(int) * 1023 );
    char *p = (char *)sdmmalloc(sizeof(char) * test_size);
    // 内存安全测试

    printf("test ret ptr %p\n", p);
    printf("mytest:%c%c%c\n", p[0],p[1],p[2]);
    for (int i = 0; i < test_size; i += CL_SIZE)
    {
        p[i] = '1';
        p[i + 1] = 'b';
    }
    printf("mytest:%c\n", p[0]); // 越界:4096->0
    sdmfree(p);
    return 0;
}