#include <stdio.h>
#include <stdlib.h>
extern "C"
{
    #include "gem5/sdmmalloc.h"
}
const char pat[] = "Hello,sDM";
#define test_size sDM_PAGE_SIZE * 2//1024 * 32 // 4MB*32
int main()
{
    // int *p = (int *)sdmmalloc(sizeof(int) * 1023 );
    char *p = (char *)sdmmalloc(sizeof(char) * test_size);
    // 内存安全测试
    p[0] = 'y';
    p[1] = 'q';
    p[2] = 'y';
    printf("test ret ptr %p\n", p);
    printf("mytest:%c%c%c\n", p[0], p[1], p[2]);
    for (int i = 0; i < test_size; i += CL_SIZE)
    {
        p[i] = '&';
        p[i + 1] = '&';
    }
    for (int i = 0; i < test_size; i += CL_SIZE)
    {
        printf("mytest:%c\n", p[i]);
    }
    
    sdmfree(p);
    return 0;
}