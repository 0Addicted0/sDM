#include <stdio.h>
#include <stdlib.h>
#include "gem5/sdmmalloc.h"
int main()
{
    // int *p = (int *)sdmmalloc(sizeof(int) * 1023 );
    char *p = (char *)sdmmalloc(sizeof(char) * PAGE_SIZE);
    // 内存安全测试
    printf("test ret ptr %p\n", p);
    // p[0] = 0;
    printf("mytest:%x\n",p[0]);// 越界
    sdmfree(p);
    return 0;
}