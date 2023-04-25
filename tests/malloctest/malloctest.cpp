#include <stdio.h>
#include <stdlib.h>
#include "gem5/sdmmalloc.h"
int main()
{
    int *p = (int *)sdmmalloc(sizeof(int) * 1023 );
    // 内存安全测试
    //printf("sdmmalloc ret ptr %p", p);
    p[0] = 0;
    printf("%d\n",p[4096]);
    sdmfree(p);
    return 0;
}