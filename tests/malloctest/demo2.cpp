#include <stdio.h>
#include <string.h>
#include "gem5/sdmmalloc.h"
const char pat[] = "Without sDMM is not a good idea!";
int main(){
    // welc();
    char *p = (char *)malloc(sizeof(char) * 1024);
    memset(p, 0, 64);
    // scanf("%s", p);
    printf("input:\n%s\n", pat);
    printf("ptr=%p\n", p);
    for (int i = 0; i < 16;i++)
        memcpy(p + i * 64, pat, 33);
    printf("secret:%s\n", p);
    free(p);
    return 0;
}