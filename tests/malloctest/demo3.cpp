#include <stdio.h>
#include <string.h>
#include "gem5/sdmmalloc.h"
const char pat[] = "Without sDMM is not a good idea!";
const char pat2[] = "Easy to be attacked!";
int main(){
    char *p = (char *)sdmmalloc(sizeof(char) * 64);
    memset(p, 0, 64);
    printf("input secret:\n%s\n", pat);
    printf("ptr=%p\n", p);
    memcpy(p, pat, 33);
    printf("change secret:\n%s\n", pat2);
    memcpy(p,pat2,21);
    printf("secret:\n%s\n", p);
    sdmfree(p);
    return 0;
}