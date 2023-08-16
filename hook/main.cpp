#include <stdio.h>
#include <stdlib.h>
using namespace std;
int main()
{
    //calloc test
    char * ptr = (char *)calloc(4, sizeof(char));
    *ptr = 88;
    printf("[0]=%d\n", *ptr);
    free(ptr);
    // malloc test
    // char *ptr = (char *)malloc(sizeof(char) * 4);
    // *ptr = 88;
    // printf("[0]=%d\n", *ptr);
    // free(ptr);
    return 0;
}
