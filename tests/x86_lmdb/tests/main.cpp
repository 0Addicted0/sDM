#include <cstdio>
#include <cstdlib>
#include <lmdb.h>
using namespace std;
int main()
{
    //calloc test
    char * ptr = (char *)calloc(4, sizeof(char));
    *ptr = 88;
    printf("[0]=%d\n", *ptr);
    free(ptr);
    // cout << "lmdb version:"<< mdb_version(0, 0, 0)<<endl;
    // malloc test
    // char *ptr = (char *)malloc(sizeof(char) * 4);
    // *ptr = 88;
    // printf("[0]=%d\n", *ptr);
    // free(ptr);
    return 0;
}
