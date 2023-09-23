#include <iostream>
#define PAGE_ALIGN_MASK 0x1000
#define PAGE_SIZE 4096
#define CL_SIZE 64
using namespace std;
int main()
{
    int cnt = 0;
    for (uint64_t rva = 0 + 128*PAGE_SIZE; rva <= 0x1000+ 128*PAGE_SIZE; rva += CL_SIZE,cnt++)
        cout<<cnt <<":"<< (rva & ((PAGE_SIZE>>1)-1)) / CL_SIZE << endl;
    return 0;
}