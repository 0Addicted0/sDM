#include "gem5/sdmmalloc.h"

static unordered_map<void *, void *> addrmap; // 记录原起始地址
void *sdmmalloc(size_t len)
{
    len = (len & PAGE_ALIGN_MASK) + (len & (~PAGE_ALIGN_MASK) == 0 ? 0 : PAGE_SIZE); // 长度对齐
    printf("sDMAlloc:len = %d\n", (int)len);
    size_t newlen = len + PAGE_SIZE;
    void *mallocret = malloc(newlen);
    printf("sDMAlloc:ret %p\n", mallocret);
    void *addr = (void *)((uint64_t)mallocret + PAGE_SIZE - ((uint64_t)mallocret & (~PAGE_ALIGN_MASK)));
    printf("sDMAlloc:vaddr %p\n", addr); // 地址对齐,但是会导致可用空间比申请的空间大一点（最多一个页?）
    addrmap[addr] = mallocret;
    for (int i = 0; i < len; i += PAGE_SIZE)
    {
        ((char *)addr)[i] = 'a';
        ((char *)addr)[i+1] = 'b';
        ((char *)addr)[i+2] = 'c';
    }
    // 用于测试物理地址（gem5的虚拟地址）是否可直接写入
    // ((char *)addr)[1] = 2;
    if (!m5_sdm_poster((long int)addr, len)) // 不知道为什么，m5ops解析无法解析int32的参数
    {
        printf("errors\n");
    }
    return addr;
}

bool sdmfree(void *ptr)
{

    if (addrmap.count(ptr) == 0)
    {
        cout << "sDMAlloc:error,pointer is a invalid addr" << endl;
        return false;
    }
    void *realptr = addrmap[ptr];
    free(realptr);
    addrmap.erase(ptr);
    return true;
}
