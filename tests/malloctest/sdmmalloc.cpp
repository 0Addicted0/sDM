#include "gem5/sdmmalloc.h"

static unordered_map<void *, void *> addrmap; // 记录原起始地址
void *sdmmalloc(size_t len)
{
    len = (len & PAGE_ALIGN_MASK) + (len & (~PAGE_ALIGN_MASK) == 0 ? 0 : sDM_PAGE_SIZE); // 长度对齐
    // printf("sDMAlloc:size %ld KB\n", len/1024);
    size_t newlen = len + sDM_PAGE_SIZE;
    void *mallocret = malloc(newlen);
    // printf("sDMAlloc:ret %p\n", mallocret);
    void *addr = (void *)((uint64_t)mallocret + sDM_PAGE_SIZE - ((uint64_t)mallocret & (~PAGE_ALIGN_MASK)));
    // printf("sDMAlloc:vaddr %p\n", addr); // 地址对齐,但是会导致可用空间比申请的空间稍大,但不超过一个页
    addrmap[addr] = mallocret;
    for (int i = 0; i < len; i += sDM_PAGE_SIZE)
    {
        ((char *)addr)[i] = 0;
    }
    // 用于测试物理地址（gem5的虚拟地址）是否可直接写入
    if (!m5_sdm_poster((long int)addr, len)) // m5ops解析无法解析int32的参数
    {
        printf("Apply for secure space failed\n");
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
    m5_sdm_puller((uint64_t)ptr);   //释放SDM 安全空间
    free(realptr);
    addrmap.erase(ptr);
    return true;
}
