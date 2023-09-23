#include "gem5/sdmmalloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
inline size_t align(size_t len)
{
	return (len & PAGE_ALIGN_MASK) + ((len & (~PAGE_ALIGN_MASK)) == 0 ? 0 : sDM_PAGE_SIZE); // 长度对齐
}
inline void walk(void *ptr, size_t len)
{
	for (int i = 0; i < len; i += sDM_PAGE_SIZE)// raise mapping
        ((char *)ptr)[i] = 0;
}
void *_sdm_malloc_(size_t *_size_)
{
	*_size_ = align(*_size_);
	void *ptr = malloc((*_size_)+ sDM_PAGE_SIZE);
	void *addr = (void *)((uint64_t)ptr + sDM_PAGE_SIZE - ((uint64_t)ptr & (~PAGE_ALIGN_MASK))); // algined ptr in page size
	walk(addr, *_size_);
	*(uint64_t *)((uint8_t *)addr - sizeof(uint64_t)) = (uint64_t)ptr;// log the original ptr
	return addr;
}

void *sdmmalloc(size_t len)
{
    void *addr = _sdm_malloc_(&len);
	if (!m5_sdm_poster((uint64_t)addr, len)) // m5ops解析无法解析int32的参数
	{
		printf("[lib]Apply for secure space failed\n");
    }
    else 
    {
		printf("[lib]malloc[0x%p, %ld]...\n", addr, len);
		// printf("[lib]Apply for secure space[0x%p] success\n", addr);
    }
	return addr;
}

void *sdmcalloc(size_t len)
{
	printf("[lib]calloc\t");
	return sdmmalloc(len);
}

void *sdmrealloc(void *__ptr, size_t __size)
{
	size_t size = (size_t)m5_sdm_finder((uint64_t)__ptr);
	if(size == 0)
	{
		// non-secure space
		return realloc(__ptr, __size); 
	}
	void *addr = _sdm_malloc_(&__size);
	assert(m5_sdm_realloc((uint64_t)addr, __size, (uint64_t)__ptr, size));
	printf("[lib]realloc[0x%p->0x%p, %ld]...\n", __ptr, addr, __size);
	return addr;
}

bool sdmfree(void *ptr)
{
    if(!m5_sdm_finder((uint64_t)ptr))
	{
		// printf("[lib]Destroy non-secure space[0x%p]\n", ptr);
		free(ptr);
        return false;
	}
    void *realptr = (void *)(*((uint64_t *)((uint8_t *)ptr - sizeof(uint64_t))));
    m5_sdm_puller((uint64_t)ptr);   //释放SDM 安全空间
	printf("[lib]Destroy secure space[0x%p]\n", ptr);
    free(realptr);
    return true;
}
