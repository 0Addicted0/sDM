#define _GNU_SOURCE
#include <stdbool.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "gem5/m5ops.h"
#define PAGE_ALIGN_MASK 0xfffffffffffff000 // 转换为页面对齐地址
#define sDM_PAGE_SIZE (1<<12)
#define CL_SIZE (1<<6)
#define _sDM_ 1 // 是否启用sDM
// #define _SDM_DBG_ 1 // 打印调试信息

static void *(*real_malloc)(size_t) = NULL;
static void *(*real_calloc)(size_t, size_t) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;
static void (*real_free)(void *) = NULL;
static __thread int no_hook = 0; // 线程局部变量
static __thread int no_realloc = 0; // 线程局部变量
static void __attribute__((constructor)) init(void) // 在main函数之前执行,保存旧函数指针
{
	real_malloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
	real_calloc = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
	real_free = (void (*)(void *))dlsym(RTLD_NEXT,"free");
	real_realloc = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
	no_hook = 1;
#ifdef _SDM_DBG_
	printf("[lib]init...\n");
#endif
	no_hook = 0;
}
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
	void *ptr = (*real_malloc)((*_size_)+ sDM_PAGE_SIZE);
#ifdef _sDM_
	void *addr = (void *)((uint64_t)ptr + sDM_PAGE_SIZE - ((uint64_t)ptr & (~PAGE_ALIGN_MASK))); // algined ptr in page size
	walk(addr, *_size_);
	*(uint64_t *)(addr - sizeof(uint64_t)) = (uint64_t)ptr;// log the original ptr
	return addr;
#endif
#ifndef _sDM_
	return ptr;
#endif
}
void *malloc(size_t len)
{
	if (no_hook)
	{
		return (*real_malloc)(len);
	}
	void *addr = _sdm_malloc_(&len);
	no_hook = 1;
#ifdef _sDM_
	if (!m5_sdm_poster((uint64_t)addr, len)) // m5ops解析无法解析int32的参数
	{
#ifdef _SDM_DBG_
		printf("[lib]Apply for secure space failed\n");
#endif
    }
    else 
    {
#ifdef _SDM_DBG_
		printf("[lib]malloc[0x%p, %ld]...\n", addr, len);
		// printf("[lib]Apply for secure space[0x%p] success\n", addr);
#endif
    }
#endif
#ifndef _sDM_
	printf("[lib]malloc[0x%p,%ld]...\n",addr,len);
#endif
	no_hook = 0;
	return addr;
}

void *calloc(size_t __nmemb, size_t __size)
{
	size_t len = __nmemb * __size;
#ifdef _sDM_
	void *addr = _sdm_malloc_(&len);
	no_hook = 1;
	if (!m5_sdm_poster((uint64_t)addr, len)) // m5ops解析无法解析int32的参数
	{
#ifdef _SDM_DBG_
		printf("[lib]Apply for secure space failed\n");
#endif
    }
    else 
    {
#ifdef _SDM_DBG_
		printf("[lib]calloc[0x%p, %ld]...\n", addr, len);
		// printf("[lib]Apply for secure space[0x%p] success\n", addr);
#endif
    }
	no_hook = 0;
#endif
#ifndef _sDM_
	// void *addr = real_calloc(__nmemb, __size);
	void *addr = _sdm_malloc_(&len);
	for(size_t i = 0; i < __nmemb * __size; i++)
		*((char*)addr+i) = 0; // memset(addr, 0, __nmemb * __size);
#endif
	// no_hook = 1;
	// printf("[lib]calloc[0x%p,%ld]...\n", addr, __nmemb * __size);
	// no_hook = 0;
	return addr;
}

void *realloc(void *__ptr, size_t __size)
{
	if(no_realloc)
	{
		return real_realloc(__ptr, __size);
	}
#ifdef _sDM_
	size_t size = (size_t)m5_sdm_finder((uint64_t)__ptr);
	if(size == 0)
	{
		// non-secure space
		return real_realloc(__ptr, __size); 
	}
	void *addr = _sdm_malloc_(&__size);
	assert(m5_sdm_realloc((uint64_t)addr, __size, (uint64_t)__ptr, size));
	no_hook = 1;
#ifdef _SDM_DBG_
	printf("[lib]realloc[0x%p->0x%p, %ld]...\n", __ptr, addr, __size);
#endif
	no_hook = 0;
	return addr;
#endif
#ifndef _sDM_
	void *addr = real_realloc(__ptr, __size); 
	no_realloc = 1;
	printf("[lib]realloc[0x%p->0x%p,%ld]...\n", __ptr, addr, __size);
	no_realloc = 0;
	return addr;
#endif
}

void free(void *ptr)
{
	no_hook = 1;
#ifdef _sDM_
	if(!m5_sdm_finder((uint64_t)ptr))
	{
		// printf("[lib]Destroy non-secure space[0x%p]\n", ptr);
		no_hook = 0;
		return (*real_free)(ptr);
	}
#ifdef _SDM_DBG_
	printf("[lib]Destroy secure space[0x%p]\n", ptr);// (void *)(*(uint64_t *)(ptr - sizeof(uint64_t))));
#endif
#endif
#ifndef _sDM_
	printf("[lib]Destroy non-secure space[0x%p]\n", ptr);
#endif
	no_hook = 0;
#ifdef _sDM_
	m5_sdm_puller((uint64_t)ptr);
	return (*real_free)((void *)(*(uint64_t *)(ptr - sizeof(uint64_t))));
#endif
#ifndef _sDM_
	return (*real_free)(ptr);
#endif
}

// void *calloc(size_t __nmemb, size_t __size)
// {
// 	void *addr = malloc(__nmemb * __size);// wrong, but wwhy?
// 	for(size_t i = 0; i < __nmemb * __size; i++)
// 		*((char*)addr+i) = 0; // memset(addr, 0, __nmemb * __size);
// 	no_hook = 1;
// 	printf("[lib]calloc[0x%p,%ld]...\n",addr, __size);
// 	no_hook = 0;
// 	return addr;
// }
