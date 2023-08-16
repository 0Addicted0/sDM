#define _GNU_SOURCE
#include <stdbool.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "gem5/m5ops.h"
#define PAGE_ALIGN_MASK 0xfffffffffffff000 // 转换为页面对齐地址
#define sDM_PAGE_SIZE (1<<12)
#define CL_SIZE (1<<6)
// #define _sDM_ 1

static void *(*real_malloc)(size_t) = NULL;
static void *(*real_calloc)(size_t, size_t) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;
static void (*real_free)(void *) = NULL;
static __thread int no_hook = 0; // 线程局部变量
static void __attribute__((constructor)) init(void) // 在main函数之前执行,保存旧函数指针
{
	real_malloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
	real_calloc = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
	real_free = (void (*)(void *))dlsym(RTLD_NEXT,"free");
	no_hook = 1;
	printf("[lib]init...\n");
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
	void *ptr = (*real_malloc)(*_size_ + sDM_PAGE_SIZE);
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
	void *ptr = NULL;
	if (no_hook)
	{
		return (*real_malloc)(len);
	}
	void *addr = _sdm_malloc_(&len);
	no_hook = 1;
#ifdef _sDM_
	if (!m5_sdm_poster((uint64_t)addr, len)) // m5ops解析无法解析int32的参数
	{
		printf("[lib]Apply for secure space failed\n");
    }
    else 
    {
		printf("[lib]Apply for secure space[0x%p] success\n", addr);
    }
#endif
#ifndef _sDM_
	printf("[lib]malloc hook...\n");
#endif
	no_hook = 0;
	return addr;
}

void *calloc(size_t __nmemb, size_t __size)
{
	no_hook = 1;
	printf("[lib]calloc hook...\n");
	no_hook = 0;
	return malloc(__nmemb * __size);
}
// void *realloc(void *__ptr, size_t __size)
// {
// 	void *nptr = malloc(__size);
// 	memcpy(nptr, __ptr, __size);
// }
void free(void *ptr)
{
	no_hook = 1;
#ifdef _sDM_
	if(!m5_sdm_finder((uint64_t)ptr))
	{
		printf("[lib]Destroy non-secure space[0x%p]\n", ptr);
		no_hook = 0;
		return (*real_free)(ptr);
	}
	printf("[lib]Destroy secure space[0x%p]\n", (void *)(*(uint64_t *)(ptr - sizeof(uint64_t))));
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
