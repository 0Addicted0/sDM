/**
 * This is a secure disaggregated remote shared-memory system
 * It's two fundmental aspects are confidentiality and integrity of data in remote DDR(NVM)
 * We decouple the pool management and data management
 * 1. For the confidentiality: we use CME which is consistent with existing research
 * 2. For the integrity: We propose IncompleteIntegrityTree which is a space-friendly scheme
 *    based on SGX-style integrity tree
 * 3. sDM size smaller than 1TB = 1024GB = 2^20MB = 2^30KB
 * Following is the defination of secure remote memory structure
 * v1.0: unable to dynamic extend
 * v1.1:
 *   1. change counter mode to major-minor
 *   2. overcome uncontinuous region protected
 */
#ifndef _SDM_HH_
#define _SDM_HH_

#include "sDM_def.hh"
#include "./IIT/IIT.hh"
#include "CME/cme.hh"

#include <unordered_map>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#define MAX_HEIGHT 5 // 32G
/**
 * 约定
 * 1.远端内存的分配的粒度是页面(4K),传输粒度也应为4K以上
 * 2.IT(integrity tree)的节点大小为64B(CacheLine)
 * 3.申请时本地[内存控制器(CXL扩展内存控制器)]
 * 会对安全内存的申请做修改：
 *      1. 修改申请大小
 *      2. 在本地记录安全内存的metadata
 *      3. 对于相应的Root的管理,假设Root保证能在本地安全存储
 */
namespace gem5
{
    namespace sDM
    {
        typedef uint64_t sdmIDtype;                // sdm空间编号类型 u64
        typedef uint64_t sdm_size;                 // sdm保护的数据的大小
        typedef uint8_t *sdm_dataPtr;              // 数据区指针
        typedef uint8_t sdm_hashKey[SM4_KEY_SIZE]; // sdm空间密钥
        typedef uint8_t sdm_CMEKey[SM3_KEY_SIZE];  // sdm hash密钥
        typedef uint8_t sdm_HMACPtr[HMAC_SIZE];    // 一个SM3 HASH 256bit
        typedef uint8_t CL[CL_SIZE];
        uint64_t ceil(uint64_t a, uint64_t b);
        uint64_t getIITsize(uint64_t data_size);
        /**
         * @author
         * yqy
         * @brief
         * 记录数据页面指针的二元组
         * <数据页面起始远端物理地址,到目前为止页面数量,此页面向后的连续页面数量>便于计算偏移
         * @attention
         * size=16B
         */
        typedef struct _pagePtrPair
        {
            Addr curPageAddr;
            uint32_t pnum, cnum;
        } sdm_pagePtrPair;
        typedef sdm_pagePtrPair *sdm_pagePtrPairPtr;
        /**
         * @brief
         * 为解决数据空间在远端内存物理上可能不连续
         * @brief
         * 用来查找距离该sdm空间内逻辑上的相对偏移
         * @attention 本地申请来存放这些不连续页的指针集的物理空间本身也可能不连续
         * @attention 因为我们并不阻止节点使用本地DRAM
         * @author
         * yqy
         */
        typedef struct _sdm_dataPagePtrPage
        {
            sdm_pagePtrPair pair[PAGE_SIZE / PAIR_SIZE - 1]; // 0 ~ PAGE_SIZE / PAIR_SIZE - 1 - 1
            sdmIDtype reserved;                              // 保留,本页存储的数据页面指针集所属的sdm编号
            sdm_dataPtr next;                                // 指向下一个存放数据页面指针集合的本地物理页
            /**
             * @author yqy
             * @brief 返回本页存储的数据页面指针集的最大地址范围
             * @brief 用于查找地址所在页的物理地址
             * @param 本页首地址
             * @attention 需要接入Packet
             */
            Addr getMaxBound(Addr paddr)
            {
                // 构造Packet访问 pair[PAGE_SIZE / PAIR_SIZE - 1 - 1]
                // addr: paddr + (PAGE_SIZE / PAIR_SIZE - 1 - 1) * PAIR_SIZE;
                // 构造packet并访问
                // ...
                // 假设得到的结果存储在rbound中
                sdm_pagePtrPair rbound;
                Addr p = rbound.curPageAddr + (rbound.cnum * PAGE_SIZE) - 1;
                return p;
            }
        } sdm_dataPagePtrPage;
        typedef sdm_dataPagePtrPage *sdm_dataPagePtrPagePtr;

        /**
         * @brief
         * 为解决HMAC在远端内存物理上可能不连续
         * @attention 本地申请来存放这些不连续页的指针集的物理空间本身也可能不连续
         * @attention 因为我们并不阻止节点使用本地DRAM
         * @author
         * yqy
         */
        typedef struct _sdm_hmacPagePtrPage
        {
            sdmIDtype id;     // 保留,本页存储的HMAC数据页面指针集所属的sdm编号
            sdm_dataPtr next; // 指向下一个存放数据页面指针集合的本地物理页
            sdm_pagePtrPair pair[PAGE_SIZE / PAIR_SIZE - 1];
        } sdm_hmacPagePtrPage;
        typedef sdm_hmacPagePtrPage *sdm_hmacPagePtrPagePtr;

        /**
         * @brief
         * 为解决IIT在远端内存物理上可能不连续
         * @attention 本地申请来存放这些不连续页的指针集的物理空间本身也可能不连续
         * @attention 因为我们并不阻止节点使用本地DRAM
         * @author
         * yqy
         */
        typedef struct _sdm_iitNodePagePtrPage
        {
            sdmIDtype id;     // 保留,本页存储的HMAC数据页面指针集所属的sdm编号
            sdm_dataPtr next; // 指向下一个存放数据页面指针集合的本地物理页
            sdm_pagePtrPair pair[PAGE_SIZE / PAIR_SIZE - 1];
        } sdm_iitNodePagePtrPage;
        typedef sdm_iitNodePagePtrPage *sdm_iitNodePagePtrPagePtr;

        /**
         * 单个sdm的metadata结构如下
         * |metadata|
         * |         -------------------\
         * |                             ------------------------------------\
         * |-数据空间大小-|-数据页指针链表头-|-HMAC指针链表头-|-完整性树指针链表头-|
         */
        typedef struct _sdm_space
        {
            sdmIDtype id;                            // 每个space拥有唯一id,用于避免free-malloc counter重用问题
            sdm_size sDataSize;                      // 数据空间大小字节单位
            sdm_dataPagePtrPagePtr dataPtrPagePtr;   // 数据物理页地址集指针
            sdm_hmacPagePtrPagePtr HMACPtrPagePtr;   // HMAC页指针集指针
            sdm_iitNodePagePtrPagePtr iITPtrPagePtr; // 完整性树页指针集指针
            // iit_root Root;                        // 当前空间树Root
            sdm_hashKey iit_key; // 当前空间完整性树密钥
            sdm_CMEKey cme_key;  // 当前空间内存加密密钥
            /**
             * @brief 返回解密的密钥
             * @param key_type 需要返回的密钥标识:HASH_KEY_TYPE,CME_KEY_TYPE
             * @attention 未实现
             */
            void key_get(int key_type, uint8_t *key)
            {
                if (key_type == HASH_KEY_TYPE)
                {
                    //... decryt iit key
                    memcpy(key, iit_key, sizeof(sdm_hashKey));
                }
                else if (key_type == CME_KEY_TYPE)
                {
                    //... decrypt cme key
                    memcpy(key, cme_key, sizeof(sdm_CMEKey));
                }
            }
        } sdm_space;

        /**
         * 这是一个页面HMAC结构
         */
        typedef struct _sdm_page_hmac
        {
            sdm_HMACPtr hmac[CL_SIZE / HMAC_SIZE];

            uint8_t *high() // 高半页的HMAC
            {
                return (uint8_t *)((hmac + 1));
            }
            uint8_t *low() // 低半页的HMAC
            {
                return (uint8_t *)hmac;
            }
            void print()
            {
                for (int i = 0; i < CL_SIZE; i++)
                {
                    for (int j = 1; j <= HMAC_SIZE; j++)
                        printf("%02x ", hmac[i][j]);
                    printf("  ");
                }
                printf("\n");
            }
        } sdm_page_hmac;
        typedef sdm_page_hmac *sdm_page_hmacPtr;

        /**
         * sDMmanager管理所有sdm相关操作，是sdm的硬件抽象
         */
        class sDMmanager
        {
        private:
            // 数据页页指针集指针
            // sdm_dataPagePtrPagePtr dataPtrPagePtr;
            std::vector<sdm_dataPagePtrPagePtr> dataPtrPage;
            sdmIDtype sdm_space_cnt;                         // 全局单增,2^64永远不会耗尽, start from 1
            int sdm_pool_id;                                 // 可用本地内存池(内存段)编号
            std::vector<sdm_space> sdm_table;                // id->sdm
            std::unordered_map<Addr, uint64_t> sdm_paddr2id; // paddr -> id

        public:
            sDMmanager(int sdm_pool_id);
            ~sDMmanager();
            sdmIDtype isContained(Addr paddr);
            bool sDMspace_register(std::vector<Addr> &pageList);
            Addr getVirtualOffset(sdmIDtype id, Addr paddr);
            int getKeyPath(sdmIDtype id, Addr rva, Addr *keyPathAddr, iit_NodePtr keyPathNode);
            void read(Addr paddr);
            bool verify(Addr paddr, sdmIDtype id, Addr *rva, int &h, Addr *keyPathAddr, iit_NodePtr keyPathNode, sdm_hashKey key);
            void write(Addr paddr);
        };
    }
}
#endif
