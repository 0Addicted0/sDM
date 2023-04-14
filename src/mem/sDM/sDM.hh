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
#include "CME/CME.hh"

#include <unordered_map>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include "../../sim/mem_pool.hh"
#include "../packet.hh"
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
        typedef uint8_t sdm_HMAC[HMAC_SIZE];       // 一个SM3 HASH 256bit
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
            uint32_t pnum; // 该空间到此页面(不含)的前面连续的逻辑页面数量
            uint32_t cnum; // 包含该地址其后连续的页面数量(>=1)
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
        // typedef struct _sdm_dataPagePtrPage
        // {
        //     sdm_pagePtrPair pair[PAGE_SIZE / PAIR_SIZE - 1]; // 0 ~ PAGE_SIZE / PAIR_SIZE - 1 - 1
        //     sdmIDtype reserved;                              // 保留,本页存储的数据页面指针集所属的sdm编号
        //     sdm_dataPtr next;                                // 指向下一个存放数据页面指针集合的本地物理页
        // } sdm_dataPagePtrPage;
        // typedef sdm_dataPagePtrPage *sdm_dataPagePtrPagePtr;

        /**
         * @brief
         * 为解决IIT在远端内存物理上可能不连续
         * @attention 本地申请来存放这些不连续页的指针集的物理空间本身也可能不连续
         * @attention 因为我们并不阻止节点使用本地DRAM
         * @author
         * yqy
         */
        // typedef struct _sdm_iitNodePagePtrPage
        // {
        //     sdmIDtype id;     // 保留,本页存储的HMAC数据页面指针集所属的sdm编号
        //     sdm_dataPtr next; // 指向下一个存放数据页面指针集合的本地物理页
        //     sdm_pagePtrPair pair[PAGE_SIZE / PAIR_SIZE - 1];
        // } sdm_iitNodePagePtrPage;
        // typedef sdm_iitNodePagePtrPage *sdm_iitNodePagePtrPagePtr;

        /**
         * @author yqy
         * @brief skip list的结构
         * @brief 16Byte
         */
        typedef struct _skip_list_jmp
        {
            Addr next;     // 连续段页面首地址
            Addr maxBound; // 连续页面段的最大地址
        } skip_jmp;
        /**
         * @author yqy
         * @brief skip list的结构
         * @brief 16Byte
         */
        typedef struct _skip_list_jmp_local
        {
            uint64_t con;  // 连续页面段后还有几个页面(包含当前页面)
            Addr maxBound; // 连续页面段的最大地址
        } local_jmp;
        /**
         * @brief 为解决HMAC/IIT在远端内存物理上可能不连续
         * @author yqy
         * @attention 本地申请来存放这些不连续页的指针集的物理空间本身也可能不连续
         * @attention因为我们并不阻止节点使用本地DRAM
         * @attention 合并了前面两个结构
         */
        typedef struct _sdm_PagePtrPage
        {
            // 默认为两级
            union
            {
                skip_jmp jmp[(PAGE_SIZE / SKIP_SIZE) - 1];         // 指向下一个存放数据页面指针集合的本地物理页,jmp[i]表示其后第2^(i[0,...])个连续段
                sdm_pagePtrPair pair[(PAGE_SIZE / PAIR_SIZE) - 1]; // 剩余可用pair数
            };
            local_jmp cur_segMax; // 当前连续页段的最大,此结构中的next保留未用
        } sdm_PagePtrPage;
        typedef sdm_PagePtrPage *sdm_PagePtrPagePtr;
        typedef sdm_PagePtrPage sdm_hmacPagePtrPage;
        typedef sdm_PagePtrPage sdm_iitNodePagePtrPage;
        typedef sdm_hmacPagePtrPage *sdm_hmacPagePtrPagePtr;
        typedef sdm_iitNodePagePtrPage *sdm_iitNodePagePtrPagePtr;

        /**
         * @author yqy
         * @brief 用于记录申请的物理空间块
         */
        typedef struct _phy_space_block
        {
            Addr start;
            int npages;
        } phy_space_block;
        typedef phy_space_block *phy_space_blockPtr;
        /**
         * 单个sdm的metadata结构如下
         * |metadata|
         * |         -------------------\
         * |                             --------------------------------------\
         * |-数据空间大小-|-数据页指针链表头-|-HMAC指针链表头-|-完整性树指针链表头-|
         */
        typedef struct _sdm_space
        {
            sdmIDtype id;                          // 每个space拥有唯一id,用于避免free-malloc counter重用问题
            sdm_size sDataSize;                    // 数据空间大小字节单位
            uint32_t iITh;                         // 完整性树高
            Addr datavAddr;                        // 数据虚拟地址起始
            sdm_hmacPagePtrPagePtr HMACPtrPagePtr; // HMAC页指针集指针
            int hmac_skip;
            sdm_iitNodePagePtrPagePtr iITPtrPagePtr; // 完整性树页指针集指针
            int iit_skip;
            // iit_root Root;                        // 当前空间树Root(暂时使用一个单独的64arity节点level0代替)
            sdm_hashKey iit_key; // 当前空间完整性树密钥
            sdm_CMEKey cme_key;  // 当前空间内存加密密钥
            /**
             * @brief 返回解密的密钥
             * @param key_type 需要返回的密钥标识:HASH_KEY_TYPE,CME_KEY_TYPE
             * @param key 接收key的指针
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
            sdm_HMAC hmac[CL_SIZE / HMAC_SIZE];

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
            // std::vector<sdm_dataPagePtrPagePtr> dataPtrPage;
            sdmIDtype sdm_space_cnt;                                                          // 全局单增,2^64永远不会耗尽, start from 1
            int remote_pool_id;                                                               // 可用本地内存池(内存段)编号
            int local_pool_id;                                                                // 记录每个process/workload的本地pool的编号
            MemPools *mem_pools;                                                              // 实例化时的内存池指针
            std::vector<sdm_space> sdm_table;                                                 // id->sdm
            std::unordered_map<Addr, uint64_t> sdm_paddr2id;                                  // paddr -> id
            bool sdm_malloc(int npages, int pool_id, std::vector<phy_space_block> &phy_list); // 申请本地内存物理空间
            void build_SkipList(std::vector<phy_space_block> &remote_phy_list, std::vector<phy_space_block> &local_phy_list,
                                int skip, int ac_num, int lnpages);
            void write2Mem(uint32_t byte_size, uint8_t *data, Addr gem5_addr);
            void read4Mem(uint32_t byte_size, uint8_t *container, Addr gem5_addr);
            bool hmac_verify(Addr dataPAddr, Addr rva, Addr *hmacAddr, sdmIDtype id,
                             uint8_t *hpg_data, iit_NodePtr counter, sdm_hashKey hash_key);
            Addr find(Addr head, Addr offset, int skip, int known, int &pnum);

        public:
            sDMmanager(int sdm_pool_id);
            ~sDMmanager();
            sdmIDtype isContained(Addr paddr);
            bool sDMspace_register(std::vector<Addr> &pageList);
            Addr getVirtualOffset(sdmIDtype id, Addr paddr);
            int getKeyPath(sdmIDtype id, Addr rva, Addr *keyPathAddr, iit_NodePtr keyPathNode);
            bool verify(Addr paddr, uint8_t *hpg_data, sdmIDtype id, Addr *rva, int *h,
                        Addr *keyPathAddr, iit_NodePtr keyPathNode, Addr *hmacAddr, sdm_hashKey hash_key);
            void write(PacketPtr pkt);
            void read(PacketPtr pkt);
        };
    }
}
#endif
