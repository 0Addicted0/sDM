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

#include "sDMdef.hh"
#include "./IIT/IIT.hh"
#include "CME/CME.hh"
#include "simpleCache.hh"

#include "params/sDMmanager.hh"
#include "base/types.hh"
#include "../../sim/system.hh"
#include "../../sim/mem_pool.hh"
#include "../packet.hh"
#include "../port.hh"
#include "../../sim/sim_object.hh"
#include "../../sim/process.hh"
#include "../../sim/clocked_object.hh"

#include <map>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
#include <queue>
#include <list>
#include <set>
// #define SDMDEBUG 1 // 取消校验比较
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

        // struct sDMmanagerParams;
        typedef uint64_t sdmID;                    // sdm空间编号类型 u64
        typedef uint64_t sdm_size;                 // sdm保护的数据的大小
        typedef uint8_t *sdm_dataPtr;              // 数据区指针
        typedef uint8_t sdm_hashKey[SM3_KEY_SIZE]; // sdm space hash密钥(hmac iit)
        typedef uint8_t sdm_CMEKey[SM4_KEY_SIZE];  // sdm space cme密钥
        typedef uint8_t sdm_HMAC[HMAC_SIZE];       // 一个SM3 HASH 256bit
        typedef uint8_t CL[CL_SIZE];
        extern uint64_t ceil(uint64_t a, uint64_t b);
        // 可移入sDMmanager的方法中
        extern uint64_t getIITsize(uint64_t data_size);
        /**
         * @brief 统计
         */
        class sDMstat
        {
        private:
            uint64_t _totWriteCount, _totReadCount;
            std::map<Addr, uint64_t> sp_distrib; // addr <==> access count
            std::map<Tick, uint64_t> ti_distrib; // tick <==> access bytes
            std::string _name;
            // 统计增量
            uint64_t _dw, _dr, _dL1, _dL2, _denc, _ddec, _dhotp;
            // 加解密/hash统计
        public:
            uint64_t _encrypt_counter, _decrypt_counter,_dhash;
            uint64_t L1hits, L2hits, hits;
            uint64_t L1access, L2access, L1miss, L2miss;
            uint64_t HotPageCachehit,HotPageCacheaccess,CtrFilterHits,CtrFilteraccess,CtrBackupaccess;
            sDMstat(std::string name);
            ~sDMstat();
            void addstat(Addr addr, uint32_t byte_size, bool isRead);
            uint64_t getReadCount();
            uint64_t getWriteCount();
            void print_tot();
            void print_cache();
            void start();
            void print_enc_dec();
            void print_distrib();
            void end(uint64_t &dw, uint64_t &dr, uint64_t &dL1, uint64_t &dL2, uint64_t &denc, uint64_t &ddec, uint64_t &dhotp);
            void AccessStats(std::string name,bool access);
        };
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
        //     sdm_pagePtrPair pair[sDM_PAGE_SIZE / PAIR_SIZE - 1]; // 0 ~ sDM_PAGE_SIZE / PAIR_SIZE - 1 - 1
        //     sdmID reserved;                              // 保留,本页存储的数据页面指针集所属的sdm编号
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
        //     sdmID id;     // 保留,本页存储的HMAC数据页面指针集所属的sdm编号
        //     sdm_dataPtr next; // 指向下一个存放数据页面指针集合的本地物理页
        //     sdm_pagePtrPair pair[sDM_PAGE_SIZE / PAIR_SIZE - 1];
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
                skip_jmp jmp[(sDM_PAGE_SIZE / SKIP_SIZE) - 1];         // 指向下一个存放数据页面指针集合的本地物理页,jmp[i]表示其后第2^(i[0,...])个连续段
                sdm_pagePtrPair pair[(sDM_PAGE_SIZE / PAIR_SIZE) - 1]; // 剩余可用pair数
            };
            local_jmp cur_segMax; // 当前连续页段的最大,此结构中的next保留未用
        } sdm_PagePtrPage;        // PAGE
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
         * |-数据空间大小-|-数据页指针链表头-|-HMAC指针链表头-|-完整性树指针表头-|
         */
        typedef struct _sdm_space
        {
            sdmID id;                                // 每个space拥有唯一id,用于避免free-malloc counter重用问题
            Addr datavAddr;                          // 数据虚拟地址起始
            sdm_size sDataSize;                      // 数据空间大小字节单位
            uint32_t iITh;                           // 完整性树高
            sdm_hmacPagePtrPagePtr HMACPtrPagePtr;   // HMAC页指针集指针
            int hmac_skip;                           // hmac数据对表最大skip大小
            sdm_iitNodePagePtrPagePtr iITPtrPagePtr; // 完整性树页指针集指针
            int iit_skip;                            // iit数据对表最大skip大小
            // 52B(43B)->64B
            iit_Node Root;        // 当前空间树Root(暂时使用一个单独的64arity节点level0代替)
            sdm_hashKey hash_key; // 当前空间完整性树密钥 16B
            sdm_CMEKey cme_key;   // 当前空间内存加密密钥 32B
            /**
             * @author yqy
             * @brief 定义排序升序sdm数据空间升序排列
             */
            bool operator<(const struct _sdm_space &x) const
            {
                return datavAddr + sDataSize < x.datavAddr + x.sDataSize;
            }
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
                    //... decryt hash key with cpu key
                    memcpy(key, hash_key, sizeof(sdm_hashKey));
                }
                else if (key_type == CME_KEY_TYPE)
                {
                    //... decrypt cme key with cpu key
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
        class sDMmanager : public ClockedObject
        {
        private:
            void write2gem5(uint32_t byte_size, uint8_t *data, Addr gem5_addr);
            void read4gem5(uint32_t byte_size, uint8_t *container, Addr gem5_addr);

        public:
             class sDMLRUCache
            {
                typedef struct DLinkedNode
                {
                    uint64_t key = 0; // 节点地址
                    //uint8_t* value = (uint8_t*)malloc(sizeof(uint8_t) * 64);  // 64 byte 
                    DLinkedNode* pre;
                    DLinkedNode* post;
                    uint8_t* value;
                } DLinkedNode;

            private:
                std::unordered_map<Addr, DLinkedNode*> key2DLinkedNodeptr;

            private:
                int count;
                int Cachelinesize;
            private:
                int capacity;   //cache size(num of cache line)
                int CacheID;	// L1Cache or L2Cache

            private:
                DLinkedNode* head, * tail;
                std::string Cachename="";
                sDMmanager *sDMmanagerptr;

            public:
                sDMLRUCache(sDMmanager* sDMmanagerptr,int capacity, Tick latency, int ID, char* name,int Cachelinesize = 64)
                {
                    this->Cachename = name;
                    this->count = 0;
                    this->capacity = capacity;
                    this->latency = latency;
                    this->CacheID = ID;
                    this->Cachelinesize = Cachelinesize;
                    this->sDMmanagerptr = sDMmanagerptr;

                    head = new DLinkedNode();
                    head->pre = NULL;

                    tail = new DLinkedNode();
                    tail->post = NULL;

                    head->post = tail;
                    tail->pre = head;
                }
                ~sDMLRUCache() {
                    while (head != tail)
                    {
                        auto it = head->post;
                        delete(head);
                        head = it;
                    }
                }
            public:
                Tick latency = 0;
                DLinkedNode* get(Addr key)
                {
                    if (key2DLinkedNodeptr.count(key) > 0)
                    {
                        return key2DLinkedNodeptr[key];
                    }
                    else
                    {
                        return NULL;
                    }
                }
                /**
                 * @brief 
                 * @param newNodeaddr 
                 * @param databuf 
                 * @param retbuf 
                 * |--------value-------|---key---|
                 * @return 当有数据剔除时返回ture
                */
                bool Write2Cache(Addr key, uint8_t* databuf, uint8_t* retbuf) {
                    sDMmanagerptr->lstat->AccessStats(this->Cachename, 1);
                    DLinkedNode* newNode = (DLinkedNode*)malloc(sizeof(DLinkedNode));
                    newNode->value = (uint8_t*)malloc(Cachelinesize);
                    newNode->key = key;
                    memcpy(newNode->value, databuf, Cachelinesize);
                    if (key2DLinkedNodeptr.count(key) == 0) {
                        ++count;
                    }
                    else {
                        removeNode(key2DLinkedNodeptr[key]);
                        free(key2DLinkedNodeptr[key]->value);
                        free(key2DLinkedNodeptr[key]);
                    }
                    key2DLinkedNodeptr[key] = newNode;
                    addNode(newNode);

                    if (count > capacity)
                    {
                        // evict
                        // pop the tail
                        Evict(retbuf);                        
                        return true;
                    }
                    return false;
                }

                void Evict(uint8_t* retbuf) {
                    DLinkedNode* oldtail = popTail();
                    memcpy(retbuf, oldtail->value, Cachelinesize);
                    memcpy(retbuf + Cachelinesize, (uint8_t*)(&oldtail->key), 8);
                    key2DLinkedNodeptr.erase(oldtail->key);
                    removeNode(oldtail);
                    free(oldtail->value);
                    free(oldtail);
                }
            public:
                /**
                 * @brief
                 * @param key
                 * @param value
                 * @param isread 1是读，0是写
                 * @return 返回是否命中，不命中不做任何事
                */
                int access(Addr key, uint8_t* value, bool isread)
                {
                    sDMmanagerptr->lstat->AccessStats(this->Cachename, 1);
                    if (key2DLinkedNodeptr.count(key) > 0)
                    { // hit
                        sDMmanagerptr->lstat->AccessStats(this->Cachename, 0);
                        DLinkedNode *NewNode = key2DLinkedNodeptr[key];
                        if (isread) {
                            memcpy(value, NewNode->value, Cachelinesize);  //读出数据
                        }
                        else {
                            memcpy(NewNode->value, value, Cachelinesize);  //写入新数据
                        }

                        key2DLinkedNodeptr[key] = NewNode;
                        removeNode(NewNode);
                        addNode(NewNode);
                        /*printf("hit L%dCache\n",capacity==4?1:2);*/
                        return true; // 命中
                    }
                    return false; // 未命中
                }
                std::string getname() { return this->Cachename; }
                int getCacheLinesize() {
                    return Cachelinesize;
                }

            private:
                void addNode(DLinkedNode* node)
                {
                    node->pre = head;
                    node->post = head->post;

                    head->post->pre = node;
                    head->post = node;
                }

            private:
                void removeNode(DLinkedNode* node)
                {
                    DLinkedNode* pre = node->pre;
                    DLinkedNode* post = node->post;

                    pre->post = post;
                    post->pre = pre;
                    --count;
                }

            private:
                void moveToHead(DLinkedNode* node)
                {
                    removeNode(node);
                    addNode(node);
                }

            private:
                DLinkedNode* popTail()
                {
                    DLinkedNode* res = tail->pre;
                    return res;
                }
            };

            class sDMKeypathCache
            {
            public:
                sDMmanager* sDMmanagerptr;
                uint64_t  L1access = 0, L2access = 0,memoryaccess = 0;

            public:
                Tick RemoteMemAccessLatency = 0;
                sDMKeypathCache(sDMmanager* sDMmanagerptr,int L1CacheCapacity = 0, int L2CacheCapacity = 0, Tick L1CacheLatency = 0,
                    Tick L2CacheLatency = 0, Tick RemoteMemAccessLatency = 0) {
                    this->L1Cache = new sDMLRUCache(sDMmanagerptr,L1CacheCapacity, L1CacheLatency, 1,(char *)("KeyPathL1"));
                    this->L2Cache = new sDMLRUCache(sDMmanagerptr,L2CacheCapacity, L2CacheLatency, 2,(char *)("KeyPathL2"));
                    this->RemoteMemAccessLatency = RemoteMemAccessLatency;
                    this->sDMmanagerptr = sDMmanagerptr;
                }
                ~sDMKeypathCache();
                sDMLRUCache* L1Cache;
                sDMLRUCache* L2Cache;
                /**
                 * @brief
                 * @param Nodeaddr
                 * @param databuf
                 * @param isread 读还是写，1是读，0是写
                 * @return
                */
                Tick CacheAccess(Addr Nodeaddr, uint8_t* databuf, bool isread);

            };
            //热页面缓存，采用LFU替换策略
            class sDMLFUCache {
            private:
                struct CtrLinkNode {
                    uint8_t* CacheLineAddr;
                    //一个缓存行缓存半页数据。
                    Addr hpageaddr; // 对应的物理地址（半页对齐），用于被驱逐时加入到过滤器中
                    CtrLinkNode* Next;
                    CtrLinkNode* Pre;
                };
                struct CtrLink      //具有相同countr的地址链，链首是最旧的地址cache line
                                    //应该先淘汰
                {
                    CtrLinkNode* head = NULL;
                    CtrLinkNode* tail = NULL;
                    uint64_t ctr;   //该链对应的计数器
                };
                int count=0;
                std::unordered_map<uint64_t, CtrLink*> FreqtoCtrLink;
                std::unordered_map<Addr, CtrLinkNode*> KeytoCtrLinkNode;
                std::unordered_map<Addr, uint64_t> KeytoFreq;
                std::unordered_map<Addr, uint64_t> CtrBackup; // 内存上的计数器备份
                std::list<uint64_t> LifeTimeCtr;  //在备份区淘汰存活时间最久的计数器备份
                std::queue<CtrLink*> CtrLinks;  //计数器链表复用，减少重复申请空间
                std::set<uint64_t> minFreq;  // 快速找到最小的ctr。
            private:
                int capacity=0;   // cache size(num of cache line)
                int CacheID=0;	// L1Cache or L2Cache
                int Threshold=0;
                int CtrBackupsize;  //计数器备份大小
                uint64_t CacheLinesize = 0;
                sDMLRUCache* CtrFilter;
                sDMLRUCache* HotPageCache;

            public:
                /**
                 * breif 该类是本地内存上缓存的远端内存的部分内存及其相关数据的模拟程序
                 * CtrFiltersize 计数器过滤器大小
                 * Threshold  热页面阈值
                 * CtrBackupsize 备份区
                */
                sDMLFUCache(sDMmanager* sDMmanagerptr, int capacity, uint64_t CacheLinesize = sDM_PAGE_SIZE >> 1,
                uint64_t CtrFiltersize = 128,uint64_t Threshold = 2,uint64_t CtrBackupsize = 128) {
                    this->capacity = capacity;
                    this->CacheLinesize = CacheLinesize;
                    for (int i = 0; CtrLinks.size() < capacity + 1; i++) {
                        CtrLinks.push(CreateCtrlink(i));
                    }
                    this->sDMmanagerptr = sDMmanagerptr;
                    this->Threshold = Threshold;
                    this->CtrFilter = new sDMLRUCache(sDMmanagerptr,CtrFiltersize, 0, 1, (char*)"CtrFilter",sizeof(uint64_t));  //计数器大小sizeof(64)
                    this->HotPageCache = new sDMLRUCache(sDMmanagerptr,capacity, 0, 1,(char*)"HotPageCache", sDM_PAGE_SIZE >> 1);
                    this->CtrBackupsize = CtrBackupsize;  //和计数器过滤器保持一致
                }
                ~sDMLFUCache();
            public:
                sDMmanager* sDMmanagerptr;
                CtrLink* CreateCtrlink(uint64_t ctr) {
                    if (FreqtoCtrLink.count(ctr) > 0) {
                        printf("LRUCache(error):create an existed CtrLink");
                        return NULL;
                    }
                    CtrLink* newCtrlink = (CtrLink*)malloc(sizeof(CtrLink));
                    newCtrlink->head = (CtrLinkNode*)malloc(sizeof(CtrLinkNode));
                    newCtrlink->tail = (CtrLinkNode*)malloc(sizeof(CtrLinkNode));
                    newCtrlink->head->Next = newCtrlink->tail;
                    newCtrlink->tail->Pre = newCtrlink->head;
                    newCtrlink->ctr = 0;
                    return newCtrlink;
                }
                void deleteCtrlink(uint64_t ctr) {
                    if (FreqtoCtrLink.count(ctr) == 0) {
                        printf("LFUCache(error):delete an invalid link\n");
                        return;
                    }
                    //当且仅当一条ctr链没有任何数据的时候可以删除该链
                    if (FreqtoCtrLink[ctr]->head->Next != FreqtoCtrLink[ctr]->tail)
                    {
                        printf("LFUCache(erro):Not a empty CtrLink\n");
                        return;
                    }
                    CtrLinks.push(FreqtoCtrLink[ctr]);//回收CtrLink，用于复用
                    FreqtoCtrLink.erase(ctr);
                }
                /**
                 * @brief 回收一条空链，同时取消ctr到计数器链的映射
                 * @param ctr
                */
                void RecoverCtrLink(uint64_t ctr) {
                    deleteCtrlink(ctr);
                }
                bool Insert2Ctrlink(Addr key, CtrLinkNode* Node, uint64_t ctr, uint8_t* retbuf, bool isinLink);
                bool CacheAccess(Addr key, uint8_t* value, bool isread);
                bool AccessHotPageCache(Addr key, uint8_t* value, bool isread);
                void hPageinAccess(Addr addr, uint8_t* value, uint64_t bytesize, bool isread);
                bool Evict(uint8_t* retbuf);
                void deletebackup(uint64_t Addr) {
                    for (auto it = LifeTimeCtr.begin(); it != LifeTimeCtr.end(); it++) {
                        if ((*it) == Addr) {
                            LifeTimeCtr.erase(it);
                            return;
                        }
                    }
                }
                void AddCtr2Filter(uint64_t key, uint64_t ctr);
            };
            class sDMAddrCache : public simpleCache
            {
                public:
                    sDMmanager *manager;
                    Addr head, offset;
                    int skip, pnum;
                    sDMAddrCache(sDMmanager *manager,
                                uint64_t cache_line_nums, 
                                int evict_m = 0, 
                                uint64_t tag_latency = 0) : simpleCache(cache_line_nums, evict_m, tag_latency)
                    {
                        this->manager = manager;
                        std::cout << "Address Cache init!" << std::endl;
                    };
                    void set(uint64_t head, uint64_t offset, int skip)
                    {
                        this->head = head;
                        this->offset = offset;
                        this->skip = skip;
                    };
                    // construct function of Base-class cannot call 
                    uint64_t _read(uint64_t tag) override
                    {
                        return (manager->find(head, offset, skip, 0, pnum)) & PAGE_ALIGN_MASK;
                    };
                    void print_cache();
            };
            class sDMPort : public RequestPort
            {
            public:
                sDMPort(const std::string &_name, sDMmanager *_sdmmanager) : RequestPort(_name, _sdmmanager),
                                                                             sdmmanager(_sdmmanager)
                {
                    // printf("name:%s sDMmanager:%p\n", _name.c_str(), _sdmmanager);
                }

            protected:
                sDMmanager *sdmmanager;

                bool recvTimingResp(PacketPtr pkt)
                {
                    // sdmmanager->pkt_recv = pkt;
                    // sdmmanager->has_recv = true;
                    return true;
                }
                void recvReqRetry()
                {
                    // printf("sDMmanager retry\n");
                    panic("%s does not expect a retry\n", name());
                }
            };

            // private:
        public:
            // 数据页页指针集指针
            // sdm_dataPagePtrPagePtr dataPtrPagePtr;
            // std::vector<sdm_dataPagePtrPagePtr> dataPtrPage;
            bool isHotPageenable = true;
            sDMPort memPort;
            RequestorID _requestorId;
            Process *process;    // 是为了使用pTable而引入与实际情况是不相符的
            sdmID sdm_space_cnt; // sDM_space编号器全局单增,2^64永远不会耗尽, start from 1
            int local_pool_id;   // 记录每个process/workload的本地pool的编号
            int remote_pool_id;  // 可用本地内存池(内存段)编号
            // hash/encryption时延
            uint64_t hash_latency;
            uint64_t encrypt_latency;
            uint64_t onchip_cache_size;
            uint64_t onchip_cache_latency;
            uint64_t dram_cache_size;
            uint64_t remoteMemAccessLatency;
            uint64_t localMemAccessLatency;
            MemPools *mem_pools;              // 实例化时的内存池指针
            std::vector<sdm_space> sdm_table; // id->sdm
            // 拦截每次的访存的vaddr时,根据pid找到对应的sdm space表,查找此表对应到相应的space id vaddr <==> (page_num,space id)
            std::unordered_map<uint64_t, std::map<Addr, std::pair<size_t, sdmID>>> sdm_paddr2id;
            sDMKeypathCache *KeypathCache; // L1 and L2
            sDMLFUCache *HotPageCache; //HotPageCache
            sDMAddrCache *addrCache; // 针对find函数的cache
            sDMstat *lstat;         // 本地内存统计量
            sDMstat *rstat;         // 远端内存统计量
            /**
             * @author psj
             * @brief 返回当前sDMmanager的_requestorId
             */
            sDMmanager(const sDMmanagerParams &p);
            ~sDMmanager();

            bool sdm_malloc(int npages, int pool_id, std::vector<phy_space_block> &phy_list); // 申请gem5模拟内存物理空间
            bool sdm_free(int pool_id, std::vector<phy_space_block> &phy_list);

            void build_SkipList(std::vector<phy_space_block> &remote_phy_list, std::vector<phy_space_block> &local_phy_list,
                                int skip, int ac_num, int lnpages);
            void write2Mem(uint32_t byte_size, uint8_t *data, Addr gem5_addr);
            void read4Mem(uint32_t byte_size, uint8_t *container, Addr gem5_addr);
            bool hmac_verify(Addr dataPAddr, Addr rva, Addr *hmacAddr, sdmID id, uint8_t *hpg_data, iit_NodePtr counter, sdm_hashKey hash_key);
            Addr find(Addr head, Addr offset, int skip, int known, int &pnum);
            void sDMspace_init(Addr vaddr, size_t byte_size, sdm_CMEKey ckey, sdm_hashKey hkey, std::vector<phy_space_block> r_hmac_phy_list,
                               std::vector<phy_space_block> r_iit_phy_list, uint32_t h, sdm_space &sp);
            sdmID isContained(uint64_t pid, Addr vaddr);
            bool sDMspace_register(uint64_t pid, Addr vaddr, size_t data_byte_size);
            bool sDMspace_free(uint64_t pid, Addr vaddr);
            Addr getVirtualOffset(sdmID id, Addr paddr);
            int getKeyPath(sdmID id, Addr rva, Addr *keyPathAddr, iit_NodePtr keyPathNode);
            bool verify(Addr data_vaddr, uint8_t *hpg_data, sdmID id, Addr *rva, int *h,
                        Addr *keyPathAddr, iit_NodePtr keyPathNode, Addr *hmacAddr, sdm_hashKey hash_key);
            void write(uint64_t pid, PacketPtr pkt, uint8_t *aligned_mem_ptr, Addr pktVAddr);
            void read(uint64_t pid, PacketPtr pkt, uint8_t *algined_mem_ptr, Addr vaddr);
            Port &
            getPort(const std::string &if_name, PortID idx = InvalidPortID) override
            {
                if (if_name == "mem_side")
                    return memPort;
                return sDMmanager::getPort(if_name, idx);
            }
            RequestorID requestorId() { return _requestorId; }
            void AccessMemory(Addr addr, uint8_t *databuf, bool isread, uint8_t datasize);

            void encrypt(uint8_t *plaint, uint8_t *counter, int counterLen, sDM::Addr paddr2CL, uint8_t *key2EncryptionCL);
            void decrypt(uint8_t *cipher, uint8_t *counter, int counterLen, sDM::Addr paddr2CL, uint8_t *key2EncryptionCL);
            void timer();     // 定时器在read/write开始调用
            uint64_t formula(uint64_t local_dL1, uint64_t local_dL2, uint64_t local_acc, uint64_t remote_acc, uint64_t enc_dec, uint64_t dhash);
            uint64_t delay(); // 返回本次Read/Write的时延
            void summary();
        };
    }
}
#endif // _SDM_HH_