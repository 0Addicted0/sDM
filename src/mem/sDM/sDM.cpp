#include "sDM.hh"

namespace gem5
{
    namespace sDM
    {
        /**
         * @brief
         * 向上取整除法
         * @author
         * yqy
         */
        uint64_t ceil(uint64_t a, uint64_t b)
        {
            return ((a / b) + (((a % b) == 0) ? 0 : 1));
        }
        /**
         * @author yqy
         * @brief 根据数据区大小计算iit大小
         * @return 返回整个iit的字节大小
         */
        uint64_t getIITsize(uint64_t data_size)
        {
            /**
             * 一个叶节点arity=32,对应32个CL => data_size = 2KB
             * h=0,root,iit节点数:64^0, 不单独成树
             * h=1,L1,iit叶节点数:64^1,数据区大小:64^1*2KB=128KB
             * h=2,L2,iit叶节点数:64^2,数据区大小:64^2*2KB=8MB
             * h=3,L2,iit叶节点数:64^3,数据区大小:64^3*2KB=512MB
             * h=4,L2,iit叶节点数:64^4,数据区大小:64^4*2KB=32GB
             */
            assert(data_size > IIT_LEAF_ARITY * CL_SIZE); // >2KB 树至少高于1层(包含根)
            uint64_t leaf_num = data_size / (IIT_LEAF_ARITY * CL_SIZE);
            uint64_t node_num = 1; // root
            while (leaf_num > 1)
            {
                node_num += leaf_num;
                leaf_num >>= 6; // /64
            }
            return node_num * CL_SIZE; // 转换为字节大小
        }
        /**
         * sDMmanager构造函数
         */
        sDMmanager::sDMmanager(int sdm_pool_id) : remote_pool_id(remote_pool_id)
        {
            printf("!!sDMmanager!!\n");
        }
        /**
         * sDMmanager
         */
        sDMmanager::~sDMmanager()
        {
        }
        /**
         * @author
         * yqy
         * @brief
         * 判断地址所在页是否处于sdm中
         * 并返回其id
         * @return
         * 返回0表示该地址所在页面不处于任何sdm中
         * 否则返回其所在sdm的id(sdmIDtype)
         */
        sdmIDtype sDMmanager::isContained(Addr paddr)
        {
            paddr &= PAGE_ALIGN_MASK;
            auto id = sdm_paddr2id.find(paddr);
            if (id == sdm_paddr2id.end())
                return 0;
            return id->second;
        }
        /**
         * @author yqy
         * @brief 返回物理地址在所属sdm中的虚拟空间的相对偏移
         * @param id:所属sdm的编号(sdmIDtype)
         * @param paddr:物理地址
         * @return 虚拟空间的相对偏移
         * @attention 查页表部分未实现
         */
        Addr sDMmanager::getVirtualOffset(sdmIDtype id, Addr paddr)
        {
            Addr cur_vaddr = paddr; // 查页表paddr
            return cur_vaddr - sdm_table[id].datavAddr;
        }
        /**
         * @author yqy
         * @brief 利用skip list查询
         * @brief 用于距离首地址偏移所在页的物理地址
         * @param id sdm_space对应的id
         * @param offset 偏移量
         * @param known 标识是否已经检查过该页(0:未检查,1:处于该本地页,2:超出该本地页)
         * @param pnum 经过的页面数
         * @attention 未实现
         * @attention *处存在错误
         *
         * ----------
         * |  |  |  | <x,3,~> ...
         * ----------
         * '''
         * ----------------
         * |  |  |  |  |  | <y,5,~> ...
         * ----------------
         */
        Addr sDMmanager::find(Addr head, Addr offset, int skip, int known, int &pnum)
        {
            uint8_t *next_list[skip];
            uint64_t c;
            sdm_pagePtrPair rbound;
            // 获取最后一个连续页的最后一个数据对的范围
            bool flag = false; // 是否获取了c
            if (!known)
            {
                read4Mem(sizeof(c), (uint8_t *)&c, head + (PAGE_SIZE - sizeof(uint64_t) * 2));
                flag = true;
                read4Mem(PAIR_SIZE, (uint8_t *)&rbound,
                         head + (c - 1) * PAGE_SIZE + (PAGE_SIZE / PAIR_SIZE - 1));
                if ((rbound.pnum + rbound.cnum) * PAGE_SIZE >= offset)
                    known = 1;
                else
                    known = 2;
            }
            if (known == 1) // 在连续页的范围内
            {
                // 在本地连续页内二分找出数据对
                // 连续页的数量
                if (!flag)
                    read4Mem(sizeof(c), (uint8_t *)&c, head + (PAGE_SIZE - sizeof(uint64_t) * 2));
                int l = -1;
                int r = c;
                while (r - l > 1) // 二分第一个末数据对地址范围大于offset的本地页
                {
                    int mid = (r + l) >> 1;
                    // 读取页的最后一个数据对
                    read4Mem(PAIR_SIZE, (uint8_t *)&rbound,
                             head + mid * PAGE_SIZE +
                                 (PAGE_SIZE / PAIR_SIZE - 1));
                    if ((rbound.pnum + rbound.cnum) * PAGE_SIZE >= offset)
                        r = mid;
                    else
                        l = mid;
                }
                // 在第r页内二分出数据对
                head += r * PAGE_SIZE;
                //  [skip/2,...,PAGE_SIZE/PAIR_SIZE]
                // ^                                ^
                // i                                j
                l = skip / 2 - 1;
                r = PAGE_SIZE / PAIR_SIZE;
                while (r - l > 1)
                {
                    int mid = (r + l) >> 1;
                    read4Mem(PAGE_SIZE, (uint8_t *)&rbound, head + (mid * PAIR_SIZE));
                    if ((rbound.pnum + rbound.cnum) * PAGE_SIZE >= offset)
                        r = mid;
                    else
                        l = mid;
                }
                // 在第r个数据对中
                // 在数据对中找到所在页
                head = rbound.curPageAddr;
                head += (offset - rbound.pnum) / PAGE_SIZE;
                pnum = rbound.pnum + (offset - rbound.pnum) / PAGE_SIZE;
                return head;
            }
            else
            {
                // 本地跳跃页间二分
                //  [0,...,skip-1]
                // ^              ^
                // i              j
                // 注意这里应该是找到最后一个最后连续页的末数据对小于等于offset的skip
                int l = -1, r = skip;
                while (r - l > 1)
                {
                    int mid = (l + r) >> 1;
                    // 取得第2^(mid-1)跳的页首地址
                    read4Mem(sizeof(sdm_dataPtr), next_list[mid], head + sizeof(sdm_dataPtr) * mid);
                    // 获取对应跳的连续页数
                    read4Mem(sizeof(c), (uint8_t *)&c, (Addr)next_list[mid] + (PAGE_SIZE - sizeof(uint64_t) * 2));
                    // 获取对应跳最后一个连续页的最后一个数据对的范围
                    read4Mem(PAIR_SIZE, (uint8_t *)&rbound, ((Addr)next_list[mid]) + PAGE_SIZE * (c - 1) + (PAGE_SIZE / PAIR_SIZE - 1));
                    if ((rbound.pnum + rbound.cnum) * PAGE_SIZE >= offset)
                    {
                        r = mid;
                        known = 1;
                    }
                    else
                    {
                        l = mid;
                        known = 2;
                    }
                }
                return find(((Addr)next_list[l]), offset, skip, known, pnum);
            }
        }
        /**
         * @author yqy
         * @brief 查找关键路径上节点的远端物理地址
         * @param id 访问地址所属sdm的id
         * @param rva 访问的物理地址对应的虚拟空间偏移
         * @param keyPathAddr 返回关键路径物理地址
         * @param keyPathNode 返回关键路径节点
         * @return 返回层数
         * @attention 未实现
         */
        int sDMmanager::getKeyPath(sdmIDtype id, Addr rva, Addr *keyPathAddr, iit_NodePtr keyPathNode)
        {
            int pnum = 0;
            Addr leafNodePagePtr = find((Addr)sdm_table[id].iITPtrPagePtr, rva, sdm_table[id].iit_skip, 0, pnum);
            leafNodePagePtr += (rva - pnum * PAGE_SIZE);
            return 0;
        }
        /**
         * @author yqy
         * @brief 用于申请一定大小的物理空间,用于存储sdm管理结构
         * @param npages 申请空间的页面数
         * @param pool_id 使用哪个内存进行分配
         * @param phy_list 返回分配到的物理地址链表vector<phy_space_block>
         */
        bool
        sDMmanager::sdm_malloc(int npages, int pool_id, std::vector<phy_space_block> &phy_list)
        {
            // 这里直接调用
            Addr start = mem_pools->allocPhysPages(npages, pool_id); // 调用gem5物理内存分配函数直接分配
            // 由于gem5本身没有处理不连续的地址情况,所以一定是连续的
            if (start == POOL_EXHAUSTED)
            {
                // 本地内存耗尽
                return false;
            }
            phy_list.push_back({start, npages});
            // 成功则直接返回
            return true;
        }
        /**
         * @author yqy
         * @param &skip 正在构建的sdm_space
         * @param pair_num 远端返回的物理地址对数量
         * @param &pair_per 每个本地页可以填充的数据对数量
         * @return 返回需要申请的本地页面数
         */
        int pred_local_page_need(int &skip, size_t pair_num, int &pair_per)
        {
            // 这里实现skip list,需要根据pair_num的数量申请本地内存
            if (pair_num >= 32 * ((PAGE_SIZE / PAIR_SIZE - 1) - 1))
                skip = 6; // 构建6级 step=1,2,4,8,16,32
            else if (pair_num >= 16 * ((PAGE_SIZE / PAIR_SIZE - 1) - 1))
                skip = 4; // 构建4级 step=1,2,4,8
            else
                skip = 2; // 构建1级 step=1,2
            // 计算除去skip指针后的可用的pair数量
            pair_per = ((PAGE_SIZE / PAIR_SIZE - 1) - skip / 2);
            int lpage_hamc_needed = ceil(pair_num, pair_per);
        }
        /**
         * @author yqy
         * @brief 将连续数据写入到gem5内存中
         * @param byte_size 写入字节大小
         * @param data 数据指针
         * @param gem5_addr 写入的位置
         * @attention 未实现
         */
        void sDMmanager::write2Mem(uint32_t byte_size, uint8_t *data, Addr gem5_addr)
        {
            //  packet mem[i]->gem5MemPtr->[i];...
            return;
        }
        /**
         * @author yqy
         * @brief 从gem5内存中读取连续数据
         * @param byte_size 读取字节大小
         * @param container 存放读取数据指针
         * @param gem5_addr 读取的位置
         * @attention 未实现
         * @attention 注意可能需要将地址按CL对齐后再读?
         */
        void sDMmanager::read4Mem(uint32_t byte_size, uint8_t *container, Addr gem5_addr)
        {
            return;
        }
        /**
         * @author yqy
         * @brief 构建skip list
         * @param remote_phy_list 远端地址数据对
         * @param local_phy_list 本地地址数据对
         * @param ac_num 每个本地页可容纳数据对数量
         */
        void sDMmanager::build_SkipList(std::vector<phy_space_block> &remote_phy_list, std::vector<phy_space_block> &local_phy_list,
                                        int skip, int ac_num)
        {
            // 当前在填充第几个本地页面,hmacPtrPagePtr指向当前本地页
            Addr hmacPtrPagePtr = local_phy_list[0].start;
            int cur = 0;   // 这些页面用于记录申请到的远端物理页面信息
            int cur_k = 1; // 记录当前本地页面段的第几个
            // 当前正在记录第几个页面数据对
            size_t cur_pair = 0;
            // 每个本地页可以填充的数据对数量
            uint32_t logic_npages = 0;
            while (cur_pair < remote_phy_list.size()) // 所有页面数据对
            {
                // 每次都开始写一个新的本地页面
                sdm_hmacPagePtrPage mem; // 用于暂时组织数据,然后统一调用packet将数据写到hmacPtrPagePtr对应的本地页中
                // memset(&mem,0,sizeof(sdm_hmacPagePtrPage));
                // 首先写入skip部分
                for (int i = 1; i <= skip; i++)
                {
                    if (cur + i < local_phy_list.size()) // 还有后续段
                        mem.next[i - 1] = (sdm_dataPtr)local_phy_list[cur + i].start;
                    else
                        mem.next[i - 1] = 0x0; // 不存在后续段
                }
                // 然后填充数据对
                for (int i = 1; i <= ac_num; i++)
                {
                    mem.pair[skip / 2 + (i - 1)].curPageAddr = remote_phy_list[cur_pair].start;
                    mem.pair[skip / 2 + (i - 1)].cnum = remote_phy_list[cur_pair].npages;
                    mem.pair[skip / 2 + (i - 1)].pnum = logic_npages;
                    logic_npages += remote_phy_list[cur_pair].npages; // 累计逻辑空间大小
                    cur_pair++;
                    if (cur_pair >= remote_phy_list.size())
                        break;
                }
                // 向本地内存写入该页
                mem.c = remote_phy_list[cur_pair].npages - cur_k + 1;
                write2Mem(PAGE_SIZE, (uint8_t *)&mem, hmacPtrPagePtr);
                // 如果还有剩余数据对
                if (cur_pair >= remote_phy_list.size())
                    break;
                // 找到下一个可用的本地页
                // 检查l_hmac_phy_list[cur]起始的连续页是否用完
                cur_k++;
                if (cur_k <= local_phy_list[cur].npages) // 还有连续页
                    hmacPtrPagePtr += PAGE_SIZE;         // 指向下一个连续的本地页
                else
                {
                    // 该连续段已用完
                    cur++; // 使用下个段
                    cur_k = 1;
                    hmacPtrPagePtr = local_phy_list[cur].start;
                }
            }
        }
        /**
         * @brief 为数据空间构建sDM空间
         * @author yqy
         * @param pPageList 该sDM空间内的数据页物理地址列表
         * @return 是否成功注册
         * //sdm metadata指针(这里sdm metadata是sdm结构体指针)
         * @attention 初始化这些空间的数据没有实现
         */
        bool sDMmanager::sDMspace_register(std::vector<Addr> &pPageList)
        {
            assert(pPageList.size() && "data is empty");
            // 可以使用某种hash结构存
            // 这里需要计算所需的额外空间
            // 1. data大小
            sdm_size data_size = pPageList.size() * PAGE_SIZE;
            // 2. IIT树大小
            sdm_size iit_size = getIITsize(data_size);
            // 3. HMAC大小
            sdm_size hmac_size = data_size * SDM_HMAC_ZOOM;
            // 额外所需空间的总大小
            sdm_size extra_size = iit_size + hmac_size;
            // 准备metadata
            sdm_space sp;
            // 标记space id
            sp.id = ++sdm_space_cnt;
            // 这里为hmac和iit申请远端内存空间
            std::vector<phy_space_block> r_hmac_phy_list;
            std::vector<phy_space_block> r_iit_phy_list;
            sdm_malloc(hmac_size / PAGE_SIZE, remote_pool_id, r_hmac_phy_list);
            sdm_malloc(iit_size / PAGE_SIZE, remote_pool_id, r_iit_phy_list);
            // 初始化HMAC和iit区域(将数据区置0)
            // ...

            // 预估所需页面数量,同时填写跳数、每页可写数据对数量
            int hmac_per, iit_per;
            int hmac_lpage_num = pred_local_page_need(sp.hmac_skip, r_hmac_phy_list.size(), hmac_per);
            int iit_lpage_num = pred_local_page_need(sp.iit_skip, r_iit_phy_list.size(), iit_per);
            // 向本地申请内存空间
            std::vector<phy_space_block> l_hmac_phy_list;
            std::vector<phy_space_block> l_iit_phy_list;
            sdm_malloc(hmac_lpage_num, local_pool_id, l_hmac_phy_list);
            sdm_malloc(iit_lpage_num, local_pool_id, l_iit_phy_list);
            // 构建两个链表
            sp.HMACPtrPagePtr = (sdm_hmacPagePtrPagePtr)l_hmac_phy_list[0].start;
            // 构建hmac skip-list
            build_SkipList(r_hmac_phy_list, l_hmac_phy_list, sp.hmac_skip, hmac_per);
            // 构建iit skip-list
            build_SkipList(r_iit_phy_list, l_iit_phy_list, sp.iit_skip, iit_per);
            // 这里的sdm_table、sdm_paddr2id查询还没有接入gem5
            for (auto paddr : pPageList)
            {
                // 该地址不可能已经存在于其他sdm空间
                assert(!sdm_paddr2id[paddr] && "reused before free");
                // 添加地址映射
                sdm_paddr2id[paddr] = sp.id;
            }
            sdm_table.push_back(sp);
            return true;
        }
        /**
         * @author yqy
         * @brief 完成HMAC校验(所在半页)
         * @param paddr 需要校验的地址
         */
        bool sDMmanager::hmac_verify(Addr paddr, iit_NodePtr counter, sdm_hashKey hash_key)
        {
            Addr pageAddr = (paddr & PAGE_ALIGN_MASK) | (paddr & (PAGE_SIZE >> 1));
            uint8_t pg_data[PAGE_SIZE >> 1];
            // 读取所在半页的内存数据
            read4Mem(PAGE_SIZE >> 1, pg_data, pageAddr);
            uint8_t calc_hmac[SM3_SIZE];
            // 计算HMAC
            CME::sDM_HMAC(pg_data, PAGE_SIZE >> 1, hash_key, paddr, (uint8_t *)counter, sizeof(iit_Node), calc_hmac, SM3_SIZE);
            // 与存储值比较
            sdm_HMAC stored_hmac;
            read4Mem(PAGE_SIZE >> 1, stored_hmac, pageAddr);
            assert(memcmp(calc_hmac, stored_hmac, sizeof(sdm_HMAC)) == 0 && "HMAC verify failed");
            return true;
        }
        /**
         * @author yqy
         * @brief 对paddr CL的数据进行校验
         * @brief 并将一些中间值通过传输的指针参数返回
         * @attention HMAC校验未完成
         */
        bool sDMmanager::verify(Addr paddr, sdmIDtype id, Addr *rva, int &h, Addr *keyPathAddr, iit_NodePtr keyPathNode, sdm_hashKey key)
        {
            *rva = getVirtualOffset(id, paddr);
            h = getKeyPath(id, *rva, keyPathAddr, keyPathNode);
            // 执行校验
            // 1. HMAC校验
            iit_Node tmpLeaf;
            keyPathNode[0].erase_hash_tag(IIT_LEAF_TYPE, &tmpLeaf);
            bool hmac_verified = hmac_verify(paddr, &tmpLeaf, key);
            // 2. iit校验
            int type = IIT_LEAF_TYPE;
            // paddr对应的缓存行位于上层节点的哪个计数器
            uint32_t next_k = *rva / IIT_LEAF_ARITY * CL_SIZE;
            next_k /= IIT_MID_ARITY;
            // 用于存放当前节点和父节点的major-minor计数器
            CL_Counter cl, f_cl;
            bool verified = true;
            for (int i = 0; i < h && verified; i++)
            {
                if (i < h - 1) // sum check
                {
                    keyPathNode[i].sum(type, cl);
                    // 取出父计数器
                    keyPathNode[i + 1].getCounter_k(IIT_MID_TYPE, next_k, f_cl);
                    // 比较父计数器是否与当前计数器相等
                    verified = counter_cmp(cl, f_cl);
                }
                iit_hash_tag has_tag = keyPathNode[i].abstract_hash_tag(type);
                iit_hash_tag chas_tag = keyPathNode[i].get_hash_tag(type, key, keyPathAddr[i]);
                // 比较计算值和存储值
                verified = (has_tag == chas_tag);
                type = IIT_MID_TYPE;
            }
            return verified;
        }
        /**
         * @author yqy
         * @brief 读取paddr的CL时进行校验
         * @return 是否通过校验
         * @attention 未实现
         */
        void sDMmanager::read(Addr paddr)
        {
            sdmIDtype id = sDMmanager::isContained(paddr);
            if (id == 0) // 该物理地址不包含在任何sdm中,无需对数据包做修改
                return;
            Addr rva;
            int h;
            Addr keyPathAddr[MAX_HEIGHT] = {0};
            iit_Node keyPathNode[MAX_HEIGHT] = {0};
            sdm_hashKey hash_key;
            sdm_table[id].key_get(HASH_KEY_TYPE, hash_key);
            bool verified = verify(paddr, id, &rva, h, keyPathAddr, keyPathNode, hash_key);
            assert(verified && "verify failed before read");
            assert(0 && "sDM_Decrypt failed");
            //... 这里需要对数据包进行解密
            // uint8_t* data = PacketPtr->getdataPtr<uint8_t*>;
            CL_Counter cl;
            keyPathNode[0].getCounter_k(IIT_LEAF_TYPE, rva / (IIT_LEAF_ARITY * CL_SIZE), cl);
            sdm_CMEKey cme_key;
            sdm_table[id].key_get(CME_KEY_TYPE, cme_key);
            // CME::sDM_Decrypt(data, counter, paddr, cl, cme_key);
        }
        /**
         * @author yqy
         * @brief 写入paddr的CL时进行校验,并加密、维护iit、计算hmac
         * @return 是否完成写入
         * @attention 未实现
         */
        void
        sDMmanager::write(Addr paddr)
        {
            sdmIDtype id;
            id = isContained(paddr);
            if (!id) // 无需修改任何数据包
                return;
            // 该地址在所属空间中的相对偏移
            Addr rva;
            int h;
            Addr keyPathAddr[MAX_HEIGHT] = {0};
            iit_Node keyPathNode[MAX_HEIGHT] = {0};
            sdm_hashKey hash_key;
            sdm_table[id].key_get(HASH_KEY_TYPE, hash_key);
            bool verified = verify(paddr, id, &rva, h, keyPathAddr, keyPathNode, hash_key);
            assert(verified && "verify failed before write");

            // 写入数据
            // 假设写队列是安全的
            // 真正写入内存时才进行修改,读取写队列中的数据不需要校验
            // 在修改完成之前不允许读取

            // 1. 需要对数据包进行加密
            //  uint8_t* data = PacketPtr->getdataPtr<uint8_t*>;
            CL_Counter cl;
            uint32_t cur_k = rva / (IIT_LEAF_ARITY * CL_SIZE);
            int node_type = IIT_LEAF_TYPE;
            bool OF;
            keyPathNode[0].inc_counter(node_type, cur_k, OF);
            keyPathNode[0].get_hash_tag(node_type, hash_key, paddr);
            cur_k /= IIT_MID_ARITY;

            sdm_CMEKey cme_key;
            sdm_table[id].key_get(CME_KEY_TYPE, cme_key);
            // 可以提前取得所在半页的数据,其后的HMAC计算是必须的,提高并行度
            if (OF)
            {
                // 引发重加密所在半页
                Addr pageAddr = paddr & PAGE_ALIGN_MASK; // 页
                if (paddr & (IIT_LEAF_ARITY * CL_SIZE))
                {
                    // 重加密高半页
                }
                else
                {
                    // 重加密
                }
            }
            else
            { // 仅加密该缓存行
              // CME::sDM_Encrypt(data, counter, paddr, cl, cme_key);
            }
            // 2. 重新计算HMAC并写入
            // CME::sDM_HMAC(data, CL_SIZE, hash_key, paddr, cl,cme_key);
            // 3. 修改iit tree
            for (int i = 1; i < h; i++)
            {
                keyPathNode[i].inc_counter(node_type, cur_k, OF);
                keyPathNode[i].get_hash_tag(node_type, hash_key, paddr);
                cur_k /= IIT_MID_ARITY;
            }
            // 写回所有数据
        }
    }
}
