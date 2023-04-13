#include "sDM.hh"
#include <algorithm>

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
         * @attention 待传入参数*
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
         * @author yqy
         * @brief 将连续数据写入到gem5内存中
         * @param byte_size 写入字节大小
         * @param data 数据指针
         * @param gem5_addr 写入的位置
         * @attention 未实现*
         * @attention 注意可能需要将地址按CL对齐后再读写
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
         * @attention 未实现*
         * @attention 注意可能需要将地址按CL对齐后再读写
         */
        void sDMmanager::read4Mem(uint32_t byte_size, uint8_t *container, Addr gem5_addr)
        {
            // container <- packet[byte_size];
            return;
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
            Addr cur_vaddr = paddr; // 实际使用查页表paddr
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
            local_jmp rbound;
            sdm_pagePtrPairPtr rboundp = (sdm_pagePtrPair *)&rbound; // 这里两个结构体大小相同,因此可以共用一下
            bool flag = false;                                       // rbound是否已经通过内存得到
            if (!known)                                              // 首次进入不确定是否在该连续段中
            {
                // 获取最后一个连续页的最后一个数据对的范围
                read4Mem(sizeof(local_jmp), (uint8_t *)&rbound, head + PAGE_SIZE - sizeof(local_jmp));
                flag = true;
                if ((rbound.maxBound) >= offset)
                    known = 1;
                else
                    known = 2;
            }
            if (known == 1) // 在连续页的范围内
            {
                if (!flag)
                    read4Mem(sizeof(local_jmp), (uint8_t *)&rbound, head + PAGE_SIZE - sizeof(local_jmp));
                // 在当前连续段内二分找出地址所在页
                int l = -1;
                int r = rbound.con;
                while (r - l > 1) // 二分第一个末数据对地址范围大于offset的本地页
                {
                    int mid = (r + l) >> 1;
                    // 读取页的最后一个数据对,注意还要除去local_jmp,因此需要减去两个PAIR_SIZE
                    read4Mem(PAIR_SIZE, (uint8_t *)&rbound, head + mid * PAGE_SIZE + PAGE_SIZE - PAIR_SIZE - PAIR_SIZE);
                    if ((rboundp->pnum + rboundp->cnum) * PAGE_SIZE >= offset)
                        r = mid;
                    else
                        l = mid;
                }
                // 在第r页内二分出数据对
                head += r * PAGE_SIZE;
                //  [skip/2,...,PAGE_SIZE/PAIR_SIZE-1]
                // ^                                  ^
                // i                                  j
                l = skip / 2 - 1;
                r = PAGE_SIZE / PAIR_SIZE;
                while (r - l > 1)
                {
                    int mid = (r + l) >> 1;
                    read4Mem(PAGE_SIZE, (uint8_t *)&rbound, head + (mid * PAIR_SIZE));
                    if ((rboundp->pnum + rboundp->cnum) * PAGE_SIZE >= offset)
                        r = mid;
                    else
                        l = mid;
                }
                // 在第r个数据对中
                // 在数据对中找到所在页
                head = rboundp->curPageAddr;
                head += (offset - rboundp->pnum) / PAGE_SIZE;
                pnum = rboundp->pnum + (offset - rboundp->pnum) / PAGE_SIZE;
                return head;
            }
            else
            {
                // 本地跳跃页查找
                // 注意这里应该是找到一个连续段最大地址范围对小于等于offset的skip
                skip_jmp jmps[skip];
                // 从本地内存中读取skip list
                read4Mem(sizeof(skip_jmp) * skip, (uint8_t *)jmps, head);
                int i = skip - 1;
                while (jmps[i].maxBound > offset && i >= 0)
                    i--;
                return find(jmps[i].next, offset, skip, known, pnum);
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
         * @attention 取回节点数据未实现*
         */
        int sDMmanager::getKeyPath(sdmIDtype id, Addr rva, Addr *keyPathAddr, iit_NodePtr keyPathNode)
        {
            int pnum = 0;
            rva = rva / (PAGE_SIZE >> 1); // 每经过半页数据,会形成一个叶节点
            Addr leafNodePagePtr = find((Addr)sdm_table[id].iITPtrPagePtr, rva, sdm_table[id].iit_skip, 0, pnum);
            leafNodePagePtr += (rva - pnum * PAGE_SIZE);
            // 取回节点数据
            // ...
            return 0;
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
            skip = 1;
            // 这里实现skip list,需要根据pair_num的数量申请本地内存
            if (pair_num >= 8 * (PAGE_SIZE / PAIR_SIZE - 1) - skip)
                skip = 3; // 构建3级 step=1,2,4
            else if (pair_num >= 4 * ((PAGE_SIZE / PAIR_SIZE - 1) - skip))
                skip = 2; // 构建4级 step=1,2
            else
                skip = 1; // 构建1级 step=1
            // 计算除去skip指针后的可用的pair数量
            pair_per = ((PAGE_SIZE / PAIR_SIZE - 1) - skip);
            return ceil(pair_num, pair_per);
        }
        /**
         * @author yqy
         * @brief 构建skip list
         * @param remote_phy_list 远端地址数据对
         * @param local_phy_list 本地地址数据对
         * @param ac_num 每个本地页可容纳数据对数量
         * @param lnpages 本地总页面数
         */
        void sDMmanager::build_SkipList(std::vector<phy_space_block> &remote_phy_list,
                                        std::vector<phy_space_block> &local_phy_list, int skip, int ac_num, int lnpages)
        {
            Addr ptrPagePtr[lnpages];
            ptrPagePtr[0] = local_phy_list[0].start;
            int cur = 0;     // 当前正在写第几个页面
            int cur_seg = 0; // 当前正在使用第几个本地连续段
            int cur_k = 1;   // 当前正在使用第几个本地连续段中的第几个
            int seg_start;   // 当前段的其实页面下标
            // 当前正在记录第几个页面数据对
            size_t cur_pair = 0;
            // 前面累积的物理空间逻辑大小
            uint32_t logic_npages = 0;
            sdm_hmacPagePtrPage mem[lnpages]; // 用于暂时组织数据,然后统一调用packet将数据写到hmacPtrPagePtr对应的本地页中
            // 先在缓冲中填写每一个页面
            while (cur_pair < remote_phy_list.size()) // 所有页面数据对
            {
                // 每次都开始写一个新的本地页面
                memset(&mem[cur], 0, sizeof(sdm_hmacPagePtrPage));
                // 首先写入skip部分
                for (int i = 0; i < skip; i++)
                {
                    if (cur_seg + i < local_phy_list.size()) // 还有后续段
                    {
                        mem[cur].jmp[i].next = local_phy_list[cur_seg + i].start;
                    }
                    else // 不存在后续段
                    {
                        mem[cur].jmp[i].next = 0x0;
                        mem[cur].jmp[i].maxBound = 0x0;
                    }
                }
                // 然后填充数据对
                for (int i = 0; i < ac_num; i++)
                {
                    // 前skip的位置是skip_list的结构
                    mem[cur].pair[skip + i].curPageAddr = remote_phy_list[cur_pair].start;
                    mem[cur].pair[skip + i].cnum = remote_phy_list[cur_pair].npages;
                    mem[cur].pair[skip + i].pnum = logic_npages;
                    logic_npages += remote_phy_list[cur_pair].npages; // 累计逻辑空间大小
                    cur_pair++;
                    if (cur_pair >= remote_phy_list.size())
                        break;
                }
                mem[cur].cur_segMax.con = local_phy_list[cur_seg].npages - cur_k + 1;
                cur_k++;
                // 检查l_hmac_phy_list[cur_seg]起始的连续页是否用完
                if (cur_k <= local_phy_list[cur_seg].npages) // 还有连续页,最后一个页面不可能还存在连续段,这里一定不会越界
                {
                    ptrPagePtr[cur + 1] = ptrPagePtr[cur] + PAGE_SIZE; // 指向下一个连续的本地页
                }
                else
                {
                    mem[seg_start].cur_segMax.maxBound = logic_npages * PAGE_SIZE;
                    write2Mem(PAIR_SIZE, (uint8_t *)&(mem[seg_start].cur_segMax),
                              ptrPagePtr[seg_start] + PAGE_SIZE - PAIR_SIZE);
                    // 该连续段已用完
                    if (cur_pair < remote_phy_list.size() && cur_seg < local_phy_list.size()) // 防止最后一个页面越界
                    {
                        // 找到下一个可用的本地页
                        cur_seg++;                                           // 使用下个段
                        cur_k = 1;                                           // 新连续段的第一个
                        seg_start = cur + 1;                                 // 记录新连续段的下标
                        ptrPagePtr[cur + 1] = local_phy_list[cur_seg].start; // 记录新页面对应的本地物理地址
                    }
                }
                // 先写入该页面的pair数据对到gem5内存
                write2Mem(PAGE_SIZE - -PAIR_SIZE - skip * sizeof(skip_jmp),
                          (uint8_t *)&(mem[cur].pair[skip]), ptrPagePtr[cur] + sizeof(skip_jmp) * skip);
                cur++;
            }
            // 回写skip list的next.max_bound
            for (int i = 0; i < local_phy_list.size(); i++)
            {
                for (int j = 0; j < skip; j++)
                {
                    mem[i].jmp[j].maxBound = mem[i + (1 << j)].cur_segMax.maxBound;
                }
                write2Mem(sizeof(skip_jmp) * skip, (uint8_t *)&mem[i], ptrPagePtr[i]); // 重写这些部分
            }
        }
        /**
         * @brief 为数据空间构建sDM空间
         * @author yqy
         * @param pPageList 该sDM空间内的数据页物理地址列表
         * @return 是否成功注册
         * //sdm metadata指针(这里sdm metadata是sdm结构体指针)
         * @attention 初始化这些空间的数据没有实现*
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
            // sdm_size extra_size = iit_size + hmac_size;// 额外所需空间的总大小
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
            build_SkipList(r_hmac_phy_list, l_hmac_phy_list, sp.hmac_skip, hmac_per, hmac_lpage_num);
            // 构建iit skip-list
            build_SkipList(r_iit_phy_list, l_iit_phy_list, sp.iit_skip, iit_per, iit_lpage_num);
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
         * @brief 计算HMAC(所在半页)
         * @param sdata 加密后的内存数据指针
         * @param paddr 所在半页的物理地址指针
         * @param counter 所在半页对应的计数器(节点)指针
         * @param hash_key 所属sdm的hash密钥
         * @param hmac 返回计算得到的hmac指针
         * @attention 最终返回的HMAC长度为32Byte
         */
        void hmac_get(uint8_t *sdata, Addr paddr, iit_NodePtr counter, sdm_hashKey hash_key, uint8_t *hmac)
        {
            CME::sDM_HMAC(sdata, PAGE_SIZE >> 1, hash_key, paddr, (uint8_t *)counter, sizeof(iit_Node), hmac, SM3_SIZE);
        }
        /**
         * @author yqy
         * @brief 完成HMAC校验(所在半页)
         * @param dataPAddr 读取的数据地址
         * @param rva 需要校验的地址的逻辑偏移
         * @param hmacAddr 返回hmac存在本地内存的物理地址
         * @param hpg_data 所在半页的数据
         * @param counter 所在半页对应的计数器(节点)指针
         * @param hash_key 所属sdm的hash密钥
         */
        bool sDMmanager::hmac_verify(Addr dataPAddr, Addr rva, Addr *hmacAddr, sdmIDtype id,
                                     uint8_t *hpg_data, iit_NodePtr counters, sdm_hashKey hash_key)
        {
            Addr pageAddr = (dataPAddr & PAGE_ALIGN_MASK) | (dataPAddr & (PAGE_SIZE >> 1));
            uint8_t calc_hmac[SM3_SIZE];
            // 读取所在半页的内存数据
            read4Mem(PAGE_SIZE >> 1, hpg_data, pageAddr);
            // 计算HMAC
            hmac_get(hpg_data, pageAddr, counters, hash_key, calc_hmac);
            // 与存储值比较
            int pnum;
            rva /= SDM_HMAC_ZOOM;
            *hmacAddr = find((Addr)sdm_table[id].HMACPtrPagePtr, rva, sdm_table[id].hmac_skip, 0, pnum);
            sdm_HMAC stored_hmac;
            // 从本地内存中读取
            read4Mem(PAGE_SIZE >> 1, stored_hmac, *hmacAddr);
            assert(memcmp(calc_hmac, stored_hmac, sizeof(sdm_HMAC)) == 0 && "HMAC verify failed");
            return true;
        }
        /**
         * @author yqy
         * @brief 对paddr CL的数据进行校验
         * @brief 并将一些中间值通过传输的指针参数返回
         * @param paddr 物理地址
         * @param hpg_data 所在半页的数据指针(这里是用来存储hmac-verify时读取的数据,避免多次重复读取,注意空间应该在调用者中事先分配)
         * @param id 用来存储所属sdm space的编号
         * @param rva 用来存储paddr处的数据位于整个安全空间的逻辑偏移(通过引用的形式返回给调用者)
         * @param h 记录关键路径的长度(通过引用的形式返回给调用者)
         * @param keyPathAddr 记录关键路径上节点在远端内存中的物理地址(避免多次重复读取,注意空间应该在调用者中事先分配)
         * @param keyPathNode 记录关键路径上节点的数据(避免多次重复读取,注意空间应该在调用者中事先分配)
         * @param key sdm_hashKe用于计算hash值的key
         */
        bool sDMmanager::verify(Addr paddr, uint8_t *hpg_data, sdmIDtype id, Addr *rva, int *h,
                                Addr *keyPathAddr, iit_NodePtr keyPathNode, Addr *hmacAddr, sdm_hashKey hash_key)
        {
            *rva = getVirtualOffset(id, paddr);
            *h = getKeyPath(id, *rva, keyPathAddr, keyPathNode);
            // 1. HMAC校验
            iit_Node tmpLeaf;
            keyPathNode[0].erase_hash_tag(IIT_LEAF_TYPE, &tmpLeaf);
            bool hmac_verified = hmac_verify(paddr, *rva, hmacAddr, id, hpg_data, &tmpLeaf, hash_key); // 该函数内会读取所在半页的加密数据到hpg_data[PAGE_SIZE/2]数组中
            // 2. iit校验
            int type = IIT_LEAF_TYPE;
            // paddr对应的缓存行位于上层节点的哪个计数器
            uint32_t next_k = *rva / IIT_LEAF_ARITY * CL_SIZE;
            next_k /= IIT_MID_ARITY;
            // 用于存放当前节点和父节点的major-minor计数器
            CL_Counter cl, f_cl;
            bool verified = true;
            for (int i = 0; i < *h && verified; i++)
            {
                if (i < *h - 1) // sum check
                {
                    keyPathNode[i].sum(type, cl);
                    // 取出父计数器
                    keyPathNode[i + 1].getCounter_k(IIT_MID_TYPE, next_k, f_cl);
                    // 比较父计数器是否与当前计数器相等
                    verified = counter_cmp(cl, f_cl);
                }
                iit_hash_tag has_tag = keyPathNode[i].abstract_hash_tag(type);
                iit_hash_tag chas_tag = keyPathNode[i].get_hash_tag(type, hash_key, keyPathAddr[i]);
                // 比较计算值和存储值
                assert(has_tag == chas_tag);
                // 后续节点都是mid类型
                type = IIT_MID_TYPE;
            }
            return true;
        }
        /**
         * @author yqy
         * @brief 读取paddr的CL时进行校验
         * @return 是否通过校验
         * @attention 要求gem5的读取的大小与cacheline对齐
         * @attention 在abstract_mem.cc中检查每一一个read packet
         */
        void sDMmanager::read(PacketPtr pkt)
        {
            Addr paddr = pkt->getAddr();
            sdmIDtype id = sDMmanager::isContained(paddr);
            if (id == 0) // 该物理地址不包含在任何sdm中,无需对数据包做修改
                return;
            assert((pkt->getSize() == CL_SIZE) && "read:packet size isn't aligned with cache line");
            Addr rva;
            int h;
            Addr keyPathAddr[MAX_HEIGHT] = {0};
            iit_Node keyPathNode[MAX_HEIGHT] = {0};
            sdm_hashKey hash_key;
            sdm_table[id].key_get(HASH_KEY_TYPE, hash_key);
            Addr hmacAddr;                    // hmac在远端的物理地址
            uint8_t hpg_data[PAGE_SIZE >> 1]; // 在函数verify调用的hmac-verify函数中会读取所在的半页密态内存,需要在verify的调用者中准备存储空间
            bool verified = verify(paddr, hpg_data, id, &rva, &h, keyPathAddr, keyPathNode, &hmacAddr, hash_key);
            assert(verified && "verify failed before read");
            assert(0 && "sDM_Decrypt failed");
            CL_Counter cl;
            keyPathNode[0].getCounter_k(IIT_LEAF_TYPE, rva / (IIT_LEAF_ARITY * CL_SIZE), cl);
            sdm_CMEKey cme_key;
            sdm_table[id].key_get(CME_KEY_TYPE, cme_key);
            // 解密Packet中的数据,并修改其中的数据
            CME::sDM_Decrypt(pkt->getPtr<uint8_t>(), (uint8_t *)&cl, sizeof(CL_Counter), paddr, cme_key);
        }
        /**
         * @author yqy
         * @brief 写入paddr的CL时进行校验,并加密、维护iit、计算hmac
         * @param pkt 截获的每一一个packet
         * @return 是否完成写入
         * @attention 1. 要求gem5的读取的大小与cacheline对齐
         * @attention 2. 假设写队列是安全的,真正写入内存时才进行修改,读取写队列中的数据不需要校验
         * @attention 3. 注意minor计数器溢出引发的重新加密半页数据写回到内存时,不需要检查
         */
        void
        sDMmanager::write(PacketPtr pkt)
        {
            Addr paddr = pkt->getAddr();
            sdmIDtype id;
            id = isContained(paddr);
            if (!id) // 无需修改任何数据包
                return;
            assert((pkt->getSize() == CL_SIZE) && "write:packet size isn't aligned with cache line");
            Addr rva; // 该地址在所属空间中的相对偏移
            int h;
            Addr keyPathAddr[MAX_HEIGHT] = {0};
            iit_Node keyPathNode[MAX_HEIGHT] = {0};
            sdm_hashKey hash_key;
            sdm_table[id].key_get(HASH_KEY_TYPE, hash_key);
            Addr hmacAddr;                    // 对应的hmac在远端的物理地址
            uint8_t hpg_data[PAGE_SIZE >> 1]; // 在函数verify调用的hmac-verify函数中会读取所在的半页密态内存,需要在verify的调用者中准备存储空间
            bool verified = verify(paddr, hpg_data, id, &rva, &h, keyPathAddr, keyPathNode, &hmacAddr, hash_key);
            assert(verified && "verify failed before write");
            uint32_t cur_k = rva / (IIT_LEAF_ARITY * CL_SIZE);
            int node_type = IIT_LEAF_TYPE;
            bool OF;
            iit_Node bkeyPathNode[MAX_HEIGHT];
            // 备份原来的节点信息(解密旧数据需要)
            memcpy(bkeyPathNode, keyPathNode, sizeof(iit_Node) * MAX_HEIGHT);
            keyPathNode[0].inc_counter(node_type, cur_k, OF);
            keyPathNode[0].get_hash_tag(node_type, hash_key, paddr);
            cur_k /= IIT_MID_ARITY;
            sdm_CMEKey cme_key;
            sdm_table[id].key_get(CME_KEY_TYPE, cme_key);
            Addr hPageAddr = (paddr & PAGE_ALIGN_MASK) | (paddr & (PAGE_SIZE >> 1)); // 半页对齐地址
            CL_Counter cl;
            int off = (paddr - hPageAddr) / CL_SIZE; // 对应所在半页中的第几个计数器/缓存行
            if (OF)                                  // 引发重加密所在半页
            {
                // 可以提前取得所在半页的数据(已在hpg_data中取得),其后的HMAC计算是必须的,提高并行度
                for (int i = 0; i < (PAGE_SIZE >> 1) / CL_SIZE; i++)
                {
                    // 先解密得到原数据
                    bkeyPathNode[0].getCounter_k(IIT_LEAF_TYPE, i, cl); // 取得该cl的旧counter
                    CME::sDM_Decrypt(hpg_data + i * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter),
                                     hPageAddr + i * CL_SIZE, cme_key);
                }
                memcpy(hpg_data + off * CL_SIZE, pkt->getPtr<uint8_t>(), CL_SIZE);
                for (int i = 0; i < (PAGE_SIZE >> 1) / CL_SIZE; i++)
                {
                    // 使用新的counter加密
                    keyPathNode[0].getCounter_k(IIT_LEAF_TYPE, i, cl);
                    CME::sDM_Encrypt(hpg_data + i * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter),
                                     hPageAddr + i * CL_SIZE, cme_key);
                    // 将重新加密好的cacheLine写回到内存
                    write2Mem(CL_SIZE, hpg_data + i * CL_SIZE, hPageAddr + i * CL_SIZE);
                }
            }
            else
            {
                keyPathNode[0].getCounter_k(IIT_LEAF_TYPE, off, cl);
                CME::sDM_Encrypt(pkt->getPtr<uint8_t>(), (uint8_t *)&cl, sizeof(CL_Counter),
                                 hPageAddr + off * CL_SIZE, cme_key);
                // 将重新加密好的cacheLine写回到内存
                write2Mem(CL_SIZE, hpg_data + off * CL_SIZE, hPageAddr + off * CL_SIZE);
                // 保持hpg_data的最新性,加密性,下面计算hmac会使用该数组
                memcpy(hpg_data + off * CL_SIZE, pkt->getPtr<uint8_t>(), CL_SIZE);
            }
            // 2. 重新计算HMAC并写入到远端内存
            uint8_t hmac[CL_SIZE >> 1];
            hmac_get(hpg_data, hPageAddr, keyPathNode, hash_key, hmac);
            write2Mem(CL_SIZE >> 1, hmac, hmacAddr);
            // 3. 修改iit tree并写回
            for (int i = 1; i < h; i++)
            {
                keyPathNode[i].inc_counter(node_type, cur_k, OF);
                keyPathNode[i].get_hash_tag(node_type, hash_key, paddr);
                cur_k /= IIT_MID_ARITY;
                write2Mem(sizeof(iit_Node), (uint8_t *)(&keyPathNode[i]), keyPathAddr[i]);
            }
        }
    }
}
