#include "sDM.hh"
#include "sDMdef.hh"
#include "sDMglb.hh"
extern std::vector<gem5::memory::AbstractMemory *> sDMdrams;

namespace gem5
{
    std::unordered_map<uint64_t, uint64_t> rpTable;
    namespace sDM
    {
        uint64_t maxTick;
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
         * @brief dump page data
         */
        void sDMdump(char *title, uint8_t *tptr, size_t sz)
        {
            printf("%s:\n", title);
            for (size_t i = 0; i < sz; i++)
            {
                // printf("%016lx  ", ptr[i]);
                printf("%02x ", tptr[i]);
                if ((i + 1) % 8 == 0)
                    printf("  ");
                if ((i + 1) % 16 == 0)
                    printf("\n");
            }
            printf("----------------------------------------\n");
        }
        /**
         * @author yqy
         * @brief 根据数据区大小计算iit大小
         * @return 返回整个iit的字节大小
         */
        uint64_t getIITsize(uint64_t data_size, uint32_t &h)
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
                leaf_num = ceil(leaf_num, IIT_MID_ARITY);
                h++;
            }
            return node_num * CL_SIZE; // 转换为字节大小
        }

        /**
         * sDMmanager构造函数，后续需要初始化的变量可以添加到sDM.py配置文件中（每个变量可能需要赋默认值），通过params初始化
         * 如果要在类实例化时通过传参初始化，可采用以下方法，覆盖默认值。
         * params = {"x": 3, "y": 4}
         * instance = sDMmanager(params=params)
         * @attention 待传入参数
         */
        sDMmanager::sDMmanager(const sDMmanagerParams &params) : ClockedObject(params),
                                                                 memPort(params.name + ".mem_side", this),
                                                                 _requestorId(params.system->getRequestorId(this)),
                                                                 //  process(params.process),
                                                                 local_pool_id(params.local_pool_id),
                                                                 remote_pool_id(params.remote_pool_id)

        {
            has_recv = false;
            pkt_recv = NULL;
            waitAddr = 0;
            sdm_space_cnt = 0;
            sdm_table.assign(1, sdm_space());
            // printf("sDM.cpp process=%p,sDMmanager=%p,requestorId=%d\n", process, this, _requestorId);
            // std::cout << "!!sDMmanager!!\n"
            //   << "requestorID"
            //   << " " << _requestorId << std::endl;
        }
        /**
         * @author psj
         * @brief 收到响应packet后记录pkt并向发送方通知已接收响应包
         * @return 返回是否成功收到响应packet
         * @attention 未验证*
         */
        void sDMmanager::read4Mem(uint32_t byte_size, uint8_t *container, Addr gem5_addr)
        {
            int num = byte_size / CL_SIZE;
            if (!num)
                read4gem5(byte_size, container, gem5_addr);
            for (int i = 0; i < num; i++)
                read4gem5(CL_SIZE, container + i * CL_SIZE, gem5_addr + i * CL_SIZE);
            return;
        }
        /**
         * @brief:实际从gem5中读取
         */
        void sDMmanager::read4gem5(uint32_t byte_size, uint8_t *container, Addr gem5_addr)
        {
            // RequestPtr req = std::make_shared<Request>(gem5_addr, byte_size, 0, _requestorId);
            // PacketPtr pkt = Packet::createRead(req);
            // pkt->dataDynamic(new uint8_t[byte_size]);
            // pkt->setsDMflag();
            // maxTick = 0;
            // waitAddr = gem5_addr;
            // memPort.sendTimingReq(pkt);
            // mem_ctrl发回响应packet时会自动调用recvTimingResp的函数，设置两个全局变量has_recv和pkt_recv
            // 当has_recv为true时，表示收到响应packet，在recvTimingResp函数中将收到响应pkt复制给pkt_recv

            // pkt->writeDataToBlock(container, byte_size);
            if (sDMdrams[remote_pool_id]->getAddrRange().contains(gem5_addr))
            {
                memcpy(container, sDMdrams[remote_pool_id]->toHostAddr(gem5_addr), byte_size);
            }
            else
            {
                assert(sDMdrams[local_pool_id]->getAddrRange().contains(gem5_addr) && "undefind addr");
                memcpy(container, sDMdrams[local_pool_id]->toHostAddr(gem5_addr), byte_size);
            }

            // waitAddr = 0;
            // delete pkt;
            return;
        }

        /**
         * @author psj
         * @brief 将连续数据写入到gem5内存中
         * @param byte_size 写入字节大小
         * @param data 数据指针
         * @param gem5_addr 写入的位置
         * @attention 未验证*
         * @attention 注意可能需要将地址按CL对齐后再读写
         */
        void sDMmanager::write2gem5(uint32_t byte_size, uint8_t *data, Addr gem5_addr)
        {
            // RequestPtr req = std::make_shared<Request>(gem5_addr, byte_size, 0, _requestorId);
            // PacketPtr pkt = new Packet(req, MemCmd::WritebackDirty); // why can't WriteReq?
            // PacketPtr pkt = new Packet(req, MemCmd::WriteReq);
            // pkt->allocate();
            // pkt->setData((const uint8_t *)data);
            // pkt->setsDMflag();
            // maxTick = 0;
            // memPort.sendTimingReq(pkt); //  packet mem[i]->gem5MemPtr->[i];...
            if (sDMdrams[remote_pool_id]->getAddrRange().contains(gem5_addr))
            {
                memcpy(sDMdrams[remote_pool_id]->toHostAddr(gem5_addr), data, byte_size);
            }
            else
            {
                assert(sDMdrams[local_pool_id]->getAddrRange().contains(gem5_addr) && "undefind addr");
                memcpy(sDMdrams[local_pool_id]->toHostAddr(gem5_addr), data, byte_size);
            }
            // printf("write2mem over \n");
            return;
        }

        /**
         * @brief sDMmanger调用 byte_size可以为任意值
         * @param byte_size 写入字节大小
         * @param data 数据指针
         * @param gem5_addr 写入的位置
         */
        void sDMmanager::write2Mem(uint32_t byte_size, uint8_t *data, Addr gem5_addr)
        {
            // assert(byte_size >= CL_SIZE && "write2Mem: byte_size >= CL_SIZE");
            // assert((byte_size % CL_SIZE == 0) && "write2Mem: byte_size is aligned by CL_SIZE");
            // divide into CL_SIZE
            uint32_t num = byte_size / CL_SIZE;
            if (!num)
            {
                write2gem5(byte_size, data, gem5_addr);
            }
            for (uint32_t i = 0; i < num; i++)
            {
                write2gem5(CL_SIZE, data + i * CL_SIZE, gem5_addr + i * CL_SIZE);
            }
        }

        /**
         * @author ys
         * @brief 用于申请一定大小的物理空间,用于存储sdm管理结构
         * @param npages 申请空间的页面数
         * @param pool_id 使用哪个内存进行分配
         * @param phy_list 返回分配到的物理地址链表vector<phy_space_block>
         */
        bool
        sDMmanager::sdm_malloc(int npages, int pool_id, std::vector<phy_space_block> &phy_list)
        {
            Addr start = mem_pools->allocPhysPages(npages, pool_id); // 调用gem5物理内存分配函数直接分配
            // 由于gem5本身没有处理不连续的地址情况,所以一定是连续的
            if (start == POOL_EXHAUSTED)
            {
                // printf("pool exhausted\n");
                // 本地内存耗尽
                return false;
            }
            phy_list.push_back({start, npages});
            // 成功则直接返回
            return true;
        }

        /**
         * @author yqy
         * @brief
         * 判断地址所在页是否处于sdm中
         * 并返回其id
         * @return
         * 返回0表示该地址所在页面不处于任何sdm中
         * 否则返回其所在sdm的id(sdmIDtype)
         */
        sdmIDtype sDMmanager::isContained(Addr vaddr)
        {
            vaddr &= PAGE_ALIGN_MASK;
            if (sdm_paddr2id.size() == 0)
            {
                return 0;
            }
            auto it = sdm_paddr2id.lower_bound(vaddr);
            if (it != sdm_paddr2id.end() && it->first == vaddr)
                return it->second.second;
            if (it != sdm_paddr2id.begin())
                it--;
            if (it->first <= vaddr && vaddr < it->first + it->second.first)
                return it->second.second;
            return 0;
        }
        /**
         * @author yqy
         * @brief 返回虚拟地址在所属sdm中的虚拟空间的相对偏移
         * @param id:所属sdm的编号(sdmIDtype)
         * @param data_vaddr:虚拟地址
         * @return 虚拟空间的相对偏移
         */
        Addr sDMmanager::getVirtualOffset(sdmIDtype id, Addr data_vaddr)
        {
            return data_vaddr - sdm_table[id].datavAddr;
        }
        /**
         * @author yqy
         * @brief 利用skip list查询
         * @brief 用于距离首地址偏移所在页的物理地址
         * @param offset 偏移量
         * @param head 本地页的起始页地址
         * @param skip 空间对应表的skip的大小
         * @param known 标识是否已经检查过该页(0:未检查,1:处于该本地页,2:超出该本地页)
         * @param &pnum 前面逻辑连续的页面数
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
                    // 读取页的最后一个数据对(本身就需要减去自身的大小),还要除去local_jmp
                    // 注意因此减去PAIR_SIZE+sizeof(local_jmp)
                    read4Mem(PAIR_SIZE, (uint8_t *)&rbound, head + mid * PAGE_SIZE + PAGE_SIZE - PAIR_SIZE - sizeof(local_jmp));
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
                // l = skip / 2 - 1;
                l = skip - 1;
                r = PAGE_SIZE / PAIR_SIZE;
                while (r - l > 1)
                {
                    int mid = (r + l) >> 1;
                    read4Mem(PAIR_SIZE, (uint8_t *)&rbound, head + (mid * PAIR_SIZE));
                    if ((rboundp->pnum + rboundp->cnum) * PAGE_SIZE > offset || // debug >= -> >
                        (rboundp->cnum = -1 && rboundp->cnum == rboundp->pnum)) // 0xffffffffffffffff
                        r = mid;
                    else
                        l = mid;
                }
                // 在第r个数据对中
                // 在数据对中找到所在页
                head = rboundp->curPageAddr;
                head += offset - rboundp->pnum * PAGE_SIZE;
                pnum = rboundp->pnum + (offset - rboundp->pnum * PAGE_SIZE) / PAGE_SIZE;
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
                while (jmps[i].maxBound > offset && i > 0)
                    i--;
                return find(jmps[i].next, offset, skip, 0, pnum);
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
         */
        int sDMmanager::getKeyPath(sdmIDtype id, Addr rva, Addr *keyPathAddr, iit_NodePtr keyPathNode)
        {
            int pnum = 0; // 目标页前面有多少逻辑页
            // 在sdm_space 中加了一个iITh变量，在getiitsize()函数里计算
            uint32_t h = sdm_table[id].iITh;
            uint64_t nodenums = sdm_table[id].sDataSize / (IIT_LEAF_ARITY * CL_SIZE); // 叶节点数,之后表示当前层的节点数
            uint64_t offset = (rva / (CL_SIZE * IIT_LEAF_ARITY));                     // 该偏移对应哪一个叶节点，之后表示相对当前层的节点偏移量
            Addr offsetiit = offset * sizeof(iit_Node);                               // 相对于iit树第一个节点的偏移地址
            for (int i = 0; i < h; i++)
            {
                // 远端物理地址
                Addr NodePagePtr = find((Addr)sdm_table[id].iITPtrPagePtr, offsetiit, sdm_table[id].iit_skip, 0, pnum);
                // NodePagePtr += (offsetiit - pnum * PAGE_SIZE); // 目标页首地址加上偏移
                // NodePagePtr += offsetiit;
                keyPathAddr[i] = NodePagePtr; // 目标节点的远端物理地址
                read4Mem(sizeof(iit_Node), (u_int8_t *)(&keyPathNode[i]), NodePagePtr);
                offsetiit += (nodenums - offset) * sizeof(iit_Node);
                nodenums = ceil(nodenums, IIT_MID_ARITY); // 下一层的节点数
                offset /= IIT_MID_ARITY;
                // iit_hash_tag hash_tag = keyPathNode[i].abstract_hash_tag((i == 0 ? IIT_LEAF_TYPE : IIT_MID_TYPE));
                offsetiit += offset * sizeof(iit_Node);
            }
            return h;
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
            if (pair_num >= 8 * ((PAGE_SIZE / PAIR_SIZE - 1) - 3))
                skip = 3; // 构建3级 step=1,2,4
            else if (pair_num >= 4 * (((PAGE_SIZE / PAIR_SIZE - 1) - 2)))
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
            int cur = 0;       // 当前正在写第几个页面
            int cur_seg = 0;   // 当前正在使用第几个本地连续段
            int cur_k = 1;     // 当前正在使用第几个本地连续段中的第几个
            int seg_start = 0; // 当前段的起始页面下标
            int seg_size = local_phy_list.size();
            int seg_start_num[seg_size] = {0}; // 每一段起始页面下标
            // 当前正在记录第几个页面数据对
            size_t cur_pair = 0;
            // 前面累积的物理空间逻辑大小
            uint32_t logic_npages = 0;
            sdm_hmacPagePtrPage mem[lnpages]; // 用于暂时组织数据,然后统一调用packet将数据写到hmacPtrPagePtr对应的本地页中
            // 先在缓冲mem中填写每一个页面
            while (cur_pair < remote_phy_list.size()) // 所有页面数据对
            {
                // 每次都开始写一个新的本地页面
                memset(&mem[cur], 0xff, sizeof(sdm_hmacPagePtrPage));
                // 首先写入skip部分
                for (int i = 0; i < skip; i++)
                {
                    if (cur_seg + (1 << i) < local_phy_list.size() - 1) // 还有后续段 debug只有一个页面时仍会进入
                    {
                        mem[cur].jmp[i].next = local_phy_list[cur_seg + (1 << i)].start;
                    }
                    // else // 不存在后续段
                    // {
                    //     mem[cur].jmp[i].next = 0x0;
                    //     mem[cur].jmp[i].maxBound = 0x0;
                    // }
                }
                // 然后填充数据对
                for (int i = 0; i < ac_num; i++)
                {
                    // 前skip的位置是skip_list的结构
                    mem[cur].pair[skip + i].curPageAddr = remote_phy_list[cur_pair].start;
                    mem[cur].pair[skip + i].cnum = remote_phy_list[cur_pair].npages;
                    mem[cur].pair[skip + i].pnum = logic_npages;
                    //        mem[cur].pair[skip + i].curPageAddr,
                    //        mem[cur].pair[skip + i].cnum,
                    //        mem[cur].pair[skip + i].pnum);
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
                    for (int i = seg_start + 1; i <= cur; i++)
                        mem[i].cur_segMax.maxBound = mem[seg_start].cur_segMax.maxBound;
                    // write2Mem(PAIR_SIZE, (uint8_t *)&(mem[seg_start].cur_segMax), ptrPagePtr[seg_start] + PAGE_SIZE - PAIR_SIZE);
                    // 该连续段已用完
                    if (cur_pair < remote_phy_list.size() && cur_seg < local_phy_list.size()) // 防止最后一个页面越界
                    {
                        // 找到下一个可用的本地页
                        cur_seg++;           // 使用下个段
                        cur_k = 1;           // 新连续段的第一个
                        seg_start = cur + 1; // 记录新连续段的下标
                        seg_start_num[cur_seg] = cur + 1;
                        ptrPagePtr[cur + 1] = local_phy_list[cur_seg].start; // 记录新页面对应的本地物理地址
                    }
                }
                // 先写入该页面的pair数据对到gem5内存
                // 改为统一写入
                // write2Mem(PAGE_SIZE - PAIR_SIZE - skip * sizeof(skip_jmp), (uint8_t *)&(mem[cur].pair[skip]), ptrPagePtr[cur] + sizeof(skip_jmp) * skip);
                cur++;
            }
            // 回写skip list的next.max_bound
            for (int i = 0; i < local_phy_list.size(); i++)
            {
                for (int j = 0; j < skip; j++)
                {
                    if (i + (1 << j) >= local_phy_list.size()) // 越界
                        continue;
                    mem[seg_start_num[i]].jmp[j].maxBound = mem[seg_start_num[i + (1 << j)]].cur_segMax.maxBound;
                }
                // 改为统一写入
                // write2Mem(sizeof(skip_jmp) * skip, (uint8_t *)&mem[i], ptrPagePtr[i]); // 重写这些部分
            }
            // 分多次写入 -> 统一写入
            for (int i = 0; i < lnpages; i++)
            {
                write2Mem(PAGE_SIZE, (uint8_t *)&mem[i], ptrPagePtr[i]);
            }
        }
        /**
         * @author: ys
         * @description: sdm空间初始化函数
         * @param {Addr} vaddr  数据的虚拟地址
         * @param {size_t} byte_size    数据大小
         * @param {sdm_CMEKey} ckey
         * @param {sdm_hashKey} hkey
         * @param {vector<phy_space_block>} r_hmac_phy_list 远端存放hmac的物理地址
         * @param {vector<phy_space_block>} r_iit_phy_list 远端存放iit的物理地址
         */
        void sDMmanager::sDMspace_init(Addr vaddr, size_t byte_size, sdm_CMEKey ckey, sdm_hashKey hkey,
                                       std::vector<phy_space_block> r_hmac_phy_list, std::vector<phy_space_block> r_iit_phy_list,
                                       uint32_t h, sdm_space &sp)
        {
            assert(r_hmac_phy_list.size() > 0);
            // 向数据空间写入0(并加密)
            CL_Counter cl{0};
            uint8_t *encrypteddata = (uint8_t *)malloc(byte_size);
            Addr addr = vaddr;
            for (int i = 0; i < byte_size / CL_SIZE; i++)
            {
                // 分CL加密并写入
                uint8_t buf[64] = {0}; // 64字节的缓存行
                auto entry = process->pTable->lookup(addr & PAGE_ALIGN_MASK);
                assert(entry != NULL);
                Addr paddr = entry->paddr + (addr & (~PAGE_ALIGN_MASK));
                CME::sDM_Encrypt(buf, cl, sizeof(cl), paddr, ckey); // 加密数据
                write2Mem(CL_SIZE, buf, paddr);                     // 写回内存
                memcpy(encrypteddata + i * CL_SIZE, buf, CL_SIZE);
                addr += CL_SIZE;
            }
            addr = vaddr;

            // 计算HMAC
            int hmacpageindx = 0; // 存hmac的物理页面列表的索引
            auto block = r_hmac_phy_list[hmacpageindx++];
            Addr hmacpageAddrstart = block.start;                          // 存放hmac的起始物理地址(远端)
            Addr hmacpageAddrend = block.start + PAGE_SIZE * block.npages; // 该数据对对应的结束地址
            printf("hmac paddr=[%lx]\n", hmacpageAddrstart);
            uint8_t hmac[SM3_SIZE * 2];
            iit_Node counter = {0};
            for (int i = 0; i < byte_size / (PAGE_SIZE >> 1); i++)
            {
                // Addr hpageAddr = (addr & PAGE_ALIGN_MASK) + (addr & (PAGE_SIZE >> 1)); // 加密使用的缓存行地址 unused
                auto entry = process->pTable->lookup(addr & PAGE_ALIGN_MASK);
                assert(entry != NULL);
                Addr paddr = entry->paddr + (addr & (PAGE_SIZE >> 1));
                // read4Mem(PAGE_SIZE >> 1, dataptr, paddr); // 被加密的数据

                // iit_NodePtr counter = new iit_Node(); // new 会将结构体内部置0

                CME::sDM_HMAC(encrypteddata + i * (PAGE_SIZE >> 1), PAGE_SIZE >> 1, hkey, paddr, (uint8_t *)(&counter),
                              sizeof(iit_Node), hmac + (i & 1) * SM3_SIZE, SM3_SIZE); // 计算hash值，存入hmac

                if (hmacpageAddrstart < hmacpageAddrend)
                {
                    hmacpageAddrstart += SM3_SIZE;
                }
                else
                { // 页面耗尽了,重新计算下一个页的起始和结束地址
                    assert(hmacpageindx < r_hmac_phy_list.size());
                    auto block = r_hmac_phy_list[hmacpageindx++];
                    hmacpageAddrstart = block.start;
                    hmacpageAddrend = hmacpageAddrstart + block.npages * PAGE_SIZE;
                    hmacpageAddrstart += SM3_SIZE;
                }
                if ((i & 1) == 1)
                {
                    write2Mem(SM3_SIZE * 2, hmac, hmacpageAddrstart - SM3_SIZE * 2);
                }
                addr += PAGE_SIZE >> 1;
            }
            printf("[%ld]in sdm_init hmac done\n", curTick());
            //  构建iit
            uint64_t leaf_num = byte_size / (IIT_LEAF_ARITY * CL_SIZE);
            uint64_t iitpPageindex = 0;
            block = r_iit_phy_list[iitpPageindex++];
            Addr curpPageAddrstart = block.start;
            Addr curpPageAddrend = curpPageAddrstart + block.npages * PAGE_SIZE;
            bool leaf = true;  // 是否是叶节点
            uint32_t curh = 1; // 当前层数
            iit_Node node = {0};
            printf("iMT paddr=[%lx]\n", curpPageAddrstart);
            while (curh <= h)
            {
                uint64_t curlayernodenum = leaf_num; // 当前层结点
                int i = 0;                           // 计算缓存行索引
                Addr hpageAddr =
                    (curpPageAddrstart & PAGE_ALIGN_MASK) + (curpPageAddrstart & (PAGE_SIZE >> 1)); // 所在半页地址
                while (curlayernodenum > 0)
                {
                    i = (curpPageAddrstart - hpageAddr) / CL_SIZE; // 缓存行索引
                    // 算hash_tag
                    // iit_hash_tag hash_tag;
                    uint8_t nodetype;
                    if (leaf)
                    { // 叶节点
                        nodetype = IIT_LEAF_TYPE;
                        // hpageAddr + i* CL_SIZE 是所在缓存行的首地址
                    }
                    else
                    { // 中间节点
                        nodetype = IIT_MID_TYPE;
                    }
                    node.init(nodetype, hkey, hpageAddr + i * CL_SIZE);
                    // iit_hash_tag hash_tag_test = node.abstract_hash_tag(nodetype);
                    // 写入物理地址
                    write2Mem(sizeof(iit_Node), (uint8_t *)&node, curpPageAddrstart);
                    curpPageAddrstart += sizeof(_iit_Node);
                    if (curpPageAddrstart >= curpPageAddrend)
                    { // 页面可用空间耗尽
                        auto block = r_iit_phy_list[iitpPageindex++];
                        curpPageAddrstart = block.start;
                        curpPageAddrend = block.npages * PAGE_SIZE + curpPageAddrstart;
                    }
                    curlayernodenum--; // 当前层写完了一个节点
                }
                leaf = false;
                leaf_num = ceil(leaf_num, IIT_MID_ARITY); // 下一层的结点数
                if(curh==h)
                {
                    memcpy((uint8_t *)(&sp.Root), (uint8_t*)(&node), sizeof(iit_Node));
                }
                curh++;
            }
            printf("[%ld]in sdm_init iMT done\n", curTick());
            return;
        }
        /**
         * @brief 为数据空间构建sDM空间
         * @author yqy
         * @param pPageList 该sDM空间内的数据页物理地址列表
         * @return 是否成功注册
         * //sdm metadata指针(这里sdm metadata是sdm结构体指针)
         * @attention 初始化这些空间的数据没有实现*
         */
        bool
        sDMmanager::sDMspace_register(uint64_t pid, Addr vaddr, size_t data_byte_size)
        {
            assert(data_byte_size && "data is empty");
            assert(((vaddr & (PAGE_SIZE - 1)) == 0) &&
                   ((data_byte_size & (PAGE_SIZE - 1)) == 0) &&
                   "vaddr or size is not aligned pagesize");
            printf("data_byte_size:%ldB\n", data_byte_size);

            const gem5::EmulationPageTable::Entry *entry = process->pTable->lookup(vaddr);
            assert(entry != NULL);

            printf("[%ld]in sDMspace_register: pid=%ld vaddr=%lx(paddr=%lx) size=%ldkB\n",
                   curTick(), pid, vaddr, entry->paddr + (vaddr & (PAGE_SIZE - 1)), data_byte_size / 1024);
            // 准备新空间的metadata
            sdm_space sp;
            // 1. 计算data大小
            uint64_t data_size = data_byte_size;
            // data_size *= PAGE_SIZE;
            // 检查申请的虚拟空间是否已经存在于其他space中
            auto aft = sdm_paddr2id.lower_bound((Addr)(vaddr + data_size));
            if (sdm_paddr2id.size() != 0) // 第一次不用检查，一定没有重复
            {
                if (aft != sdm_paddr2id.begin())
                {
                    aft--;
                    assert((aft->first + (aft->second.first) <= vaddr) && "overlapped");
                }
                else
                {
                    assert((aft->first >= vaddr + data_byte_size) && "overlapped");
                }
            }
            // 2. 计算IIT树大小
            uint32_t h = 1;
            sdm_size iit_size = getIITsize(data_size, h);
            // 3. 计算HMAC大小
            sdm_size hmac_size = data_size / SDM_HMAC_ZOOM;
            printf("iit_size = %ld\nhmac_size=%ld\n", iit_size,hmac_size);
            // sdm_size extra_size = iit_size + hmac_size; // 额外所需空间的总大小
            // 为新空间设置id
            sp.id = ++sdm_space_cnt;
            sp.iITh = h;
            sp.sDataSize = data_byte_size;
            sp.datavAddr = vaddr;
            // 为新空间设置密钥 暂时简单使用id做密钥
            memset(&sp.cme_key, 0, sizeof(sp.cme_key));
            memset(&sp.hash_key, 0, sizeof(sp.hash_key));
            memcpy(&sp.cme_key, &sp.id, sizeof(sp.id));
            memcpy(&sp.hash_key, &sp.id, sizeof(sp.id));
            // 为新空间的hmac和iit申请远端内存空间
            std::vector<phy_space_block> r_hmac_phy_list;
            std::vector<phy_space_block> r_iit_phy_list;
            // ys(debug):hmac空间大小可能没有按照页对齐，应向上取整
            assert(sdm_malloc(ceil(hmac_size, PAGE_SIZE), remote_pool_id, r_hmac_phy_list));
            assert(sdm_malloc(ceil(iit_size, PAGE_SIZE), remote_pool_id, r_iit_phy_list));
            // 初始化HMAC和iit区域(将数据区置0)
            sdm_CMEKey tmp_ckey;
            sp.key_get(CME_KEY_TYPE, tmp_ckey);
            sdm_hashKey tmp_hkey;
            sp.key_get(HASH_KEY_TYPE, tmp_hkey);
            sDMspace_init(vaddr, data_size, tmp_ckey, tmp_hkey, r_hmac_phy_list, r_iit_phy_list, sp.iITh, sp);
            // 预估所需页面数量,同时填写跳数、每页可写数据对数量
            int hmac_per, iit_per;
            int hmac_lpage_num = pred_local_page_need(sp.hmac_skip, r_hmac_phy_list.size(), hmac_per);
            int iit_lpage_num = pred_local_page_need(sp.iit_skip, r_iit_phy_list.size(), iit_per);
            // 向本地申请内存空间
            std::vector<phy_space_block> l_hmac_phy_list;
            std::vector<phy_space_block> l_iit_phy_list;
            assert(sdm_malloc(hmac_lpage_num, local_pool_id, l_hmac_phy_list));
            assert(sdm_malloc(iit_lpage_num, local_pool_id, l_iit_phy_list));
            // 构建两个链表
            sp.HMACPtrPagePtr = (sdm_hmacPagePtrPagePtr)(l_hmac_phy_list[0].start);
            sp.iITPtrPagePtr = (sdm_iitNodePagePtrPagePtr)(l_iit_phy_list[0].start);
            // 构建skip-list
            // 构建hmac skip-list
            build_SkipList(r_hmac_phy_list, l_hmac_phy_list, sp.hmac_skip, hmac_per, hmac_lpage_num);
            // 构建iit skip-list
            build_SkipList(r_iit_phy_list, l_iit_phy_list, sp.iit_skip, iit_per, iit_lpage_num);
            // 这里的sdm_table、sdm_paddr2id查询还没有接入gem5内存系统
            sdm_table.push_back(sp);
            // 加入到vaddr->id查询表
            sdm_paddr2id.insert(std::make_pair(vaddr, std::make_pair(data_size, sp.id)));
            return true;
        }
        /**
         * @author yqy
         * @brief 计算HMAC(所在半页)
         * @param sdata 加密后的内存数据指针
         * @param hpaddr 所在半页的物理地址
         * @param counter 所在半页对应的计数器(节点)指针
         * @param hash_key 所属sdm的hash密钥
         * @param hmac 返回计算得到的hmac指针
         * @attention 最终返回的HMAC长度为32Byte
         */
        void hmac_get(uint8_t *sdata, Addr hpaddr, iit_NodePtr counter, sdm_hashKey hash_key, uint8_t *hmac)
        {
            CME::sDM_HMAC(sdata, PAGE_SIZE >> 1, hash_key, hpaddr, (uint8_t *)counter, sizeof(iit_Node), hmac, SM3_SIZE);
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
        bool sDMmanager::hmac_verify(Addr dataVAddr, Addr rva, Addr *hmacAddr, sdmIDtype id,
                                     uint8_t *hpg_data, iit_NodePtr counters, sdm_hashKey hash_key)
        {
            const gem5::EmulationPageTable::Entry *entry = process->pTable->lookup(dataVAddr);
            assert(entry != NULL);
            Addr pageAddr = entry->paddr;
            pageAddr |= (dataVAddr & (PAGE_SIZE >> 1));
            uint8_t calc_hmac[SM3_SIZE];
            // 读取所在半页的内存数据
            read4Mem(PAGE_SIZE >> 1, hpg_data, pageAddr);
            //  计算HMAC
            hmac_get(hpg_data, pageAddr, counters, hash_key, calc_hmac);
            // 与存储值比较
            int pnum = 0;
            // rva /= SDM_HMAC_ZOOM;
            // rva是数据的虚拟空间的相对偏移，需按半页转换成hmac存储空间的相对偏移
            *hmacAddr = find((Addr)sdm_table[id].HMACPtrPagePtr, (rva / (PAGE_SIZE >> 1)) * SM3_SIZE, sdm_table[id].hmac_skip, 0, pnum);
            sdm_HMAC stored_hmac;
            // 从本地内存中读取
            read4Mem(sizeof(sdm_HMAC), stored_hmac, *hmacAddr);

            assert(memcmp(calc_hmac, stored_hmac, sizeof(sdm_HMAC)) == 0 && "HMAC verify failed");
            return true;
        }
        /**
         * @author yqy
         * @brief 对paddr CL的数据进行校验
         * @brief 并将一些中间值通过传输的指针参数返回
         * @param data_vaddr 虚拟地址
         * @param hpg_data 所在半页的数据指针(这里是用来存储hmac-verify时读取的数据,避免多次重复读取,注意空间应该在调用者中事先分配)
         * @param id 用来存储所属sdm space的编号
         * @param rva 用来存储paddr处的数据位于整个安全空间的逻辑偏移(通过引用的形式返回给调用者)
         * @param h 记录关键路径的长度(通过引用的形式返回给调用者)
         * @param keyPathAddr 记录关键路径上节点在远端内存中的物理地址(避免多次重复读取,注意空间应该在调用者中事先分配)
         * @param keyPathNode 记录关键路径上节点的数据(避免多次重复读取,注意空间应该在调用者中事先分配)
         * @param key sdm_hashKe用于计算hash值的key
         */
        bool sDMmanager::verify(Addr data_vaddr, uint8_t *hpg_data, sdmIDtype id, Addr *rva, int *h,
                                Addr *keyPathAddr, iit_NodePtr keyPathNode, Addr *hmacAddr, sdm_hashKey hash_key)
        {
            iit_Node tmpLeaf;
            *rva = getVirtualOffset(id, data_vaddr);
            *h = getKeyPath(id, *rva, keyPathAddr, keyPathNode);
            keyPathNode[0].erase_hash_tag(IIT_LEAF_TYPE, &tmpLeaf);

            // 1. HMAC校验
#ifndef SDMDEBUG
            assert(hmac_verify(data_vaddr, *rva, hmacAddr, id, hpg_data, &tmpLeaf, hash_key) && "HMAC verity failed"); // 该函数内会读取所在半页的加密数据到hpg_data[PAGE_SIZE/2]数组中
#endif                                                                                                                 // #endif
            // 2. iit校验
            int type = IIT_LEAF_TYPE;
            // paddr对应的缓存行位于上层节点的哪个计数器
            uint32_t whichnode = (*rva) / (IIT_LEAF_ARITY * CL_SIZE);
            uint32_t next_k = whichnode & (IIT_MID_ARITY - 1); // % IIT_LEAF_ARITY

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
                    assert(verified && "f_cl!=cl");
                }
                // iit_hash_tag hash_tag = ((iit_Node *)(keyPathNode + i * sizeof(iit_Node)))->abstract_hash_tag(type);
                iit_hash_tag hash_tag = keyPathNode[i].abstract_hash_tag(type);
                iit_hash_tag chash_tag = keyPathNode[i].get_hash_tag(type, hash_key, keyPathAddr[i]);
                // 比较计算值和存储值
#ifndef SDMDEBUG
                assert(hash_tag == chash_tag);
#endif
                // 后续节点都是mid类型
                type = IIT_MID_TYPE;
                whichnode /= IIT_MID_ARITY;
                next_k = whichnode & (IIT_MID_ARITY - 1); //% IIT_MID_ARITY
            }
            if(verified)
            {
                verified = (memcpy((uint8_t *)(&sdm_table[id].Root), (uint8_t *)(&keyPathNode[*h-1]), sizeof(iit_Node)) == 0);
                assert(verified && "iMT Root verify failed");
            }
            // printf("iit verify done\n");
            return true;
        }
        /**
         * @author yqy
         * @brief 读取paddr的CL时进行校验
         * @return 是否通过校验
         * @attention 要求gem5的读取的大小与cacheline对齐
         * @attention 在abstract_mem.cc中检查每一一个read packet
         * @attention yqy(debug):处理access中访存粒度小于CL_SIZE的情况
         * @attention pkt 不应该被除检查requestorID外的任何操作使用
         */
        void sDMmanager::read(PacketPtr pkt, uint8_t *algined_mem_ptr, Addr pkt_vaddr)
        {
            pkt->payloadDelay += 4000;
            // Addr pktAddr = pkt->getAddr();
            if (pkt->requestorId() == requestorId()) // 不应该检查sDMmanager的请求,但目前无法pass其他process中sDMmanager的请求
                return;
            Addr pktAddr = pkt_vaddr;
            sdmIDtype id = sDMmanager::isContained(pktAddr);
            if (id == 0) // 该物理地址不包含在任何sdm中,无需对数据包做修改
                return;
            // 这个assert转移到上层函数abstract_mem.cc的access函数中检查
            // assert((pkt->getSize() == CL_SIZE) && "read:packet size isn't aligned with cache line");
            Addr rva;
            int h;
            Addr keyPathAddr[MAX_HEIGHT] = {0};
            iit_Node keyPathNode[MAX_HEIGHT] = {0};
            sdm_hashKey hash_key;
            sdm_table[id].key_get(HASH_KEY_TYPE, hash_key);
            Addr hmacAddr;                    // hmac在远端的物理地址
            uint8_t hpg_data[PAGE_SIZE >> 1]; // 在函数verify调用的hmac-verify函数中会读取所在的半页密态内存,需要在verify的调用者中准备存储空间
            // 注意这里验证使用了虚拟地址
            bool verified = verify(pktAddr, hpg_data, id, &rva, &h, keyPathAddr, keyPathNode, &hmacAddr, hash_key);
#ifndef SDMDEBUG
            assert(verified && "verify failed before read");
#endif
            CL_Counter cl;
            keyPathNode[0].getCounter_k(IIT_LEAF_TYPE, (rva & (IIT_LEAF_ARITY - 1)), cl);
            sdm_CMEKey cme_key;
            sdm_table[id].key_get(CME_KEY_TYPE, cme_key);
            // 解密Packet中的数据,并修改其中的数据
            // 注意这里解密也暂时先使用了虚拟地址
            Addr paddr;
            const gem5::EmulationPageTable::Entry *entry = process->pTable->lookup(pktAddr);
            assert(entry && "paddr is valid");
            paddr = entry->paddr + (pktAddr & (~PAGE_ALIGN_MASK) & (CL_ALIGN_MASK));
            CME::sDM_Decrypt(algined_mem_ptr, (uint8_t *)&cl, sizeof(CL_Counter), paddr, cme_key);
        }
        /**
         * @author yqy
         * @brief 写入paddr的CL时进行校验,并加密、维护iit、计算hmac
         * @param pkt 截获的每一个packet
         * @return 是否完成写入
         * @attention 1. X要求gem5的读取的大小与cacheline对齐X -> 函数内部检查(off_in_cl)
         * @attention 2. 假设写队列是安全的,真正写入内存时才进行修改,读取写队列中的数据不需要校验
         * @attention 3. 注意minor计数器溢出引发的重新加密半页数据写回到内存时,不需要检查
         * @attention 现在使用虚拟地址
         */
        void
        sDMmanager::write(PacketPtr pkt, uint8_t *aligned_mem_ptr, Addr pktVAddr)
        {
            pkt->payloadDelay += 4000;
            // 要求给出的缓存行地址必定对齐
            assert(pktVAddr % CL_SIZE == 0 && "write:packet address isn't aligned with cache line");
            if (pkt->requestorId() == requestorId() || pkt->checksDMflag()) // 不应该检查来自任何sDMmanager的请求
                return;
            sdmIDtype id = isContained(pktVAddr);
            if (id == 0) // 无需修改任何数据包
                return;
            Addr rva; // 该地址在所属空间中的相对偏移
            int h;
            Addr keyPathAddr[MAX_HEIGHT] = {0};
            iit_Node keyPathNode[MAX_HEIGHT] = {0};
            sdm_hashKey hash_key;
            sdm_table[id].key_get(HASH_KEY_TYPE, hash_key);
            Addr hmacAddr;                    // 对应的hmac在远端的物理地址
            uint8_t hpg_data[PAGE_SIZE >> 1]; // 在函数verify调用的hmac-verify函数中会读取所在的半页密态内存,需要在verify的调用者中准备存储空间
            bool verified = verify(pktVAddr, hpg_data, id, &rva, &h, keyPathAddr, keyPathNode, &hmacAddr, hash_key);
            // #ifndef SDMDEBUG
            assert(verified && "verify failed before write");
            // #endif
            uint32_t before_mod_cur_k = rva / CL_SIZE;
            uint32_t cur_k = before_mod_cur_k & (IIT_LEAF_ARITY - 1);
            int node_type = IIT_LEAF_TYPE;
            bool OF;
            iit_Node bkeyPathNode[MAX_HEIGHT];
            // 备份原来的节点信息(解密旧数据需要)
            memcpy(bkeyPathNode, keyPathNode, sizeof(iit_Node) * MAX_HEIGHT);
            keyPathNode[0].inc_counter(node_type, cur_k, OF);
            iit_hash_tag new_hash_tag = keyPathNode[0].get_hash_tag(node_type, hash_key, keyPathAddr[0]);
            keyPathNode[0].embed_hash_tag(IIT_LEAF_TYPE, new_hash_tag);
            before_mod_cur_k /= IIT_LEAF_ARITY;
            cur_k = before_mod_cur_k & (IIT_MID_ARITY - 1);
            sdm_CMEKey cme_key;
            sdm_table[id].key_get(CME_KEY_TYPE, cme_key);
            Addr hPageAddr = (pktVAddr & PAGE_ALIGN_MASK) | (pktVAddr & (PAGE_SIZE >> 1)); // 半页对齐地址
            CL_Counter cl;
            int off = (pktVAddr - hPageAddr) / CL_SIZE;   // 对应所在半页中的第几个计数器/缓存行
            uint8_t off_in_cl = pkt->getAddr() % CL_SIZE; // 对应缓存行中的偏移
            const gem5::EmulationPageTable::Entry *entry = process->pTable->lookup(hPageAddr);
            assert(entry && "paddr is valid");
            Addr hpaddr = entry->paddr + (hPageAddr & (PAGE_SIZE >> 1));
            Addr clpaddr = entry->paddr + (pktVAddr & (~PAGE_ALIGN_MASK));
            if (OF) // 引发重加密所在半页
            {
                // 可以提前取得所在半页的数据(已在hpg_data中取得),其后的HMAC计算是必须的,提高并行度
                for (int i = 0; i < (PAGE_SIZE >> 1) / CL_SIZE; i++) // 先解密得到原数据
                {
                    bkeyPathNode[0].getCounter_k(IIT_LEAF_TYPE, i, cl); // 取得该cl的旧counter
                    CME::sDM_Decrypt(hpg_data + i * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter),
                                     hpaddr + i * CL_SIZE, cme_key);
                }
                // 更新为写入后的数据
                memcpy(hpg_data + off * CL_SIZE + off_in_cl, pkt->getPtr<uint8_t>(), pkt->getSize());
                // 使用新的counter加密
                for (int i = 0; i < (PAGE_SIZE >> 1) / CL_SIZE; i++)
                {
                    keyPathNode[0].getCounter_k(IIT_LEAF_TYPE, i, cl);
                    CME::sDM_Encrypt(hpg_data + i * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter),
                                     hpaddr + i * CL_SIZE, cme_key);
                    // 将重新加密好的cacheLine写回到内存
                    if (hpaddr + i * CL_SIZE == clpaddr) // 是本次写操作的地址则直接放在aligned_mem_ptr
                        memcpy(aligned_mem_ptr, hpg_data + i * CL_SIZE, CL_SIZE);
                    else // 否则需要发起新的写请求
                        write2Mem(CL_SIZE, hpg_data + i * CL_SIZE, hpaddr + i * CL_SIZE);
                }
            }
            else
            {
                bkeyPathNode[0].getCounter_k(IIT_LEAF_TYPE, off, cl); // 取得该cl的旧counter
                // 解密对应缓存行
                CME::sDM_Decrypt(hpg_data + off * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter),
                                 hpaddr + off * CL_SIZE, cme_key);

                // 更新写入的数据部分,pkt可能不按CL_SIZE对齐
                memcpy(hpg_data + off * CL_SIZE + off_in_cl, pkt->getPtr<uint8_t>(), pkt->getSize());
                // 取得新的counter
                keyPathNode[0].getCounter_k(IIT_LEAF_TYPE, off, cl);

                // 重新加密
                CME::sDM_Encrypt(hpg_data + off * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter),
                                 clpaddr, cme_key);
                // 将重新加密好的cacheLine写回到内存
                // 已经在abstract_mem中对齐，现在写入到aligned_mem_ptr即可
                memcpy(aligned_mem_ptr, hpg_data + off * CL_SIZE, CL_SIZE);
                // write2Mem(CL_SIZE, hpg_data + off * CL_SIZE, entry->paddr + off * CL_SIZE);
            }
            // 2. 重新计算HMAC并写入到远端内存
            uint8_t hmac[CL_SIZE >> 1];
            iit_Node tmpLeaf;
            keyPathNode[0].erase_hash_tag(IIT_LEAF_TYPE, &tmpLeaf);
            hmac_get(hpg_data, hpaddr, &tmpLeaf, hash_key, hmac);
            write2Mem(CL_SIZE >> 1, hmac, hmacAddr);
            // 3. 修改iit tree并写回
            for (int i = 1; i < h; i++)
            {
                keyPathNode[i].inc_counter(IIT_MID_TYPE, cur_k, OF);
                new_hash_tag = keyPathNode[i].get_hash_tag(IIT_MID_TYPE, hash_key, keyPathAddr[i]);
                keyPathNode[i].embed_hash_tag(IIT_MID_TYPE, new_hash_tag);
                before_mod_cur_k /= IIT_MID_ARITY;
                cur_k = before_mod_cur_k & (IIT_MID_ARITY - 1);
            }
            for (int i = 0; i < h; i++) {
                write2Mem(sizeof(iit_Node), (uint8_t *)(&keyPathNode[i]), keyPathAddr[i]);
            }
            memcpy((uint8_t *)(&sdm_table[id].Root), (uint8_t *)(&keyPathNode[h-1]), sizeof(iit_Node));
        }
    }
}