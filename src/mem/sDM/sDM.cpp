#include "sDM.hh"
#include "sDMdef.hh"
#include "sDMglb.hh"
extern std::vector<gem5::memory::AbstractMemory *> sDMdrams;
bool sDMinitOver = false;
namespace gem5
{
    namespace sDM
    {
        std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> rpTable; // paddr -> (pid,vaddr)
        bool sDMLogo = false;
        /**
         * @brief
         * 向上取整除法
         * @author
         * yqy
         */
        inline uint64_t ceil(uint64_t a, uint64_t b)
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
        uint64_t getiiTsize(uint64_t data_size, uint32_t &h)
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
        sDMstat::sDMstat(std::string name)
        {
            _name = name;
            _totWriteCount = _totReadCount = 0;
            L1hits = 0, L2hits = 0, hits = 0;
            L1access = 0, L2access = 0, L1miss = 0, L2miss = 0;
            _dw = _dr = _dL1 = _dL2 = 0;
            _encrypt_counter = _decrypt_counter = 0;
            HotPageCachehit = HotPageCachemiss = CtrFilterHits = CtrFiltermiss = 0;
            CtrBackupHits = 0;
        }
        sDMstat::~sDMstat()
        {
        }
        void
        sDMstat::addstat(Addr addr, uint32_t byte_size, bool isRead)
        {
            if (sp_distrib.count(addr) == 0)
                sp_distrib[addr] = 1;
            else
                sp_distrib[addr]++;

            Tick ti = curTick();
            if (ti_distrib.count(ti) == 0)
                ti_distrib[ti] = 1;
            else
                ti_distrib[ti]++; // (byte_size);

            if (isRead)
                _totReadCount++;
            else
                _totWriteCount++;
        }
        uint64_t
        sDMstat::getReadCount()
        {
            return _totReadCount;
        }
        uint64_t
        sDMstat::getWriteCount()
        {
            return _totWriteCount;
        }
        void
        sDMstat::print_tot()
        {
            // 打印总体统计
            printf("\tReadCount:%ld\n\tWriteCount:%ld\n", _totReadCount, _totWriteCount);
        }
        void
        sDMstat::print_distrib()
        {
            // 打印分布情况
            // printf("\tspace distribution[Addr:Count]:\n");
            // for (auto it : sp_distrib)
            //     printf("\t\t0x%lx:%ld\n", it.first, it.second);
            // printf("\ttime distribution[Tick:Count]:\n");
            // for (auto it : ti_distrib)
            //     printf("\t\t  %ld:%ld\n", it.first, it.second);
        }
        void
        sDMstat::print_enc_dec()
        {
            // 加解密计数器
            printf("\tencrypt_counter:%ld\n\tdecrypt_counter:%ld\n\thash_counter:%ld\n",
                   _encrypt_counter, _decrypt_counter, CME::HMAC_COUNTER);
        }
        void
        sDMstat::print_cache()
        {
            printf("\tL1access:%ld\n\tL2access:%ld\n\tL1hits:%ld\n\tL2hits:%ld\n\tL1miss:%ld\n\tL2miss:%ld\n",
                   L1access, L2access,
                   L1hits, L2hits,
                   L1miss, L2miss);
        }
        void
        sDMstat::start()
        {
            _dw = _totWriteCount;
            _dr = _totReadCount;
            _dL1 = L1hits;
            _dL2 = L2hits;
            _denc = _encrypt_counter;
            _ddec = _decrypt_counter;
            _dhash = CME::HMAC_COUNTER;
        }
        void
        sDMstat::end(uint64_t &dw, uint64_t &dr, uint64_t &dL1, uint64_t &dL2, uint64_t &denc, uint64_t &ddec)
        {
            dw = _totWriteCount - _dw;
            dr = _totReadCount - _dr;
            dL1 = L1hits - _dL1;
            dL2 = L2hits - _dL2;
            denc = _encrypt_counter - _denc;
            ddec = _decrypt_counter - _ddec;
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
                                                                 local_pool_id(params.local_pool_id),
                                                                 remote_pool_id(params.remote_pool_id),
                                                                 hash_latency(params.hash_latency),
                                                                 encrypt_latency(params.encrypt_latency),
                                                                 onchip_cache_size(params.onchip_cache_size),
                                                                 onchip_cache_latency(params.onchip_cache_latency),
                                                                 dram_cache_size(params.dram_cache_size),
                                                                 remoteMemAccessLatency(params.remote_mem_latency),
                                                                 localMemAccessLatency(params.local_mem_latency)
        {
            // has_recv = false;
            // pkt_recv = NULL;
            // waitAddr = 0;
            if (!sDMLogo)
            {
                /*
                                                print("\n\
                .▄▄ · ·▄▄▄▄  • ▌ ▄ ·. • ▌ ▄ ·. \n\
                ▐█ ▀. ██▪ ██ ·██ ▐███▪·██ ▐███▪\n\
                ▄▀▀▀█▄▐█· ▐█▌▐█ ▌▐▌▐█·▐█ ▌▐▌▐█·\n\
                ▐█▄▪▐███. ██ ██ ██▌▐█▌██ ██▌▐█▌\n\
                ▀▀▀▀ ▀▀▀▀▀• ▀▀  █▪▀▀▀▀▀  █▪▀▀▀\n\n");
                */
                printf("\n\
███████╗██████╗ ███╗   ███╗███╗   ███╗\n\
██╔════╝██╔══██╗████╗ ████║████╗ ████║\n\
███████╗██║  ██║██╔████╔██║██╔████╔██║\n\
╚════██║██║  ██║██║╚██╔╝██║██║╚██╔╝██║\n\
███████║██████╔╝██║ ╚═╝ ██║██║ ╚═╝ ██║\n\
╚══════╝╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝\n\n");
                sDMLogo = true;
            }
            CME::FAST_MODE = params.fast_mode;
            CME::HMAC_COUNTER = 0;
            hash_latency = cyclesToTicks(Cycles(hash_latency));
            encrypt_latency = cyclesToTicks(Cycles(encrypt_latency));
            onchip_cache_latency = cyclesToTicks(Cycles(onchip_cache_latency));
            localMemAccessLatency = cyclesToTicks(Cycles(localMemAccessLatency));   // Ticks
            remoteMemAccessLatency = cyclesToTicks(Cycles(remoteMemAccessLatency)); // Ticks
            printf("+-----------------------------------+\n");
            printf("|     sDMmanager configuration      |\n");
            printf("+-----------------------------------+\n");
            printf("|dram_cache_size     (Bytes)=%7ld|\n", dram_cache_size * CL_SIZE);
            printf("|onchip_cache_size   (Bytes)=%7ld|\n", onchip_cache_size * CL_SIZE);
            printf("|addr_cache_size     (Bytes)=%7ld|\n", onchip_cache_size * CL_SIZE);
            printf("|hash_latency        (Cycle)=%7d|\n", params.hash_latency);
            printf("|encrypt_latency     (Cycle)=%7d|\n", params.encrypt_latency);
            printf("|onchip_cache_latency(Cycle)=%7d|\n", params.onchip_cache_latency);
            printf("|local_Mem_latency   (Cycle)=%7d|\n", params.local_mem_latency);
            printf("|remote_Mem_latency  (Cycle)=%7d|\n", params.remote_mem_latency);
            printf("+-----------------------------------+\n");
            sdm_space_cnt = 0;
            sdm_table.assign(1, sdm_space());

            KeypathCache = new sDMKeypathCache(this, onchip_cache_size, dram_cache_size,
                                        onchip_cache_latency, localMemAccessLatency, remoteMemAccessLatency);
            HotPageCache = new sDMLFUCache(this,onchip_cache_size,sDM_PAGE_SIZE>>1);
            addrCache = new sDMAddrCache(this, onchip_cache_size, _LRU, 0);
            lstat = new sDMstat("local_mem_stat");
            rstat = new sDMstat("remote_mem_stat");
        }
        sDMmanager::~sDMmanager()
        {
            summary();
            delete (KeypathCache);
            delete (lstat);
            delete (rstat);
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
            {
                read4gem5(byte_size, container, gem5_addr);
            }
            for (int i = 0; i < num; i++)
            {
                read4gem5(CL_SIZE, container + i * CL_SIZE, gem5_addr + i * CL_SIZE);
            }
            return;
        }
        /**
         * @brief:实际从gem5中读取
         */
        void sDMmanager::read4gem5(uint32_t byte_size, uint8_t *container, Addr gem5_addr)
        {
            printf("start read4mem\n");
            RequestPtr req = std::make_shared<Request>(gem5_addr, byte_size, 0, _requestorId);
            printf("start createRead\n");
            PacketPtr pkt = Packet::createRead(req);
            printf("start dataDynamic\n");
            pkt->dataDynamic(new uint8_t[byte_size]);
            pkt->setSDMRaise();
            // pkt->writeDataToBlock(container, byte_size);

            // waitAddr = gem5_addr;
            // memPort.sendTimingReq(pkt);
            // mem_ctrl发回响应packet时会自动调用recvTimingResp的函数，设置两个全局变量has_recv和pkt_recv
            // 当has_recv为true时，表示收到响应packet，在recvTimingResp函数中将收到响应pkt复制给pkt_recv
            if (sDMdrams[remote_pool_id]->getAddrRange().contains(gem5_addr))
            {
                rstat->addstat(gem5_addr, byte_size, true);
                // memcpy(container, sDMdrams[remote_pool_id]->toHostAddr(gem5_addr), byte_size);
                printf("read from remote\n");
                sDMdrams[remote_pool_id]->access(pkt);
                printf("read from remote end\n");
            }
            else
            {
                printf("read from local\n");
                assert(sDMdrams[local_pool_id]->getAddrRange().contains(gem5_addr) && "undefind addr");
                lstat->addstat(gem5_addr, byte_size, true);
                // memcpy(container, sDMdrams[local_pool_id]->toHostAddr(gem5_addr), byte_size);
                sDMdrams[local_pool_id]->access(pkt);
            }
            // waitAddr = 0;
            printf("writeDataToBlock %ld\n",pkt->getSize());
            pkt->writeDataToBlock(container, pkt->getSize());
            printf("end read4mem\n");
            delete pkt;
            return;
        }

        /**
         * @author psj
         * @brief 将连续数据写入到gem5内存中
         * @param byte_size 写入字节大小
         * @param data 数据指针
         * @param gem5_addr 写入的位置
         */
        void sDMmanager::write2gem5(uint32_t byte_size, uint8_t *data, Addr gem5_addr)
        {
            RequestPtr req = std::make_shared<Request>(gem5_addr, byte_size, 0, _requestorId);
            // PacketPtr pkt = new Packet(req, MemCmd::WritebackDirty); // why can't WriteReq?
            PacketPtr pkt = new Packet(req, MemCmd::WriteReq);
            pkt->allocate();
            pkt->setData((const uint8_t *)data);
            pkt->setSDMRaise();
            // memPort.sendTimingReq(pkt); //  packet mem[i]->gem5MemPtr->[i];...
            assert(byte_size <= CL_SIZE);
            if (sDMdrams[remote_pool_id]->getAddrRange().contains(gem5_addr))
            {
                rstat->addstat(gem5_addr, byte_size, false);
                // memcpy(sDMdrams[remote_pool_id]->toHostAddr(gem5_addr), data, byte_size);
                sDMdrams[remote_pool_id]->access(pkt);
            }
            else
            {
                assert(sDMdrams[local_pool_id]->getAddrRange().contains(gem5_addr) && "undefind addr");
                lstat->addstat(gem5_addr, byte_size, false);
                // memcpy(sDMdrams[local_pool_id]->toHostAddr(gem5_addr), data, byte_size);
                sDMdrams[local_pool_id]->access(pkt);
            }
            delete pkt;
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
            // 调用gem5物理内存分配函数直接分配,由于gem5本身没有处理不连续的地址情况,所以一定是连续的
            Addr start = mem_pools->allocPhysPages(npages, pool_id);
            if (start == POOL_EXHAUSTED) // 本地内存耗尽
                return false;
            phy_list.push_back({start, npages});
            return true;
        }
        bool
        sDMmanager::sdm_free(int pool_id, std::vector<phy_space_block> &phy_list)
        {
            // mem_pool类中没有free函数
            return true;
        }
        /**
         * @author yqy
         * @brief
         * 判断地址所在页是否处于sdm中
         * 并返回其id
         * @return
         * 返回INVALID_SPACE表示该地址所在页面不处于任何sdm中
         * 否则返回其所在sdm的id(sdmID)
         */
        sdmID sDMmanager::isContained(uint64_t pid, Addr vaddr)
        {
            vaddr &= PAGE_ALIGN_MASK;
            if (sdm_paddr2id.count(pid) == 0)
                return INVALID_SPACE;
            auto space_tb = sdm_paddr2id[pid];
            if (space_tb.size() == 0)
                return INVALID_SPACE;
            auto it = space_tb.lower_bound(vaddr);
            if (it != space_tb.end() && it->first == vaddr)
                return it->second.second;
            if (it != space_tb.begin())
                it--;
            if (it->first <= vaddr && vaddr < it->first + it->second.first)
                return it->second.second;
            return INVALID_SPACE;
        }
        /**
         * @author yqy
         * @brief 返回虚拟地址在所属sdm中的虚拟空间的相对偏移
         * @param id:所属sdm的编号(sdmID)
         * @param data_vaddr:虚拟地址
         * @return 虚拟空间的相对偏移
         */
        inline Addr sDMmanager::getVirtualOffset(sdmID id, Addr data_vaddr)
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
                read4Mem(sizeof(local_jmp), (uint8_t *)&rbound, head + sDM_PAGE_SIZE - sizeof(local_jmp));
                flag = true;
                if ((rbound.maxBound) > offset)
                    known = 1;
                else
                    known = 2;
            }
            if (known == 1) // 在连续页的范围内
            {
                if (!flag)
                    read4Mem(sizeof(local_jmp), (uint8_t *)&rbound, head + sDM_PAGE_SIZE - sizeof(local_jmp));
                // 在当前连续段内二分找出地址所在页
                int l = -1;
                int r = rbound.con;
                while (r - l > 1) // 二分第一个末数据对地址范围大于offset的本地页
                {
                    int mid = (r + l) >> 1;
                    // 读取页的最后一个数据对(本身就需要减去自身的大小),还要除去local_jmp
                    // 因此减去PAIR_SIZE+sizeof(local_jmp)
                    read4Mem(PAIR_SIZE, (uint8_t *)&rbound, head + mid * sDM_PAGE_SIZE + sDM_PAGE_SIZE - PAIR_SIZE - sizeof(local_jmp) - PAIR_SIZE); // ignore fill_num
                    if ((rboundp->pnum + rboundp->cnum) * sDM_PAGE_SIZE >= offset)
                        r = mid;
                    else
                        l = mid;
                }
                // 在第r页内二分出数据对
                head += r * sDM_PAGE_SIZE;
                //  [skip,...,sDM_PAGE_SIZE/PAIR_SIZE-1]
                // ^                                ^
                // i                                j
                l = skip - 1;
                // r = sDM_PAGE_SIZE / PAIR_SIZE; // this will raise too many useless read
                read4Mem(PAIR_SIZE, (uint8_t *)&rbound, head + sDM_PAGE_SIZE - PAIR_SIZE - sizeof(local_jmp)); // Read fill_num
                uint32_t fill_num = rboundp->cnum;
                r = l + 1 + rboundp->cnum - 1 + 1; // rewind to the last data pair
                int mid = l;
                while (r - l > 1)
                {
                    mid = (r + l) >> 1;
                    read4Mem(PAIR_SIZE, (uint8_t *)&rbound, head + (mid * PAIR_SIZE));
                    if ((rboundp->pnum + rboundp->cnum) * sDM_PAGE_SIZE > offset || // debug >= -> >
                        (rboundp->pnum == 0xffffffff && rboundp->cnum == fill_num))
                        r = mid;
                    else
                        l = mid;
                }
                // 在第r个数据对中找到所在页
                if (mid != r) // 避免重读
                    read4Mem(PAIR_SIZE, (uint8_t *)&rbound, head + (r * PAIR_SIZE));
                head = rboundp->curPageAddr;
                head += offset - rboundp->pnum * sDM_PAGE_SIZE;
                pnum = rboundp->pnum + (offset - rboundp->pnum * sDM_PAGE_SIZE) / sDM_PAGE_SIZE;
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
                while ((jmps[i].maxBound > offset) && (i > 0))
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
        int sDMmanager::getKeyPath(sdmID id, Addr rva, Addr *keyPathAddr, iit_NodePtr keyPathNode)
        {
            [[maybe_unused]]int pnum = 0; // 目标页前面有多少逻辑页
            uint32_t h = sdm_table[id].iITh;
            uint64_t nodenums = sdm_table[id].sDataSize / (IIT_LEAF_ARITY * CL_SIZE); // 叶节点数,之后表示当前层的节点数
            uint64_t offset = (rva / (CL_SIZE * IIT_LEAF_ARITY));                     // 该偏移对应哪一个叶节点，之后表示相对当前层的节点偏移量
            Addr offsetiit = offset * sizeof(iit_Node);                               // 相对于iit树第一个节点的偏移地址
            Addr lastOff = 0;                                                         // 上次查询偏移
            for (int i = 0; i < h; i++)
            {
                // 远端物理地址
                Addr NodePAddr;
                if (i && (((keyPathAddr[i - 1] + offsetiit - lastOff) & PAGE_ALIGN_MASK) == (keyPathAddr[i - 1] & PAGE_ALIGN_MASK)))
                    NodePAddr = keyPathAddr[i - 1] + offsetiit - lastOff;
                else
                {
                    // NodePAddr = find((Addr)sdm_table[id].iITPtrPagePtr, offsetiit, sdm_table[id].iit_skip, 0, pnum);
                    //  => 查找缓存 构建伪虚拟地址 pesudo_vaddr=((id<<40) | offsetiit) & page_align_mask
                    addrCache->set((Addr)sdm_table[id].iITPtrPagePtr, offsetiit, sdm_table[id].iit_skip);
                    uint64_t pseudo_vaddr = ((id << ID_OFFSET) | offsetiit) & PAGE_ALIGN_MASK;
                    NodePAddr = (addrCache->access(pseudo_vaddr)) | (offsetiit & (sDM_PAGE_SIZE - 1));
                    // if(NodePAddr != tNodePAddr)
                    //     printf("[error]");
                    // printf("iMT_ADDR_CACHE [%ld]: id=%ld, offset=0x%lx, pseudo_vaddr=0x%lx, tNodePAddr=0x%lx, *NodePAddr=0x%lx\n", curTick(), rva, offsetiit, pseudo_vaddr, tNodePAddr, NodePAddr);
                    // pnum = addrCache->pnum;// maybe useless
                } 
                keyPathAddr[i] = NodePAddr; // 目标节点的远端物理地址
                lastOff = offsetiit;        // 上个node的偏移量
                // read4Mem(sizeof(iit_Node), (u_int8_t *)(&keyPathNode[i]), NodePAddr); // 从缓存中取得
                if (i < h - 1)
                    KeypathCache->CacheAccess(NodePAddr, (uint8_t *)(keyPathNode) + sizeof(iit_Node) * i, 1);
                offsetiit += (nodenums - offset) * sizeof(iit_Node);
                nodenums = ceil(nodenums, IIT_MID_ARITY); // 下一层的节点数
                offset /= IIT_MID_ARITY;
                offsetiit += offset * sizeof(iit_Node);
            }
            memcpy((uint8_t *)(keyPathNode) + sizeof(iit_Node) * (h - 1), &sdm_table[id].Root, sizeof(iit_Node)); // Get on-chip Root
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
            if (pair_num >= 8 * ((sDM_PAGE_SIZE / PAIR_SIZE - 1) - 3))
                skip = 3; // 构建3级 step=1,2,4
            else if (pair_num >= 4 * (((sDM_PAGE_SIZE / PAIR_SIZE - 1) - 2)))
                skip = 2; // 构建2级 step=1,2
            else
                skip = 1; // 构建1级 step=1
            // 计算除去skip指针后的可用的pair数量
            pair_per = ((sDM_PAGE_SIZE / PAIR_SIZE - 1) - skip);
            pair_per--; // 保留一个数量字节,用户记录该本地页包含的数据对的数量
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
                }
                // 然后填充数据对
                int fill_num = 0;
                for (int i = 0; i < ac_num; i++)
                {
                    // 前skip的位置是skip_list的结构
                    mem[cur].pair[skip + i].curPageAddr = remote_phy_list[cur_pair].start;
                    mem[cur].pair[skip + i].cnum = remote_phy_list[cur_pair].npages;
                    mem[cur].pair[skip + i].pnum = logic_npages;
                    logic_npages += remote_phy_list[cur_pair].npages; // 累计逻辑空间大小
                    cur_pair++;
                    fill_num++;
                    if (cur_pair >= remote_phy_list.size())
                        break;
                }
                // patch避免在无效数据对上二分
                mem[cur].pair[skip + ac_num].cnum = fill_num; // 记录本地页填充的数据对数量
                mem[cur].cur_segMax.con = local_phy_list[cur_seg].npages - cur_k + 1;
                cur_k++;
                // 检查l_hmac_phy_list[cur_seg]起始的连续页是否用完
                if (cur_k <= local_phy_list[cur_seg].npages)
                {                                                          // 还有连续页,最后一个页面不可能还存在连续段,这里一定不会越界
                    ptrPagePtr[cur + 1] = ptrPagePtr[cur] + sDM_PAGE_SIZE; // 指向下一个连续的本地页
                }
                else
                {
                    mem[seg_start].cur_segMax.maxBound = logic_npages * sDM_PAGE_SIZE;
                    for (int i = seg_start + 1; i <= cur; i++)
                        mem[i].cur_segMax.maxBound = mem[seg_start].cur_segMax.maxBound;
                    // 下面的分次写入改为后面的统一写入
                    // write2Mem(PAIR_SIZE, (uint8_t *)&(mem[seg_start].cur_segMax), ptrPagePtr[seg_start] + sDM_PAGE_SIZE - PAIR_SIZE);
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
                // 下面的分次写入改为后面的统一写入
                // write2Mem(sDM_PAGE_SIZE - PAIR_SIZE - skip * sizeof(skip_jmp), (uint8_t *)&(mem[cur].pair[skip]), ptrPagePtr[cur] + sizeof(skip_jmp) * skip);
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
                // 下面的分次写入改为后面的统一写入
                // write2Mem(sizeof(skip_jmp) * skip, (uint8_t *)&mem[i], ptrPagePtr[i]); // 重写这些部分
            }
            // 分多次写入 -> 统一写入
            for (int i = 0; i < lnpages; i++)
            {
                write2Mem(sDM_PAGE_SIZE, (uint8_t *)&mem[i], ptrPagePtr[i]);
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
                // CME::sDM_Encrypt(buf, cl, sizeof(cl), paddr, ckey); // 加密数据
                encrypt(buf, cl, sizeof(cl), paddr, ckey); // 纳入统计量中
                write2Mem(CL_SIZE, buf, paddr);            // 写回内存
                memcpy(encrypteddata + i * CL_SIZE, buf, CL_SIZE);
                addr += CL_SIZE;
            }
            addr = vaddr;
            // 计算HMAC
            int hmacpageindx = 0; // 存hmac的物理页面列表的索引
            auto block = r_hmac_phy_list[hmacpageindx++];
            Addr hmacpageAddrstart = block.start;                              // 存放hmac的起始物理地址(远端)
            Addr hmacpageAddrend = block.start + sDM_PAGE_SIZE * block.npages; // 该数据对对应的结束地址
            // printf("HMAC pageAddrSet paddr=0x%lx\n", hmacpageAddrstart);
            uint8_t hmac[SM3_SIZE * 2];
            iit_Node counter = {0};
            for (int i = 0; i < byte_size / (sDM_PAGE_SIZE >> 1); i++)
            {
                // Addr hpageAddr = (addr & PAGE_ALIGN_MASK) + (addr & (sDM_PAGE_SIZE >> 1)); // 加密使用的缓存行地址 unused
                auto entry = process->pTable->lookup(addr & PAGE_ALIGN_MASK);
                assert(entry != NULL);
                Addr paddr = entry->paddr + (addr & (sDM_PAGE_SIZE >> 1));
                CME::sDM_HMAC(encrypteddata + i * (sDM_PAGE_SIZE >> 1), sDM_PAGE_SIZE >> 1, hkey, paddr, (uint8_t *)(&counter),
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
                    hmacpageAddrend = hmacpageAddrstart + block.npages * sDM_PAGE_SIZE;
                    hmacpageAddrstart += SM3_SIZE;
                }
                if ((i & 1) == 1)
                {
                    write2Mem(SM3_SIZE * 2, hmac, hmacpageAddrstart - SM3_SIZE * 2);
                }
                addr += sDM_PAGE_SIZE >> 1;
            }
            //  构建iit
            uint64_t leaf_num = byte_size / (IIT_LEAF_ARITY * CL_SIZE);
            uint64_t iitpPageindex = 0;
            block = r_iit_phy_list[iitpPageindex++];
            Addr curpPageAddrstart = block.start;
            Addr curpPageAddrend = curpPageAddrstart + block.npages * sDM_PAGE_SIZE;
            bool leaf = true;  // 是否是叶节点
            uint32_t curh = 1; // 当前层数
            iit_Node node = {0};
            // printf("iiT  pageAddrSet paddr=0x%lx\n", curpPageAddrstart);
            while (curh <= h)
            {
                uint64_t curlayernodenum = leaf_num; // 当前层结点
                int i = 0;                           // 计算缓存行索引
                Addr hpageAddr =
                    (curpPageAddrstart & PAGE_ALIGN_MASK) + (curpPageAddrstart & (sDM_PAGE_SIZE >> 1)); // 所在半页地址
                while (curlayernodenum > 0)
                {
                    i = (curpPageAddrstart - hpageAddr) / CL_SIZE; // 缓存行索引
                    uint8_t nodetype;
                    if (leaf)
                    { // 叶节点
                        nodetype = IIT_LEAF_TYPE;
                    }
                    else
                    { // 中间节点
                        nodetype = IIT_MID_TYPE;
                    }
                    node.init(nodetype, hkey, hpageAddr + i * CL_SIZE);
                    // 写入物理地址
                    if (curh != h) // 片上根可以不写入内存
                        write2Mem(sizeof(iit_Node), (uint8_t *)&node, curpPageAddrstart);
                    curpPageAddrstart += sizeof(_iit_Node);
                    if (curpPageAddrstart >= curpPageAddrend)
                    { // 页面可用空间耗尽
                        auto block = r_iit_phy_list[iitpPageindex++];
                        curpPageAddrstart = block.start;
                        curpPageAddrend = block.npages * sDM_PAGE_SIZE + curpPageAddrstart;
                    }
                    curlayernodenum--; // 当前层写完了一个节点
                }
                leaf = false;
                leaf_num = ceil(leaf_num, IIT_MID_ARITY); // 下一层的结点数
                curh++;
            }
            memcpy((uint8_t *)(&sp.Root), (uint8_t *)(&node), sizeof(iit_Node)); // 单独存储片上根
            // printf("[%ld]sDM space initialization completed\n", curTick());
            return;
        }
        /**
         * @brief 解构sDM空间
         */
        bool
        sDMmanager::sDMspace_free(uint64_t pid, Addr vaddr)
        {
            // gem5中不需要自行回收分配的内存空间
            sdmID id = isContained(pid, vaddr);
            if (id == INVALID_SPACE)
                return false;
            printf("[%ld]in sDMspace_free:\n", curTick());
            printf("\tpid=%ld\n", pid);
            printf("\tvaddr=0x%lx\n", vaddr);
            const gem5::EmulationPageTable::Entry *entry = process->pTable->lookup(vaddr);
            assert(entry && "addr is unmapped");
            printf("\tpaddr=0x%lx\n", entry->paddr);
            printf("\tsize=%ldkB\n", sdm_table[id].sDataSize / 1024);
            printf("\tspace_id=%ld\n", id);
            auto sp = sdm_table.begin();
            for (; sp != sdm_table.end(); sp++)
            {
                if (sp->id == id)
                {
                    sdm_table.erase(sp);
                    break;
                }
            }
            if (sdm_table.size() == 1)
                summary();
            return true;
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
            assert(data_byte_size && "data is empty");              // data_size is not zero
            assert(((vaddr & (sDM_PAGE_SIZE - 1)) == 0) &&          // 地址按照页面对齐
                   ((data_byte_size & (sDM_PAGE_SIZE - 1)) == 0) && // size按照页面对齐
                   "vaddr or size is not aligned pagesize");

            const gem5::EmulationPageTable::Entry *entry = process->pTable->lookup(vaddr);
            assert(entry && "vaddr is not mapped");
            // 准备新空间的metadata
            sdm_space sp;
            // 1. 计算data大小
            uint64_t data_size = data_byte_size;
            // 检查申请的虚拟空间是否已经存在于其他space中
            if (sdm_paddr2id.count(pid) != 0)
            {
                auto tb = sdm_paddr2id[pid];
                auto aft = tb.lower_bound((Addr)(vaddr + data_size));
                if (tb.size() != 0) // 第一次不用检查，一定没有重复
                {
                    if (aft != tb.begin())
                    {
                        aft--;
                        assert((aft->first + (aft->second.first) <= vaddr) && "overlapped");
                    }
                    else
                    {
                        assert((aft->first >= vaddr + data_byte_size) && "overlapped");
                    }
                }
            }
            // 2. 计算IIT树大小
            uint32_t h = 1;
            sdm_size iit_size = getiiTsize(data_size, h);
            // 3. 计算HMAC大小
            sdm_size hmac_size = data_size / SDM_HMAC_ZOOM;
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
            // 为新空间的HMAC和iit申请远端内存空间
            std::vector<phy_space_block> r_hmac_phy_list;
            std::vector<phy_space_block> r_iit_phy_list;
            // debug:hmac空间大小可能没有按照页对齐，应向上取整
            assert(sdm_malloc(ceil(hmac_size, sDM_PAGE_SIZE), remote_pool_id, r_hmac_phy_list));
            assert(sdm_malloc(ceil(iit_size, sDM_PAGE_SIZE), remote_pool_id, r_iit_phy_list));
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
            sdm_paddr2id[pid].insert(std::make_pair(vaddr, std::make_pair(data_size, sp.id)));
            printf("[%12ld]in sDMspace_register:\n\
\tpid=%ld\n\
\tvaddr=0x%lx\n\
\tpaddr=0x%lx\n\
\tsize=%ldkB\n\
\tspace_id=%ld\n\
\tiit_size =%ldB\n\
\tHMAC_size=%ldB\n\
\th=%dLayers(root included)\n",
                   curTick(), pid, vaddr, entry->paddr + (vaddr & (sDM_PAGE_SIZE - 1)), data_byte_size / 1024, sp.id,
                   iit_size, hmac_size, sp.iITh);
/*
            \tHMAC pageAddrSet paddr=0x%lx\n\
\tiMT  pageAddrSet paddr=0x%lx\n",
                               curTick(), pid, vaddr, entry->paddr + (vaddr & (sDM_PAGE_SIZE - 1)), data_byte_size / 1024, sp.id, iit_size, hmac_size, sp.iITh,
                               r_hmac_phy_list[0].start, r_iit_phy_list[0].start);
*/
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
        inline void hmac_get(uint8_t *sdata, Addr hpaddr, iit_NodePtr counter, sdm_hashKey hash_key, uint8_t *hmac)
        {
            CME::sDM_HMAC(sdata, sDM_PAGE_SIZE >> 1, hash_key, hpaddr, (uint8_t *)counter, sizeof(iit_Node), hmac, SM3_SIZE);
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
        bool sDMmanager::hmac_verify(Addr dataVAddr, Addr rva, Addr *hmacAddr, sdmID id,
                                     uint8_t *hpg_data, iit_NodePtr counters, sdm_hashKey hash_key)
        {
            const gem5::EmulationPageTable::Entry *entry = process->pTable->lookup(dataVAddr);
            assert(entry != NULL);
            Addr pageAddr = entry->paddr;
            pageAddr |= (dataVAddr & (sDM_PAGE_SIZE >> 1));
            uint8_t calc_hmac[SM3_SIZE];
            // 读取所在半页的内存数据
            // read4Mem(sDM_PAGE_SIZE >> 1, hpg_data, pageAddr);
            printf("hmac_verify Cache  %lx\n",pageAddr);
            if (!HotPageCache->CacheAccess(pageAddr, hpg_data, true)) {
                read4Mem(sDM_PAGE_SIZE >> 1, hpg_data, pageAddr);
            }
            printf("hmac_verify Cache end\n");
            //  计算HMAC
            hmac_get(hpg_data, pageAddr, counters, hash_key, calc_hmac);
            // 与存储值比较
            // [[maybe_unused]]int pnum = 0;
            uint64_t offset = (rva / (sDM_PAGE_SIZE >> 1)) * SM3_SIZE;
            // rva是数据的虚拟空间的相对偏移，需按半页转换成hmac存储空间的相对偏移
            // *hmacAddr = find((Addr)sdm_table[id].HMACPtrPagePtr, offset, sdm_table[id].hmac_skip, 0, pnum);
            // => 缓存
            addrCache->set((Addr)sdm_table[id].HMACPtrPagePtr, offset, sdm_table[id].hmac_skip);
            uint64_t pseudo_vaddr = ((id << ID_OFFSET) | (ID_HMAC_) | offset) & PAGE_ALIGN_MASK;
            *hmacAddr = (addrCache->access(pseudo_vaddr)) | (offset & (sDM_PAGE_SIZE - 1));
            // if(*hmacAddr != thmacAddr)
            //     printf("[error]");
            // printf("HMAC_ADDR_CACHE[%ld]: id=%ld, offset=0x%lx, pseudo_vaddr=0x%lx, thmacAddr=0x%lx, *hmacAddr=0x%lx\n", curTick(), rva, offset, pseudo_vaddr, thmacAddr, *hmacAddr);
            // *hmacAddr = thmacAddr;
            // pnum = addrCache->pnum; // maybe useless
            sdm_HMAC stored_hmac;
            // 从内存中读取HMAC
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
        bool sDMmanager::verify(Addr data_vaddr, uint8_t *hpg_data, sdmID id, Addr *rva, int *h,
                                Addr *keyPathAddr, iit_NodePtr keyPathNode, Addr *hmacAddr, sdm_hashKey hash_key)
        {
            iit_Node tmpLeaf;
            *rva = getVirtualOffset(id, data_vaddr);
            *h = getKeyPath(id, *rva, keyPathAddr, keyPathNode);
            // printf("get key path done\n");
            keyPathNode[0].erase_hash_tag(IIT_LEAF_TYPE, &tmpLeaf);

            // 1. HMAC校验
#ifndef SDMDEBUG
            assert(hmac_verify(data_vaddr, *rva, hmacAddr, id, hpg_data, &tmpLeaf, hash_key) && "HMAC verity failed"); // 该函数内会读取所在半页的加密数据到hpg_data[sDM_PAGE_SIZE/2]数组中
#endif
            // 2. iit校验
            int type = IIT_LEAF_TYPE;
            // paddr对应的缓存行位于上层节点的哪个计数器
            uint32_t whichnode = (*rva) / (IIT_LEAF_ARITY * CL_SIZE);
            uint32_t next_k = whichnode & (IIT_MID_ARITY - 1); // % IIT_LEAF_ARITY

            // 用于存放当前节点和父节点的major-minor计数器
            CL_Counter cl, f_cl;
            bool verified = true;
            for (int i = 0; i < (*h - 1) && verified; i++)
            {
                // if (i < *h - 1) // sum check
                // {
                keyPathNode[i].sum(type, cl);
                // 取出父计数器
                keyPathNode[i + 1].getCounter_k(IIT_MID_TYPE, next_k, f_cl);
                // 比较父计数器是否与当前计数器相等
                verified = counter_cmp(cl, f_cl);
                assert(verified && "counter sum check failed");
                // }
                iit_hash_tag hash_tag = keyPathNode[i].abstract_hash_tag(type);
                iit_hash_tag chash_tag = keyPathNode[i].get_hash_tag(type, hash_key, keyPathAddr[i]);
                // 比较计算值和存储值
#ifndef SDMDEBUG
                assert(hash_tag == chash_tag && "hashtag check failed");
#endif
                // 后续节点都是mid类型
                type = IIT_MID_TYPE;
                whichnode /= IIT_MID_ARITY;
                next_k = whichnode & (IIT_MID_ARITY - 1); //% IIT_MID_ARITY
            }
            // if (verified) // root check
            // {
            //     verified = (memcmp((uint8_t *)(&sdm_table[id].Root), (uint8_t *)(&keyPathNode[*h - 1]), sizeof(iit_Node)) == 0);
            //     if (!verified)
            //     {
            //         sDMdump((char *)"onChip root:", (uint8_t *)(&sdm_table[id].Root), sizeof(iit_Node));
            //         sDMdump((char *)"offChip root:", (uint8_t *)(&keyPathNode[*h - 1]), sizeof(iit_Node));
            //     }
            //     assert(verified && "iiT Root verify failed");
            // }
            // printf("iit verify done\n");
            return verified;
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
        void sDMmanager::read(uint64_t pid, PacketPtr pkt, uint8_t *algined_mem_ptr, Addr pkt_vaddr)
        {
            // if (pkt->requestorId() == requestorId()) // 不应该检查sDMmanager的请求,但目前无法pass其他process中sDMmanager的请求
            // return;
            Addr pktAddr = pkt_vaddr;
            sdmID id = sDMmanager::isContained(pid, pktAddr);
            if (id == 0) // 该物理地址不包含在任何sdm中,无需对数据包做修改
                return;
            // 开启统计
            // printf("start timer read[0x%lx:0x%lx]\n",pkt->getAddr(),pkt->getAddr()+pkt->getSize()-1);
            lstat->start();
            rstat->start();
            // 这个assert转移到上层函数abstract_mem.cc的access函数中检查
            // assert((pkt->getSize() == CL_SIZE) && "read:packet size isn't aligned with cache line");
            Addr rva;
            int h;
            Addr keyPathAddr[MAX_HEIGHT] = {0};
            iit_Node keyPathNode[MAX_HEIGHT] = {0};
            sdm_hashKey hash_key;
            sdm_table[id].key_get(HASH_KEY_TYPE, hash_key);
            Addr hmacAddr;                        // hmac在远端的物理地址
            uint8_t hpg_data[sDM_PAGE_SIZE >> 1]; // 在函数verify调用的hmac-verify函数中会读取所在的半页密态内存,需要在verify的调用者中准备存储空间
            // 注意这里验证使用了虚拟地址
            bool verified = verify(pktAddr, hpg_data, id, &rva, &h, keyPathAddr, keyPathNode, &hmacAddr, hash_key);
#ifndef SDMDEBUG
            assert(verified && "verify failed before read");
#endif
            CL_Counter cl;
            keyPathNode[0].getCounter_k(IIT_LEAF_TYPE, (rva & ((sDM_PAGE_SIZE >> 1) - 1)) / CL_SIZE, cl);
            sdm_CMEKey cme_key;
            sdm_table[id].key_get(CME_KEY_TYPE, cme_key);
            // 解密Packet中的数据,并修改其中的数据
            // 注意这里解密也暂时先使用了虚拟地址
            Addr paddr;
            const gem5::EmulationPageTable::Entry *entry = process->pTable->lookup(pktAddr);
            assert(entry && "paddr is valid");
            paddr = entry->paddr + (pktAddr & (~PAGE_ALIGN_MASK) & (CL_ALIGN_MASK));
            // CME::sDM_Decrypt(algined_mem_ptr, (uint8_t *)&cl, sizeof(CL_Counter), paddr, cme_key);
            decrypt(algined_mem_ptr, (uint8_t *)&cl, sizeof(CL_Counter), paddr, cme_key); // 纳入统计量
            // char cmd[256] = {0};
            // sprintf(cmd, "[%ld]sdm  read(%lx)", curTick(), pkt->getAddr());
            // CME::CMEdump(cmd, algined_mem_ptr, CL_SIZE);
            pkt->payloadDelay += delay();
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
        sDMmanager::write(uint64_t pid, PacketPtr pkt, uint8_t *aligned_mem_ptr, Addr pktVAddr)
        {
            // assert(pktVAddr % CL_SIZE == 0 && "write:packet address isn't aligned with cache line"); // 要求给出的缓存行地址必定对齐
            sdmID id = isContained(pid, pktVAddr);
            if (id == 0) // 无需修改任何数据包
                return;
            // 开启统计
            lstat->start();
            rstat->start();
            Addr rva; // 该地址在所属空间中的相对偏移
            int h;
            Addr keyPathAddr[MAX_HEIGHT] = {0};
            iit_Node keyPathNode[MAX_HEIGHT] = {0};
            sdm_hashKey hash_key;
            sdm_table[id].key_get(HASH_KEY_TYPE, hash_key);
            Addr hmacAddr;                              // 对应的hmac在远端的物理地址
            uint8_t hpg_data[sDM_PAGE_SIZE >> 1] = {0}; // 在函数verify调用的hmac-verify函数中会读取所在的半页密态内存,需要在verify的调用者中准备存储空间
            bool verified = verify(pktVAddr, hpg_data, id, &rva, &h, keyPathAddr, keyPathNode, &hmacAddr, hash_key);
#ifndef SDMDEBUG
            assert(verified && "verify failed before write");
#endif
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
            Addr hPageAddr = (pktVAddr & PAGE_ALIGN_MASK) | (pktVAddr & (sDM_PAGE_SIZE >> 1)); // 半页对齐地址
            CL_Counter cl;
            int off = (pktVAddr - hPageAddr) / CL_SIZE;   // 对应所在半页中的第几个计数器/缓存行
            uint8_t off_in_cl = pkt->getAddr() % CL_SIZE; // 对应缓存行中的偏移
            const gem5::EmulationPageTable::Entry *entry = process->pTable->lookup(hPageAddr);
            assert(entry && "paddr is valid");
            Addr hpaddr = entry->paddr + (hPageAddr & (sDM_PAGE_SIZE >> 1));
            Addr clpaddr = entry->paddr + (pktVAddr & (~PAGE_ALIGN_MASK));
            if (OF) // 引发重加密所在半页
            {
                // 可以提前取得所在半页的数据(已在hpg_data中取得),其后的HMAC计算是必须的,提高并行度
                for (int i = 0; i < (sDM_PAGE_SIZE >> 1) / CL_SIZE; i++) // 先解密得到原数据
                {
                    bkeyPathNode[0].getCounter_k(IIT_LEAF_TYPE, i, cl); // 取得该cl的旧counter
                    // CME::sDM_Decrypt(hpg_data + i * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter), hpaddr + i * CL_SIZE, cme_key);
                    decrypt(hpg_data + i * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter), hpaddr + i * CL_SIZE, cme_key);
                }
                // 更新为写入后的数据
                pkt->writeData(hpg_data + off * CL_SIZE + off_in_cl);
                // 使用新的counter加密
                for (int i = 0; i < (sDM_PAGE_SIZE >> 1) / CL_SIZE; i++)
                {
                    keyPathNode[0].getCounter_k(IIT_LEAF_TYPE, i, cl);
                    // CME::sDM_Encrypt(hpg_data + i * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter), hpaddr + i * CL_SIZE, cme_key);
                    encrypt(hpg_data + i * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter),
                            hpaddr + i * CL_SIZE, cme_key);
                    // 将重新加密好的cacheLine写回到内存
                    if (hpaddr + i * CL_SIZE == clpaddr) // 是本次写操作的地址则直接放在aligned_mem_ptr
                        memcpy(aligned_mem_ptr, hpg_data + i * CL_SIZE, CL_SIZE);
                    // else // 否则需要发起新的写请求
                    //     write2Mem(CL_SIZE, hpg_data + i * CL_SIZE, hpaddr + i * CL_SIZE);
                    HotPageCache->hPageinAccess(hpaddr + i * CL_SIZE, hpg_data + i * CL_SIZE, CL_SIZE, 0);
                }
            }
            else
            {
                bkeyPathNode[0].getCounter_k(IIT_LEAF_TYPE, off, cl); // 取得该cl的旧counter
                // 解密对应缓存行
                // CME::sDM_Decrypt(hpg_data + off * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter), hpaddr + off * CL_SIZE, cme_key);
                decrypt(hpg_data + off * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter), hpaddr + off * CL_SIZE, cme_key);

                // 更新写入的数据部分,pkt可能不按CL_SIZE对齐
                pkt->writeData(hpg_data + off * CL_SIZE + off_in_cl);
                // 取得新的counter
                keyPathNode[0].getCounter_k(IIT_LEAF_TYPE, off, cl);

                // 重新加密
                // CME::sDM_Encrypt(hpg_data + off * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter), clpaddr, cme_key);
                encrypt(hpg_data + off * CL_SIZE, (uint8_t *)&cl, sizeof(CL_Counter), clpaddr, cme_key);
                // 将重新加密好的cacheLine写回到内存
                // 已经在abstract_mem中对齐，现在写入到aligned_mem_ptr即可
                // memcpy(aligned_mem_ptr, hpg_data + off * CL_SIZE, CL_SIZE);
                HotPageCache->hPageinAccess(clpaddr, hpg_data + off * CL_SIZE,CL_SIZE,0);
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
                if(i < h-1) // Root do not need any hash tag
                {
                    new_hash_tag = keyPathNode[i].get_hash_tag(IIT_MID_TYPE, hash_key, keyPathAddr[i]);
                    keyPathNode[i].embed_hash_tag(IIT_MID_TYPE, new_hash_tag);
                }
                before_mod_cur_k /= IIT_MID_ARITY;
                cur_k = before_mod_cur_k & (IIT_MID_ARITY - 1);
            }
            for (int i = 0; i < h - 1; i++) // 不用将root写入内存
            {
                // write2Mem(sizeof(iit_Node), (uint8_t *)(&keyPathNode[i]), keyPathAddr[i]);
                KeypathCache->CacheAccess(keyPathAddr[i], (uint8_t *)(&keyPathNode[i]), 0);
            }
            memcpy((uint8_t *)(&sdm_table[id].Root), (uint8_t *)(&keyPathNode[h - 1]), sizeof(iit_Node)); // 将root更新回片上
            // char cmd[256] = {0};
            // sprintf(cmd, "[%ld]sdm write(%lx)", curTick(), pkt->getAddr());
            // CME::CMEdump(cmd, aligned_mem_ptr, CL_SIZE);
            pkt->payloadDelay += delay();
        }

        /**
         * @author ys
         * @brief 写入一个Cache缓存行
         * @param newNodeaddr 新缓存行对应的地址，方便根据地址快速查找到对应的缓存行
         * @param databuf 写入的数据
         * @param retbuf 如果发生驱逐，返回驱逐出的缓存行信息
         * retbuf
         * |---------------------|-----|
         * |<-        64       ->|<-8->|总共72字节
         * @return 是否完成写入
         */
        bool sDMmanager::sDMLRUCache::Write2Cache(Addr newNodeaddr, uint8_t *databuf, uint8_t *retbuf)
         {
            DLinkedNode* newNode = new DLinkedNode();
            newNode->NodeAddr = newNodeaddr;
            memcpy(newNode->value, databuf, Cachelinesize);
            if (keypathcache.count(newNodeaddr) == 0) {
                if (CacheID == 1)
                {
                    sDMmanagerptr->lstat->L1miss++;
                }
                else if (CacheID == 2)
                {
                    sDMmanagerptr->lstat->L2miss++;
                }
                ++count;
            }
            else {
                if (CacheID == 1)
                {
                    sDMmanagerptr->lstat->L1hits++;
                }
                else
                {
                    sDMmanagerptr->lstat->L2hits++;
                }
                removeNode(keypathcache[newNodeaddr]);
                free(keypathcache[newNodeaddr]);
            }
            keypathcache[newNodeaddr] = newNode;
            addNode(newNode);

            if (count > capacity)
            {
                // evict
                // pop the tail
                Evict(retbuf);
                --count;

                return true;
            }
            return false;
        }

       /**
         * @brief
         * @param key
         * @param value
         * @param isread 1是读，0是写
         * @return
        */
        int sDMmanager::sDMLRUCache::access(Addr key, uint8_t* value, bool isread)
        {
            if (keypathcache.count(key) > 0)
            { // hit
                DLinkedNode* NewNode = keypathcache[key];
                if (isread) {
                    memcpy(value, NewNode->value, Cachelinesize);  //读出数据
                }
                else {
                    memcpy(NewNode->value, value, Cachelinesize);  //产生新的节点
                }
                if (CacheID == 1)
                {
                    sDMmanagerptr->lstat->L1hits++;
                }
                else
                {
                    sDMmanagerptr->lstat->L2hits++;
                }
                sDMmanagerptr->lstat->hits++;
                keypathcache[key] = NewNode;
                removeNode(NewNode);
                addNode(NewNode);
                /*printf("hit L%dCache\n",capacity==4?1:2);*/
                return true; // 命中
            }
            if (CacheID == 1)
            {
                sDMmanagerptr->lstat->L1miss++;
            }
            else
            {
                sDMmanagerptr->lstat->L2miss++;
            }
            return false; // 未命中
        }

        sDMmanager::sDMKeypathCache::~sDMKeypathCache()
        {
            delete (L1Cache);
            delete (L2Cache);

            // 此时应该把L1和L2中的数据全部回写到内存（远端内存）中
        }
        void sDMmanager::AccessMemory(Addr addr, uint8_t *databuf, bool isread = 1, uint8_t datasize = 64)
        {
            if (isread)
            {
                read4Mem(datasize, databuf, addr);
            }
            else
            {
                write2Mem(datasize, databuf, addr);
            }
        }
        /**
         * @brief
         * @param Nodeaddr 远端内存完整性树节点的物理地址
         * @param databuf 读出或写入的buf，大小为64B，一个Cache line
         * @param isread 此次Cache访问是读操作还是写操作？
         * @return
         */
        Tick sDMmanager::sDMKeypathCache::CacheAccess(Addr Nodeaddr, uint8_t *databuf, bool isread)
        {
            Tick totalTick = 0;
            int timestoL1Cache = 0, timestoL2Cache = 0, timestoremoteMemory = 0;
            timestoL1Cache++; // 访问L1cache
            if (L1Cache->access(Nodeaddr, databuf, isread))
            {
                // L1Cache hit
            }
            else
            {
                // L1Cache miss
                timestoL2Cache++; // 访问L2Cache
                if (L2Cache->access(Nodeaddr, databuf, isread))
                {
                    // L2Cache hit
                    // write to L1cache
                    uint8_t *evictfromL1Cache = (uint8_t *)malloc(64 + 8);
                    timestoL1Cache++; // 写入L1Cache的开销
                    if (L1Cache->Write2Cache(Nodeaddr, databuf, evictfromL1Cache))
                    {
                        // L1Cache 发生驱逐
                        Addr evictNodeAddr = *((Addr *)(evictfromL1Cache + 64));
                        uint8_t *evictfromL2Cache = (uint8_t *)malloc(sizeof(uint8_t) * (64 + 8));
                        timestoL2Cache++; // 写入L2Cache的开销
                        if (L2Cache->Write2Cache(evictNodeAddr, evictfromL1Cache, evictfromL2Cache))
                        {
                            // L2Cache 驱逐
                            // 写入内存的开销
                            evictNodeAddr = *((Addr *)(evictfromL2Cache + 64));
                            sDMmanagerptr->AccessMemory(evictNodeAddr, evictfromL2Cache, 0);
                            timestoremoteMemory++;
                        }
                        free(evictfromL2Cache);
                    }
                    free(evictfromL1Cache);
                }
                else
                {
                    // L2Cache miss
                    //  read4mem
                    sDMmanagerptr->AccessMemory(Nodeaddr, databuf, isread);
                    timestoremoteMemory++; // 内存访问

                    // 不缓存到L2Cache，仅缓存到L1Cache
                    uint8_t *evictfromL1Cache = (uint8_t *)malloc(sizeof(uint8_t) * (64 + 8));
                    timestoL1Cache++; // 写回L1Cache
                    if (L1Cache->Write2Cache(Nodeaddr, databuf, evictfromL1Cache))
                    { // L1Cache驱逐
                        Addr evictNodeAddr = *((Addr *)(evictfromL1Cache + 64));
                        uint8_t *evictfromL2CachetoMemory = (uint8_t *)malloc(sizeof(uint8_t) * (64 + 8));
                        timestoL2Cache++; // L2Cache访问
                        if (L2Cache->Write2Cache(evictNodeAddr, evictfromL1Cache, evictfromL2CachetoMemory))
                        {
                            evictNodeAddr = *((Addr *)(evictfromL2CachetoMemory + 64));
                            sDMmanagerptr->AccessMemory(evictNodeAddr, evictfromL2CachetoMemory, 0);
                            timestoremoteMemory++; // 内存访问
                        }
                        free(evictfromL2CachetoMemory);
                    }
                    free(evictfromL1Cache);
                }
            }
            // printf("L1Cache %d,L2Cache %d,Memory %d\n",timestoL1Cache,timestoL2Cache,timestoremoteMemory );
            totalTick = timestoL1Cache * L1Cache->latency + timestoL2Cache * L2Cache->latency + timestoremoteMemory * RemoteMemAccessLatency;
            sDMmanagerptr->lstat->L1access += timestoL1Cache;
            sDMmanagerptr->lstat->L2access += timestoL2Cache;
            return totalTick;
        }
        /**
         * @brief 开启统计量的统计
         */
        void sDMmanager::timer()
        {
            lstat->start();
            rstat->start();
        }
        /**
         * @brief 根据统计量计算时延
         * @attention 计算公式: L1hits * onchip_cache_latency()
         *
         */
        uint64_t
        sDMmanager::formula(uint64_t local_dL1, uint64_t local_dL2, uint64_t local_acc, uint64_t remote_acc, uint64_t enc_dec, uint64_t dhash)
        {
            uint64_t latency = KeypathCache->L1Cache->latency * local_dL1 + KeypathCache->L2Cache->latency * local_dL2 + // 本地命中
                               localMemAccessLatency * (local_acc) +
                               remoteMemAccessLatency * (remote_acc) +
                               encrypt_latency * (enc_dec) + hash_latency * (dhash);
            return latency;
        }
        uint64_t sDMmanager::delay()
        {
            uint64_t local_dw, local_dr, local_dL1, local_dL2, local_denc, local_ddec;
            uint64_t remote_dw, remote_dr, remote_dL1, remote_dL2, remote_denc, remote_ddec;
            uint64_t dhash = CME::HMAC_COUNTER - lstat->_dhash;
            // 获取访存与访缓存次数
            lstat->end(local_dw, local_dr, local_dL1, local_dL2, local_denc, local_ddec);
            rstat->end(remote_dw, remote_dr, remote_dL1, remote_dL2, remote_denc, remote_ddec);
            // 计算延迟
            uint64_t latency = formula(local_dL1, local_dL2, (local_dw + local_dr), (remote_dw + remote_dr), (local_denc + local_ddec), dhash);
            // KeypathCache->L1Cache->latency * local_dL1 + KeypathCache->L2Cache->latency * local_dL2 + // 本地命中
            //                    localMemAccessLatency * (local_dw + local_dr) +
            //                    remoteMemAccessLatency * (remote_dw + remote_dr) +
            //                    encrypt_latency * (local_denc + local_ddec) + hash_latency * dhash;
            // printf("extra latency:%ld {rAcc:%ld lAcc:%ld enc_dec:%ld hash:%ld L1:%ld L2:%ld}\n",
            //         latency,
            //         remote_dw + remote_dr,
            //         local_dw + local_dr,
            //         local_denc + local_ddec,
            //         dhash,
            //         local_dL1,
            //         local_dL2);
            return latency;
        }
        void sDMmanager::decrypt(uint8_t *cipher, uint8_t *counter, int counterLen, sDM::Addr paddr2CL, uint8_t *key2EncryptionCL)
        {
            lstat->_decrypt_counter++;
            CME::sDM_Decrypt(cipher, counter, counterLen, paddr2CL, key2EncryptionCL);
        }
        void sDMmanager::encrypt(uint8_t *plaint, uint8_t *counter, int counterLen, sDM::Addr paddr2CL, uint8_t *key2EncryptionCL)
        {
            lstat->_encrypt_counter++;
            CME::sDM_Encrypt(plaint, counter, counterLen, paddr2CL, key2EncryptionCL);
        }
        void sDMmanager::summary()
        {

            uint64_t tot = 0;
            // tot = formula(lstat->L1hits,
            //               lstat->L2hits,
            //               lstat->getReadCount() + lstat->getWriteCount(),
            //               rstat->getReadCount() + rstat->getWriteCount(),
            //               lstat->_encrypt_counter + lstat->_decrypt_counter,
            //               CME::HMAC_COUNTER) / 1000;
            uint64_t L1 = lstat->L1hits * KeypathCache->L1Cache->latency / 1000;
            uint64_t L2 = lstat->L2hits * KeypathCache->L2Cache->latency / 1000;
            uint64_t addrCacheLat = (addrCache->_hits + addrCache->_miss) * addrCache->_tag_latency + addrCache->_hits * onchip_cache_latency / 1000;
            uint64_t local = (lstat->getReadCount() + lstat->getWriteCount()) * localMemAccessLatency / 1000;
            uint64_t remote = (rstat->getReadCount() + rstat->getWriteCount()) * localMemAccessLatency / 1000;
            uint64_t enc_dec = (lstat->_encrypt_counter + lstat->_decrypt_counter) * encrypt_latency / 1000;
            uint64_t hash = (CME::HMAC_COUNTER)*hash_latency / 1000;
            tot = L1 + L2 + addrCacheLat + local + remote + enc_dec + hash;

            printf("\n+------------------------------------+\n");
            printf("|              Summary               |\n");
            printf("+------------------------------------+\n");
            printf("|Total Latency:%13ld (Cycles)|\n", tot);
            printf("|Total L1Latency:%11ld (Cylces)|  P:%3.4lf%%\n", L1, (double)L1 / (double)tot * 100.0);
            printf("|Total AddrCache:%11ld (Cylces)|  P:%3.4lf%%\n", addrCacheLat, (double)addrCacheLat / (double)tot * 100.0);
            printf("|Total L2Latency:%11ld (Cylces)|  P:%3.4lf%%\n", L2, (double)L2 / (double)tot * 100.0);
            printf("|Total lMemAccLat:%10ld (Cylces)|  P:%3.4lf%%\n", local, (double)local / (double)tot * 100.0);
            printf("|Total rMemAccLat:%10ld (Cylces)|  P:%3.4lf%%\n", remote, (double)remote / (double)tot * 100.0);
            printf("|Total enc_decLat:%10ld (Cylces)|  P:%3.4lf%%\n", enc_dec, (double)enc_dec / (double)tot * 100.0);
            printf("|Total hashLat:%13ld (Cylces)|  P:%3.4lf%%\n", hash, (double)hash / (double)tot * 100.0);
            printf("+------------------------------------+\n");
            if((double)(addrCache->_hits + addrCache->_miss) != 0)
                printf("|AddrTrans hitRates:%6.4lf(%%)      |\n", (double)addrCache->_hits / (double)(addrCache->_hits + addrCache->_miss) * 100.0);
            else 
                printf("|AddrTrans hitRates:--(%%)          |\n");
            printf("+------------------------------------+\n\n");
            printf("+------------------------------------+\n");
            printf("|              Details               |\n");
            printf("+------------------------------------+\n");
            printf("# remote memory:\n");
            rstat->print_tot();
            printf("# local memory:\n");
            lstat->print_tot();
            printf("# cache:\n");
            lstat->print_cache();
            printf("# addr cache:\n");
            addrCache->print_cache();
            printf("# encrypt and decrypt:\n");
            lstat->print_enc_dec();
        }

        /**
         * @brief 将node插入到ctr链
         * @param Nodeaddr 缓存行对应的虚拟地址
         * @param ctr 缓存行对应的计数器
         * @param isinLink 是否是一个Link里的节点，还是新创建的节点
         * @return
        */
        bool sDMmanager::sDMLFUCache::Insert2Ctrlink(Addr key, CtrLinkNode* Node, uint64_t ctr, uint8_t* retbuf, bool isinLink = 1) {
            bool ret = false;
			++count;
            if (isinLink) {
                //调整原来的链
                --count;
                Node->Next->Pre = Node->Pre;
                Node->Pre->Next = Node->Next;
                uint64_t oldctr = KeytoFreq[key];
                if (FreqtoCtrLink[oldctr]->head->Next == FreqtoCtrLink[oldctr]->tail) {
                    //旧链为空链，回收
                    RecoverCtrLink(oldctr);
                    minFreq.erase(oldctr);
                }
            }
            else {
                KeytoCtrLinkNode[key] = Node;
            }
			if (count > capacity) {
				--count;
				Evict(retbuf);
				ret = true;
			}
            //插入到ctr对应链的链尾
            if (FreqtoCtrLink.count(ctr) == 0) {
                // 不存在这个链，从初始化时创建的备用链表中选择一个,创建对应链。
                auto newCtrLinkptr = CtrLinks.front();
                CtrLinks.pop();
                FreqtoCtrLink[ctr] = newCtrLinkptr;
                minFreq.insert(ctr);
            }
            // 存在则直接插入
            auto tail = FreqtoCtrLink[ctr]->tail;
            Node->Next = tail;
            Node->Pre = tail->Pre;
            tail->Pre->Next = Node;
            tail->Pre = Node;

            KeytoFreq[key] = ctr;
            return ret;
        }

        /**
         * @brief Cache访问API
         * @param key 数据地址
         * @param value 数据buf
         * @param retbuf 如果有被驱逐的数据，存放在retbuf中。结构：
         * |---------2048-----------|---8---|--8--|  需要预先分配2048+8+8=2064个字节的数据缓冲区
         * |<-  被驱逐的半页数据  ->|-haddr-|-ctr-|
         * @param Pagectr 被访问页的计数器
         * @param isread 读数据还是写数据
         * @return 返回true表示命中
         */
		bool sDMmanager::sDMLFUCache::CacheAccess(Addr key, uint8_t* value, bool isread) {
			uint8_t* retbuf = (uint8_t*)malloc(sizeof(uint8_t) * (2048 + 8 + 8));
            bool ret = false;
            bool hasevictHotPage = false;
            printf("key %lx %d\n",key,isread);
            if (KeytoCtrLinkNode.count(key) > 0)
            {
                //内存缓存 hit
                printf("hit\n");
                if (isread)
                {
                    memcpy(value, KeytoCtrLinkNode[key]->CacheLineAddr, CacheLinesize);
                }
                else {
					memcpy(KeytoCtrLinkNode[key]->CacheLineAddr, value, CacheLinesize);
				}
				uint64_t ctr = KeytoFreq[key];
				CtrLinkNode* Node = KeytoCtrLinkNode[key];
				Insert2Ctrlink(key, Node, ctr + 1, retbuf, 1);  //从原来的链表中摘除，插入到ctr+1的那条链中

				ret = true;
            }
            else {
				//miss
                printf("miss\n");
                ret = false;
                uint64_t curHpagectr = 0;
				if (CtrFilter->access(key, (uint8_t*)(&curHpagectr), 1)) {
					// 不在缓存中，但是在过滤器中，判断是否为热页面
					curHpagectr++;
					if (curHpagectr > Threshold) {
						//识别为热页面，加入缓存
						CtrLinkNode* newCtrLinkNode = (CtrLinkNode*)malloc(sizeof(CtrLinkNode));
						newCtrLinkNode->CacheLineAddr = (uint8_t*)malloc(sizeof(uint8_t) * CacheLinesize);
						newCtrLinkNode->hpageaddr = key;
						// read from remote mem
                        printf("read from remote key %lx %lp \n",key,newCtrLinkNode->CacheLineAddr);
                        sDMmanagerptr->read4Mem(CacheLinesize, value, key);
                        printf("read4mem remote end\n");
                        if (isread)
						{
							memcpy(value, newCtrLinkNode->CacheLineAddr, CacheLinesize);
						}
						else {
							memcpy(newCtrLinkNode->CacheLineAddr, value, CacheLinesize);
						}
                        // 新插入的计数器先初始化为0
                        hasevictHotPage = Insert2Ctrlink(key, newCtrLinkNode, 0, retbuf, 0);  //一定不在链中
						uint8_t* CtrFilterrebuf = (uint8_t*)malloc(sizeof(uint8_t) * (CtrFilter->getCacheLinesize() + 8));
						//从计数器过滤器中逐出
                        CtrFilter->Evict(CtrFilterrebuf);
                        free(CtrFilterrebuf);
                        ret = true;
					}
					else {
						//写入增加后的计数器
						CtrFilter->access(key, (uint8_t*)(&curHpagectr), 0);
					}
				}
				else {
					// 计数器不在计数器过滤器中，加入过滤器，ctr初始化为1
					uint64_t InitCtr = 1;
					uint8_t* CtrFilterretbuf = (uint8_t*)malloc(sizeof(uint8_t) * (CtrFilter->getCacheLinesize() + 8));
					if (CtrBackup.count(key) > 0) {
						//先查看计数器备份
						InitCtr = CtrBackup[key];
						CtrBackup.erase(key);   // 剔除备份，加入过滤器
						deletebackup(key);
					}
					//加入过滤器
					if (CtrFilter->Write2Cache(key, (uint8_t*)(&InitCtr), (uint8_t*)(CtrFilterretbuf))) {
						//过滤器逐出，加入备份
						uint64_t oldctr = *(Addr*)(CtrFilterretbuf);
						CtrBackup.insert(std::pair<Addr, uint64_t>(key, oldctr));
						LifeTimeCtr.push_back(key);
						if (CtrBackup.size() > CtrBackupsize) {
							Addr oldkey = LifeTimeCtr.front();
							LifeTimeCtr.erase(LifeTimeCtr.begin());
							CtrBackup.erase(oldkey);
						}

					}
					free(CtrFilterretbuf);
				}

				if (hasevictHotPage) {
					// 新加入热页面后，热页面缓存溢出，需要把替换出的热页面对应的计数器加入过滤器中

					Addr hPageaddr = *(uint64_t*)(retbuf + 2048);
					uint64_t ctr = *(uint64_t*)(retbuf + 2048 + 8);
					ctr = Threshold / 2;
					uint8_t* ctrfilterretbuf = (uint8_t*)malloc(sizeof(char) * 64);
					uint8_t* databuf = (uint8_t*)malloc(sizeof(char) * CtrFilter->getCacheLinesize());
					memcpy(databuf, (uint8_t*)(&ctr), sizeof(uint64_t));
					bool ctrfilterret = CtrFilter->Write2Cache(hPageaddr, databuf, ctrfilterretbuf);
					if (ctrfilterret) {
						// 写入内存计数器备份区
						CtrBackup.insert(std::pair<Addr, uint64_t>(hPageaddr, ctr));
						LifeTimeCtr.push_back(hPageaddr);
						if (CtrBackup.size() > CtrBackupsize) {
							Addr oldkey = LifeTimeCtr.front();
							LifeTimeCtr.erase(LifeTimeCtr.begin());
							CtrBackup.erase(oldkey);
						}
					}
					// 写入远端内存
					sDMmanagerptr->write2Mem(sDM_PAGE_SIZE >> 1, retbuf, hPageaddr);
					free(databuf);
					free(ctrfilterretbuf);
				}
			}
			free(retbuf);
			return ret;
		}

        /**
		 * @brief 访问内存大小小于半页
		 * @param addr 
		 * @param value 
		 * @param bytesize 
		 * @param isread 
		*/
        void sDMmanager::sDMLFUCache::hPageinAccess(Addr addr, uint8_t* value, uint64_t bytesize, bool isread)
		{
			// 地址按半页对齐。
			Addr hPageaddr = (addr & PAGE_ALIGN_MASK) | (addr & (sDM_PAGE_SIZE >> 1));
			uint8_t* hPagedata = (uint8_t*)malloc(sizeof(uint8_t) * (sDM_PAGE_SIZE >> 1));

			if (!CacheAccess(hPageaddr, hPagedata, true)) {
				// 从远端读
				if (isread) {
					sDMmanagerptr->read4Mem(bytesize, value, addr);
				}
				else {
					sDMmanagerptr->write2Mem(bytesize, value, addr);
				}
			}
			else
			{
                // 命中缓存
				if (isread)
				{
					memcpy(value, hPagedata + (addr - hPageaddr), bytesize);
				}
				else
				{
					memcpy(hPagedata + (addr-hPageaddr), value, bytesize);
					CacheAccess(hPageaddr, hPagedata, isread);// 新数据写进缓存
				}
			}
            free(hPagedata);
		}

        /**
         * @brief 驱逐计数器为ctr的最旧的缓存行
         * @param retbuf 缓存行里的数据
         * @param ctr
         * @return
         */
         bool sDMmanager::sDMLFUCache::Evict(uint8_t* retbuf) {

            uint64_t ctr = *(minFreq.begin());  //最小值
            CtrLinkNode *oldNode;
            if (FreqtoCtrLink.count(ctr) == 0) {
                printf("Evict an Invalid Ctr");
                return false;
            }
            oldNode = FreqtoCtrLink[ctr]->head->Next;
            auto Addr = oldNode->hpageaddr;
            oldNode->Next->Pre = FreqtoCtrLink[ctr]->head;
            FreqtoCtrLink[ctr]->head->Next = oldNode->Next;
            memcpy(retbuf, oldNode->CacheLineAddr, CacheLinesize);  //保存旧数据
            memcpy(retbuf + 2048, &(oldNode->hpageaddr), sizeof(uint64_t)); // 保存被驱逐时的缓存行对应的半页地址
            memcpy(retbuf + 2048 + 8, (uint8_t*)(&ctr), sizeof(uint64_t)); //保存被驱逐时的计数器

            KeytoCtrLinkNode.erase(Addr);
            KeytoFreq.erase(Addr);
            free(oldNode->CacheLineAddr);
            free(oldNode);
            //维护最小堆
            if (FreqtoCtrLink[ctr]->head->Next == FreqtoCtrLink[ctr]->tail) {
                //回收该ctr链
                RecoverCtrLink(ctr);
                minFreq.erase(ctr);  // 删除最小值
            }

            return true;
        }
        sDMmanager::sDMLFUCache::~sDMLFUCache()
        {
            for (auto it : FreqtoCtrLink)
            {
                auto head = it.second->head;
                auto tail = it.second->tail;
                while (head->Next != tail)
                {
                    auto old = head->Next;
                    head->Next = old->Next;
                    free(old->CacheLineAddr);
                }
            }
        }
        void
        sDMmanager::sDMAddrCache::print_cache()
        {
            printf("\thit:%ld\n\tmiss:%ld\n\thit rate:%5.3lf\n",
                   this->_hits,
                   this->_miss,
                   (double)(this->_hits) / (double)(this->_hits + this->_miss) * 100.0);
        }
    }
}
