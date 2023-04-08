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
        sDMmanager::sDMmanager(int sdm_pool_id) : sdm_pool_id(sdm_pool_id)
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
         *
         */

        /**
         * @author yqy
         * @brief 返回物理地址在所属sdm中的虚拟空间的相对偏移
         * @param id:所属sdm的编号(sdmIDtype)
         * @param paddr:物理地址
         * @return 虚拟空间的相对偏移
         * @attention 未实现
         */
        Addr sDMmanager::getVirtualOffset(sdmIDtype id, Addr paddr)
        {
            // Addr = sdm_table[id].dataPtrPagePtr.next;
            // sdm_table[id].dataPtrPagePtr.getMaxBound(, );
            return paddr;
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
            return 0;
        }
        /**
         * @brief 为数据空间构建sDM空间
         * @author yqy
         * @param 该sDM空间内的数据页物理地址列表
         * @return 是否成功注册
         * //sdm metadata指针(这里sdm metadata是sdm结构体指针)
         * @attention 未完全实现
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

            sdm_space sp;

            sp.id = ++sdm_space_cnt;
            // 这里为hmac和iit申请远端内存空间
            // ...
            // Addr dataPtrPagePtr = phyalloc(xxx);
            // uint8_t *vdataPtrPagePtr = malloc(4K);
            // sp.dataPtrPagePtr = dataPtrPagePtr;
            // vdataPtrPagePtrxxx
            // 向本地申请内存空间构建三个链表
            // ...

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
         * @brief 对paddr CL的数据进行校验
         * @brief 并将一些中间值通过传输的指针参数返回
         * @attention HMAC校验未完成
         */
        bool sDMmanager::verify(Addr paddr, sdmIDtype id, Addr *rva, int &h, Addr *keyPathAddr, iit_NodePtr keyPathNode, sdm_hashKey key)
        {
            *rva = getVirtualOffset(id, paddr);
            // 执行校验
            // HMAC校验
            // ...
            // iit校验
            h = getKeyPath(id, *rva, keyPathAddr, keyPathNode);
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
            Addr keyPathAddr[MAX_HEIGHT];
            iit_Node keyPathNode[MAX_HEIGHT];
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
            if (OF)
            {
                // 引发重加密所在半页
                // ...
            }
            // 加密该缓存行
            // CME::sDM_Encrypt(data, counter, paddr, cl, cme_key);
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
