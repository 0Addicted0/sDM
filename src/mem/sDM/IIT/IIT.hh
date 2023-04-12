#ifndef _IIT_HH_
#define _IIT_HH_
#include "../sDM_def.hh"
#include "../CME/CME.hh"

#include <cassert>
#include <string.h>
namespace gem5
{
    namespace sDM
    {
        typedef uint64_t iit_root;
        typedef uint64_t iit_hash_tag;
        typedef uint64_t iit_major_counter;
        typedef uint16_t iit_minor_counter;
        typedef uint16_t iit_leaf_minor_counter;
        typedef uint8_t iit_mid_minor_counter;
        /*
        CL_Counter:
            1. 可以统一存下一个叶/中间节点的某个计数器:包含主计数器+副计数器
            2. 第[0]开始是2byte的副计数器,[sizeof(iit_minor_counter)]开始是高8byte是主计数器
        */
        typedef uint8_t CL_Counter[sizeof(iit_major_counter) + sizeof(iit_minor_counter)];
        typedef uint8_t _iit_mid_node[CL_SIZE];
        typedef uint16_t _iit_leaf_node[CL_SIZE >> 1];

        typedef struct _iit_Node
        {
            union
            {
                /**
                 * 每个unit又一个副计数器和主计数器以及hash_tag的部分位组成
                 * 一个arity表示一个unit
                 */
                /* iIT中间节点
                 * |mid_node|
                 * |--512bit-\
                 * |          -----------------------------------\
                 * |---8---|---8---|---8---|... |----8---|----8---|
                 * |-unit1-|-unit2-|-unit3-|... |-uint63-|-uint64-|
                 * |        \
                 * |         ---------------\
                 * 0                         8
                 * |--6--|----1---|-----1----|
                 * |-ctr-|-major--|-hash_tag-|
                 */
                _iit_mid_node midNode;
                /* iIT叶子节点
                 * |leaf_node|
                 * |--512bit--\
                 * |           ------------------------------------------------\
                 * |----16----|----16----|----16----|...|-----16----|-----16----|
                 * |---unit1--|---unit2--|---unit3--|...|---unit31--|---unit32--|
                 * |           \
                 * |            --------------\
                 * 0                          16
                 * |--12--|----2----|-----2----|
                 * |--ctr-|--major--|-hash_tag-|
                 * */
                _iit_leaf_node leafNode;
            };
            /**
             * @author yqy
             * @brief 检查给出计数器下标是否合法
             */
            void ctr_range_sanity(int iit_node_type, uint32_t k)
            {
                assert((iit_node_type == IIT_LEAF_TYPE && k < IIT_LEAF_ARITY) ||
                       (iit_node_type == IIT_MID_TYPE && k < IIT_MID_ARITY));
            }
            /**
             * @author yqy
             * @brief 检查参数给出的节点类型
             */
            void node_type_sanity(int iit_node_type)
            {
                assert((iit_node_type == IIT_LEAF_TYPE || iit_node_type == IIT_MID_TYPE) && "undefined type of node");
            }

            /**
             * @author yqy|psj|ys
             * @brief  从节点中提取出hash_tag
             * @return 返回提取出的hash_tag
             */
            iit_hash_tag abstract_hash_tag(int iit_node_type)
            {
                node_type_sanity(iit_node_type);
                iit_hash_tag hash_tag = 0x0;
                if (iit_node_type == IIT_LEAF_TYPE)
                {
                    uint16_t scanner;
                    for (int i = IIT_LEAF_ARITY - 1; i >= 0; i--)
                    {
                        scanner = ((leafNode[i]) & IIT_LEAF_NODE_HASH_TAG_MASK) >>
                                  (BYTE2BIT * sizeof(iit_leaf_minor_counter) - IIT_LEAF_NODE_EMB); // 美妙的左移
                        hash_tag = (hash_tag << IIT_LEAF_NODE_EMB) | scanner;
                    }
                }
                else
                {
                    uint8_t scanner;
                    for (int i = IIT_MID_ARITY - 1; i >= 0; i--)
                    {
                        scanner = ((midNode[i]) & IIT_MID_NODE_HASH_TAG_MASK) >>
                                  ((BYTE2BIT * sizeof(iit_mid_minor_counter) - IIT_MID_NODE_EMB)); // 美妙的左移
                        hash_tag = (hash_tag << IIT_MID_NODE_EMB) | scanner;
                    }
                }
                return hash_tag;
            }

            /**
             * @author yqy|psj|ys
             * @brief 从节点中提取出主计数器
             * @return 返回计算得到的主计数器
             */
            iit_major_counter
            abstract_major(int iit_node_type)
            {
                node_type_sanity(iit_node_type);
                iit_major_counter major = 0x0;
                if (iit_node_type == IIT_LEAF_TYPE)
                {
                    iit_leaf_minor_counter scanner;
                    for (int i = IIT_LEAF_ARITY - 1; i >= 0; i--)
                    {
                        scanner = ((leafNode[i]) & IIT_LEAF_NODE_MAJOR_MASK) >>
                                  (BYTE2BIT * sizeof(iit_leaf_minor_counter) - IIT_LEAF_NODE_EMB * 2); // 取出该unit中嵌入的部分位
                                                                                                       // 美妙的左移
                        major = (major << IIT_LEAF_NODE_EMB) | scanner;                                // 拼接
                    }
                }
                else
                {
                    iit_mid_minor_counter scanner;
                    for (int i = IIT_MID_ARITY - 1; i >= 0; i--)
                    {
                        scanner = ((midNode[i]) & IIT_MID_NODE_MAJOR_MASK) >>
                                  ((BYTE2BIT * sizeof(iit_mid_minor_counter) - IIT_MID_NODE_EMB * 2)); // 取出该unit中嵌入的部分位
                                                                                                       // 美妙的左移
                        major = (major << IIT_MID_NODE_EMB) | scanner;                                 // 拼接
                    }
                }
                return major;
            }

            /**
             * @author yqy
             * @brief 将抹去hash_tag的节点拷贝到container中
             * @return 将结果存储在container中
             */
            void erase_hash_tag(int iit_node_type, _iit_Node *container)
            {
                node_type_sanity(iit_node_type);
                memcpy((void *)container, leafNode, sizeof(_iit_leaf_node));
                if (iit_node_type == IIT_LEAF_TYPE)
                {
                    for (int i = IIT_LEAF_ARITY - 1; i >= 0; i--)
                        container->leafNode[i] &= IIT_LEAF_COUNTER_RESERVED_MASK; // 将嵌入的hash_tag位置0
                }
                else
                {
                    for (int i = IIT_MID_ARITY - 1; i >= 0; i--)
                        container->midNode[i] &= IIT_MID_COUNTER_RESERVED_MASK; // 将嵌入的hash_tag位置0
                }
            }

            /**
             * @author yqy
             * @brief 将hash_tag采用小段模式嵌入到节点中
             * @attention 这个函数会改变hash_tag,注意修改之前校验操作的必要性
             */
            void embed_hash_tag(int iit_node_type, iit_hash_tag hash_tag)
            {
                // 采用小端模式嵌入
                if (iit_node_type == IIT_LEAF_TYPE)
                {
                    iit_leaf_minor_counter scatter;
                    for (int i = 0; i < IIT_LEAF_ARITY; i++)
                    {
                        scatter = hash_tag & ((1 << IIT_LEAF_NODE_EMB) - 1); // 每次取最低的IIT_LEAF_NODE_EMB位
                        leafNode[i] = (scatter << (BYTE2BIT * sizeof(iit_leaf_minor_counter) - IIT_LEAF_NODE_EMB)) |
                                      (leafNode[i] & IIT_LEAF_COUNTER_RESERVED_MASK);
                        hash_tag >>= (IIT_LEAF_NODE_EMB);
                    }
                }
                else
                {
                    iit_mid_minor_counter scatter;
                    for (int i = 0; i < IIT_MID_ARITY; i++)
                    {
                        scatter = hash_tag & ((1 << IIT_MID_NODE_EMB) - 1); // 每次取最低的IIT_LEAF_MID_EMB位
                        midNode[i] = (scatter << (BYTE2BIT * sizeof(iit_mid_minor_counter) - IIT_MID_NODE_EMB)) |
                                     (midNode[i] & IIT_MID_COUNTER_RESERVED_MASK);
                        hash_tag >>= (IIT_MID_NODE_EMB);
                    }
                }
            }

            /**
             * @author yqy
             * @brief 将第minor计数器的值写入第k个unit
             */
            void embed_minor_k(int iit_node_type, iit_minor_counter minor, uint32_t k)
            {
                node_type_sanity(iit_node_type);
                if (iit_node_type == IIT_LEAF_TYPE)
                {
                    leafNode[k] = (leafNode[k] & (IIT_LEAF_NODE_MAJOR_MASK | IIT_LEAF_NODE_HASH_TAG_MASK)) | minor;
                }
                else
                {
                    midNode[k] = (midNode[k] & (IIT_MID_NODE_MAJOR_MASK | IIT_MID_NODE_HASH_TAG_MASK)) | minor;
                }
            }

            /**
             * @author yqy
             * @brief 将major_counter采用小段模式嵌入到节点中
             */
            void
            embed_major(int iit_node_type, iit_major_counter major)
            {
                // 采用小端模式嵌入
                node_type_sanity(iit_node_type);
                if (iit_node_type == IIT_LEAF_TYPE)
                {
                    iit_leaf_minor_counter scatter;
                    for (int i = 0; i < IIT_LEAF_ARITY; i++) // 嵌入到每个unit中
                    {
                        scatter = major & ((1 << IIT_LEAF_NODE_EMB) - 1); // 每次取最低的IIT_LEAF_MID_EMB位
                        leafNode[i] = (scatter << (BYTE2BIT * sizeof(iit_leaf_minor_counter) - IIT_LEAF_NODE_EMB - IIT_LEAF_NODE_EMB)) |
                                      (leafNode[i] & IIT_LEAF_COUNTER_RESERVED_MASK); // 嵌入到第k个unit的对应位
                        major >>= (IIT_LEAF_NODE_EMB);                                // 丢弃已经嵌入的位
                    }
                }
                else
                {
                    iit_mid_minor_counter scatter;
                    for (int i = 0; i < IIT_MID_ARITY; i++) // 嵌入到每个unit中
                    {
                        scatter = major & ((1 << IIT_MID_NODE_EMB) - 1); // 每次取最低的IIT_LEAF_MID_EMB位
                        midNode[i] = (scatter << (BYTE2BIT * sizeof(iit_mid_minor_counter) - IIT_MID_NODE_EMB - IIT_MID_NODE_EMB)) |
                                     (midNode[i] & IIT_MID_COUNTER_RESERVED_MASK); // 嵌入到第k个unit的对应位
                        major >>= (IIT_MID_NODE_EMB);                              // 丢弃已经嵌入的位
                    }
                }
            }

            /**
             * @brief 计算hash_tag
             * @author yqy
             * @param iit_node_type 此节点类型
             * @param hash_tag_key  此节点所属sdm的hash_tag密钥
             * @param paddr         此节点的物理地址
             * @return 返回计算得到的hash值
             */
            iit_hash_tag
            get_hash_tag(int iit_node_type, uint8_t *hash_tag_key, Addr paddr)
            {
                node_type_sanity(iit_node_type);
                _iit_Node node;
                CL_Counter counter;
                iit_hash_tag hash_tag;
                memset(counter, 0, sizeof(CL_Counter));
                erase_hash_tag(iit_node_type, &node);
                CME::sDM_HMAC((uint8_t *)(&node.leafNode), sizeof(_iit_Node), hash_tag_key,
                              paddr, counter, sizeof(iit_hash_tag), (uint8_t *)(&hash_tag), sizeof(iit_hash_tag));
                return hash_tag;
            }

            /**
             * @brief 将当节点置为0,并给出正确的hash_tag
             * @author yqy
             */
            void init(int iit_node_type, uint8_t *hash_tag_key, Addr paddr)
            {
                node_type_sanity(iit_node_type);
                memset(leafNode, 0, sizeof(_iit_leaf_node));
                iit_hash_tag hash_tag = get_hash_tag(iit_node_type, hash_tag_key, paddr);
                embed_hash_tag(iit_node_type, hash_tag);
            }

            /**
             * @author yqy
             * @paramiit_node_type 节点类型
             * 1. IIT_LEAF_TYPE 节点类型是叶子
             * 2. IIT_MID_TYPE  节点类型是中间节点
             * @brief 检查当前节点是否有效 hash_tag = 0则无效
             */
            bool isvalid(int iit_node_type, uint8_t *hash_tag_key, Addr paddr)
            {
                node_type_sanity(iit_node_type);
                iit_hash_tag hash_tag = get_hash_tag(iit_node_type, hash_tag_key, paddr);
                return hash_tag == INVALID_NODE ? false : true;
            }

            /**
             * @author yqy
             * @brief 返回第k个计数器:主计数器+副计数器,用存储到CL_Counter结构中(64bit+16bit)
             * @attention 内部进行counter范围检查
             */
            void getCounter_k(int iit_node_type, uint32_t k, CL_Counter counter)
            {
                node_type_sanity(iit_node_type);
                // k不能超过当前类型的arity
                ctr_range_sanity(iit_node_type, k);
                iit_major_counter major = abstract_major(iit_node_type);
                *((iit_major_counter *)(&counter[sizeof(iit_minor_counter)])) = major;
                if (iit_node_type == IIT_LEAF_TYPE)
                {
                    *((iit_minor_counter *)counter) = (leafNode[k] & IIT_LEAF_MINOR_RESERVED_MASK);
                }
                else
                {
                    *((iit_minor_counter *)counter) = (midNode[k] & IIT_MID_MINOR_RESERVED_MASK);
                }
            }

            /**
             * @author yqy
             * @brief 将第k个计数器置0
             *
             */
            void reset_counter_k(int iit_node_type, uint32_t k)
            {
                node_type_sanity(iit_node_type);
                ctr_range_sanity(iit_node_type, k);
                if (iit_node_type == IIT_LEAF_TYPE)
                    leafNode[k] &= (IIT_LEAF_NODE_HASH_TAG_MASK | IIT_LEAF_NODE_MAJOR_MASK);
                else
                    leafNode[k] &= (IIT_MID_NODE_HASH_TAG_MASK | IIT_MID_NODE_MAJOR_MASK);
            }
            // need review
            /**
             * @brief 给第k个计数器增加1
             * @author yqy|psj
             * @param OF记录是否发生溢出,用于引发页面重加密和HMAC刷新
             * @attention 未完全实现
             */
            void
            inc_counter(int iit_node_type, uint32_t k, bool &OF)
            {
                OF = false;
                CL_Counter counter;
                node_type_sanity(iit_node_type);
                getCounter_k(iit_node_type, k, counter);
                (*((iit_minor_counter *)counter))++;

                if (iit_node_type == IIT_LEAF_TYPE)
                {
                    if ((*((iit_minor_counter *)counter)) > IIT_LEAF_MINOR_MAXM)
                    {
                        *((iit_minor_counter *)counter) = 0;
                        OF = true;
                        (*((iit_major_counter *)(&counter[sizeof(iit_minor_counter)])))++;
                        assert(*((iit_major_counter *)(&counter[sizeof(iit_minor_counter)])) != 0 && "Major counter overflow");
                    }
                }
                else
                {
                    if ((*((iit_minor_counter *)counter)) > IIT_MID_MINOR_MAXM)
                    {
                        *((iit_minor_counter *)counter) = 0;
                        OF = true;
                        (*((iit_major_counter *)(&counter[sizeof(iit_minor_counter)])))++;
                        assert(*((iit_major_counter *)(&counter[sizeof(iit_minor_counter)])) != 0 && "Major counter overflow");
                    }
                }
                // if (OF)                                                                                            // 副计数器溢出
                //     embed_major(iit_node_type, *((iit_major_counter *)(&counter[sizeof(iit_minor_counter)])) + 1); //+1？（上面判断的时候，major不是溢出加1了吗），不知道是不是有问题
                // 是的这里不应该再+1了
                embed_minor_k(iit_node_type, *((iit_minor_counter *)(counter)), k);
            }

            // need review
            /**
             * @author yqy|psj
             * @param iit_node_type 当前节点类型
             * @param container (CL_Counter)结果计数器
             * @attention 结果计数器格式为中间节点
             * @brief 求当前节点的和,并转换为mid类型的节点写入指针参数中
             */
            // psj:就整个函数都有点迷惑，我觉得应该是下面这样的
            void sum(int iit_node_type, CL_Counter container, int dest_iit_node_type = IIT_MID_ARITY)
            {
                iit_major_counter major = abstract_major(iit_node_type);
                iit_major_counter minor = 0x0;
                /**
                 * leaf
                 * -----------------------------
                 * |-----major-----|---minor---|
                 * -----------------------------
                 * mid
                 * -----------------------------
                 * |---------major-------|minor|
                 * -----------------------------
                 */
                if (iit_node_type == IIT_LEAF_TYPE)
                {
                    // leaf的major是每+1,表示写了(1<<IIT_LEAF_MINOR_BIT_SIZE)次
                    // mid的major是每+1,表示写了(1<<IIT_MID_MINOR_BIT_SIZE)次
                    // 因此每个leaf中的1是mid中的1<<(IIT_LEAF_MINOR_BIT_SIZE - IIT_MID_MINOR_BIT_SIZE)倍
                    major <<= (IIT_LEAF_MINOR_BIT_SIZE - IIT_MID_MINOR_BIT_SIZE);
                    // 先以leaf的格式累加起来
                    for (int i = 0; i < IIT_LEAF_ARITY; i++)
                        minor += ((leafNode[i]) & IIT_LEAF_MINOR_RESERVED_MASK);
                }
                else
                {
                    for (int i = 0; i < IIT_MID_ARITY; i++)
                        minor += ((leafNode[i]) & IIT_MID_MINOR_RESERVED_MASK);
                }
                // switch (dest_iit_node_type)
                // {
                // case IIT_LEAF_TYPE:
                //     major += (minor / (IIT_LEAF_MINOR_MAXM + 1));
                //     minor &= (1 << IIT_LEAF_MINOR_BIT_SIZE);
                //     break;
                // case IIT_MID_TYPE:
                // 中间节点计数器更快溢出
                // 转换到mid格式上
                major += (minor / (IIT_MID_MINOR_MAXM + 1));
                minor &= ((1 << IIT_MID_MINOR_BIT_SIZE) - 1);
                // break;
                // default:
                //     assert(0 && "undefined type of node");
                //     break;
                // }
                *((iit_minor_counter *)(container)) = (iit_minor_counter)minor;
                *((iit_major_counter *)(&container[sizeof(iit_minor_counter)])) = major;
                return;
            }
            /**
             * @brief
             * 打印第k个计数器的16进制值
             * @author
             * yqy
             */
            void print(int iit_node_type, uint32_t k)
            {
                node_type_sanity(iit_node_type);
                CL_Counter counter_k;
                getCounter_k(iit_node_type, k, counter_k);
                uint64_t *major = (uint64_t *)(&counter_k[sizeof(iit_minor_counter)]); // 2~10B
                uint16_t *minor = (uint16_t *)(counter_k);                             // 0~1B
                printf("Major: %ld  |  minor: %d\n", *major, *minor);
            }
        } iit_Node;
        typedef iit_Node *iit_NodePtr;
        /**
         * @author yqy
         * @brief 比较两个计数器是否相等
         */
        bool counter_cmp(CL_Counter a, CL_Counter b);
    }
}
#endif
