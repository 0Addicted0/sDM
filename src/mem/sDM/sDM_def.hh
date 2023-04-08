#include <stdint.h>

#define BYTE2BIT 8

#define SDM_HMAC_ZOOM 64 // 缩放系数与选择的输入长度和hash算法有关 1/2Page -> 1/2CL(sm3) sizeof(HMAC)=sDataSize/sDMHMACZOOM
#define CL_SIZE 64       // 64B = 512 bit = CacheLine_Size
#define PAGE_SIZE 4096
#define CL_ALIGN_MASK 0xffffffffffffffC0   // 转换为缓存行对齐地址, +by psj:CL mask错误
#define CL_ALIGNED_CHK 0x03F               // 检查地址是否按CL对齐
#define PAGE_ALIGN_MASK 0xfffffffffffff000 // 转换为页面对齐地址  , +by psj:PAGE mask错误
#define HMAC_SIZE (SM3_len >> 3)           // SM3
#define PAIR_SIZE 16                       // ptr+num(8+8) 数据页指针集合二元组的大小

#define IIT_NODE_SIZE 64 // 64B = 512 bit = CacheLine_Size
// #define IIT_MAJOR_COUNTER_SIZE 8 // 主计数器64bit = 8B
#define IIT_LEAF_COUNTER_SIZE
// #define IIT_HASHTAG_SIZE 8       // 12B = 64 bit
#define IIT_LEAF_MINOR_BIT_SIZE 12 // 12bit -> 2B
#define IIT_MID_MINOR_BIT_SIZE 6   // 6 bit -> 1B
#define IIT_LEAF_ARITY 32          // 叶节点打包32个计数器
#define IIT_MID_ARITY 64           // 中间/root打包64个计数器
#define IIT_LEAF_TYPE 0            // 节点类型是叶子
#define IIT_MID_TYPE 1             // 节点类型是中间节点
#define INVALID_NODE 0x0
#define IIT_LEAF_NODE_HASH_TAG_MASK 0xC000
#define IIT_MID_NODE_HASH_TAG_MASK 0x80
#define IIT_LEAF_NODE_MAJOR_MASK 0x3000
#define IIT_MID_NODE_MAJOR_MASK 0x40
#define IIT_LEAF_NODE_EMB 2                   // 叶节点unit中major和hash_tag等bit数嵌入
#define IIT_MID_NODE_EMB 1                    // 中间节点unit中major和hash_tag等bit数嵌入
#define IIT_LEAF_COUNTER_RESERVED_MASK 0x3FFF //
#define IIT_MID_COUNTER_RESERVED_MASK 0x7F
#define IIT_LEAF_MINOR_RESERVED_MASK 0x0FFF
#define IIT_MID_MINOR_RESERVED_MASK 0x3F // 保留节点中的所有计数器相关位
#define IIT_LEAF_MINOR_MAXM 0xFFFF       // 叶节点的major counter最大值
#define IIT_MID_MINOR_MAXM 0x3F          // 中间节点点的minor counter最大值
#define LITTLE_ENDIAN 1                  // 使用小端模式嵌入
#define SM3_KEY_SIZE SM3_len / 8         // 基于sm3的hmac密钥
#define HASH_KEY_TYPE 0
#define CME_KEY_TYPE 1
namespace gem5
{
    namespace sDM
    {
        typedef uint64_t Addr; // 64位地址类型
    }
}
