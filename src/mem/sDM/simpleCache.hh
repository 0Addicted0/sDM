#include<iostream>
#include<unordered_map>
#define _LRU 0
#define _LFU 1
#define FLUSH_FREQ 190
#define _LRU_CNT_INIT 64
#define _LFU_CNT_INIT 64
// attention _LRU_CNT_INIT or _LFU_CNT_INIT + FLUSH_FREQ <= max(uint8_t)
namespace gem5{
    namespace sDM
    {
        typedef struct _block
        {   
            uint8_t valid,cnt,dirty; // dirty is not necessary
            uint64_t tag;
            uint64_t value;
        }block;
        
        class simpleCache // uint64_t <==> uint64_t
        {
        private:
            uint32_t _timer;
            int _evict_m;// 替换策略
            // uint64_t tag_latency;
            uint64_t _cache_line_nums;// 数据容量(block的数量)
            uint64_t _isNeedPreSet;// 预置阶段是否结束
            block *_data;
            std::unordered_map<uint64_t,int> _CAM;
        public:
            uint64_t _hits,_miss;
            uint64_t _tag_latency;
            /**
             * @author yqy
             * @brief 根据缓存行数量以及替换策略构建cache
            */
            simpleCache(uint64_t cache_line_nums, int evict_m = 0, uint64_t tag_latency = 0);
            ~simpleCache();
            virtual uint64_t _read(uint64_t tag);
            uint64_t access(uint64_t tag, bool isRead = true);
            void _evict(int idx);
            int evict(uint64_t tag);
            void flush();
            void update(int idx);
            int insert(int idx, uint64_t tag, uint64_t value);
            int _find(uint64_t tag);
            void preSet(uint64_t tag, uint64_t value);
            size_t get_byte_size(){
                return (8 + 8 + 1 + 1) * _cache_line_nums;
            }
            void _summary()
            {
                printf("summary:\n");
                printf("\thits:%ld\n",_hits);
                printf("\tmiss:%ld\n",_miss);
                printf("\thit rate:%.3lf\n", (double)_hits/(double)(_hits + _miss) * 100.0);
            }
        };
    }
}