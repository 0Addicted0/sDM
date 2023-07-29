#include "simpleCache.hh"
#include <assert.h>
#include <stdio.h>
// #define _DEBUG 1
namespace gem5
{
    namespace sDM
    {
        simpleCache::simpleCache(uint64_t cache_line_nums, int evict_m, uint64_t tag_latency)
        {
            _timer = 0;
            _evict_m = evict_m;
            _hits = _miss = 0;
            _isNeedPreSet = _cache_line_nums = cache_line_nums;
            _tag_latency = tag_latency;
            _data = (block *)malloc(sizeof(block) * cache_line_nums);
            for (int i = 0; i < cache_line_nums; i++)
            {
                _data[i].valid = 0;// 置为无效
            }
        }
        simpleCache::~simpleCache()
        {
            free(_data);
        }
        // read from memory after miss
        uint64_t simpleCache::_read(uint64_t tag)
        {
#ifndef _DEBUG
            assert(0 && "need override");
#endif
            return tag+0x1000;
            // value = manager->find();
        }
        // 访问cache,同时已经打包了访存过程函数
        uint64_t simpleCache::access(uint64_t tag, bool isRead)
        {
            if(isRead == false)
            {
                assert(0 && "This read-only simpleCache");
            }
            // 查找缓存表(附带会加入统计数据)
            int idx = _find(tag);
            if (idx == -1 || _data[idx].valid == 0)// miss
            {
                _miss++;
                uint64_t value;
                value = _read(tag);
                // assert(0 && "Read data from Memory");
                idx = insert(idx, tag, value);// 根据idx和(tag,value)插入数据
                if (idx == -1) // insert failed
                    return value;
            }
            else // hit
            {
                _hits++;
                // assert(0 && "need add latency")
                update(idx);
            }
            flush();
            assert(_data[idx].valid); // sanity check
            return _data[idx].value;
        }
        // 在查找表(CAM)中寻找tag
        int simpleCache::_find(uint64_t tag)
        {
            auto ptr = _CAM.find(tag);
            return ptr == _CAM.end() ? (-1) : ptr->second;
        }
        // 找到替换/可用block
        int simpleCache::evict(uint64_t tag)
        {
            int idx=0;
            bool isEvict = true;
            uint8_t cnt;
            switch (_evict_m)
            {
            case _LRU:
                cnt = 0;
                for(int i=0;i<_cache_line_nums;i++)
                {
                    if(_data[i].valid == 0)// 直接使用空位
                    {
                        idx = i;
                        isEvict = false;
                        break;
                    }
                    if(_data[i].cnt > cnt)
                    {
                        idx = i;
                    }
                }
                break;
            case _LFU:
                cnt = 0xFF;
                for(int i=0;i<_cache_line_nums;i++)
                {
                    if(_data[i].valid == 0)// 直接使用空位
                    {
                        idx = i;
                        isEvict = false;
                        break;
                    }
                    if(_data[i].cnt < cnt)
                    {
                        idx = i;
                    }
                }
                break;
            default:
                assert(0 && "invalid evcition method"); // sanity check
                break;
            }
            if(isEvict)
            {
                _CAM.erase(_data[idx].tag);// 擦除查找表(CAM)
                if( _data[idx].dirty)
                    _evict(idx);
            }
            _data[idx].tag = tag;
            _data[idx].valid = 0;
            return idx;
        }
        // 脏数据写回
        void simpleCache::_evict(int idx)
        {
            // writeBack
            assert(0 && "need write back");
            // manager->write2Mem(sizeof(_data[idx].ta), _data[idx].tag, _data[idx].value);
        }
        // 定时刷新计数器避免溢出
        void simpleCache::flush()
        {
            if(_timer == FLUSH_FREQ)
            {
                for (int i = 0; i < _cache_line_nums; i++)
                    _data[i].cnt <<= 1;
            }
            else 
                _timer++;
        }
        // 按照指定的策略更新计数器
        void simpleCache::update(int idx)
        {
            switch (_evict_m)
            {
            case _LRU:
                for(int i=0; i < _cache_line_nums; i++)
                {
                    if (i == idx)continue;
                    _data[i].cnt++;
                }
                break;
            case _LFU:
                _data[idx].cnt++;
                break;
            default:
                assert(0 && "invalid evcition method"); // sanity check
                break;
            }
        }
        // 向cache中插入/填充数据
        int simpleCache::insert(int idx, uint64_t tag, uint64_t value)
        {
            if(_cache_line_nums == 0)
                return -1;
            if(idx == -1)
            {
                idx = evict(tag);
            }
            // 向指定位置更新数据
            assert(_data[idx].tag == tag); // sanity check
            _CAM[tag] = idx;
            _data[idx].value = value;
            _data[idx].dirty = 0;
            _data[idx].valid = 1;
            switch (_evict_m)
            {
            case _LRU:
                _data[idx].cnt = _LRU_CNT_INIT;
                break;
            case _LFU:
                _data[idx].cnt = _LFU_CNT_INIT;
                break;
            default:
                assert(0 && "invalid evcition method"); // sanity check
                break;
            }
            return idx;
        }
        // 可以在init时预先添加一些缓存
        void simpleCache::preSet(uint64_t tag, uint64_t value)
        {
            if(_isNeedPreSet == 0) return;
            int idx = -1;
            for(int i=0; i < _cache_line_nums;i++)
            {
                if(_data[i].valid == 0)
                {
                    idx = i;
                    _isNeedPreSet--;
                    break;
                }
            }
            _data[idx].tag = tag;
            idx = insert(idx, tag, value);
        }
    }
}
#ifdef _DEBUG
int main()
{
    // linear test
    int size = 0, mode = _LRU;
    auto mycache = new gem5::sDM::simpleCache(size, mode);
    printf("size = %ld\n",mycache->get_byte_size());

    printf("Running...\n");
    for(int i=1;i<2*size;i++)
    {
        uint64_t vaddr = 0x1000 * i;
        mycache->preSet(vaddr,vaddr+0x1000);
    } 
    printf("preset over!\n");
    for (int i = 0x1000; i < 0x9FFF; i++)
    {
        uint64_t t = (i & 0xFF000);
        if(mycache->access(t) != t + 0x1000)
        {
            printf("error [%d]!\n" ,i);
        }
        else if(i%0x1000 == 0)
        {
            printf("... %d\n",(i/0x1000)-1);
        }
    }
    printf("test over!\n");
    mycache->_summary();
    return 0;
}
#endif