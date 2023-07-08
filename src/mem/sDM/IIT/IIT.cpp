#include "IIT.hh"

namespace gem5
{
    namespace sDM
    {
        /**
         * @author yqy
         * @brief 比较计数器a和b
         */
        bool counter_cmp(CL_Counter a, CL_Counter b)
        {
            return strncmp((const char *)a, (const char *)b, sizeof(CL_Counter)) == 0;
        }
    }
}
