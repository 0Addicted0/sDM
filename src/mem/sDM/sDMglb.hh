#ifndef __SDMGLB_HH__
#define __SDMGLB_HH__
#include "mem/abstract_mem.hh"
extern std::vector<gem5::memory::AbstractMemory *> sDMdrams;
extern std::vector<gem5::sDM::sDMmanager *> sDMmanagers;
#endif // __SDMGLB_HH__