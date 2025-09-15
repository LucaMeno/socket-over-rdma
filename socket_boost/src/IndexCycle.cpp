#include "IndexCycle.h"

IndexCycle::IndexCycle(int n_of_idx, int reps_per_idx)
    : maxIndices(n_of_idx), repeatCount(reps_per_idx), currentIndex(0), currentRepeat(0)
{
}

int IndexCycle::get()
{
    int repeat = currentRepeat.fetch_add(1, std::memory_order_acq_rel);
    if (repeat + 1 >= repeatCount)
    {
        currentRepeat.store(0, std::memory_order_release);
        advanceIndex();
    }
    return currentIndex.load(std::memory_order_acquire);
}

void IndexCycle::reset()
{
    currentRepeat.store(0, std::memory_order_release);
    advanceIndex();
}

void IndexCycle::advanceIndex()
{
    int idx = currentIndex.load(std::memory_order_acquire);
    int next = (idx + 1) % maxIndices;
    currentIndex.store(next, std::memory_order_release);
}
