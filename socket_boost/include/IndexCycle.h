#pragma once

#include <atomic>

class IndexCycle
{
public:
    IndexCycle(int n_of_idx, int reps_per_idx);

    int get();
    void reset();

private:
    const int maxIndices;
    const int repeatCount;
    std::atomic<int> currentIndex;
    std::atomic<int> currentRepeat;

    void advanceIndex();
};
