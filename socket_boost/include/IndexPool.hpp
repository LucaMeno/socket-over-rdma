#include <mutex>
#include <condition_variable>
#include <queue>

class IndexPool
{
public:
    // RAII class to manage the index pool
    class Guard
    {
    public:
        Guard(IndexPool *pool, int index)
            : pool_(pool), index_(index), valid_(true) {}

        ~Guard()
        {
            if (valid_)
                pool_->release(index_);
        }

        // Disallow copy and enable move semantics
        Guard(const Guard &) = delete;
        Guard &operator=(const Guard &) = delete;

        Guard(Guard &&other) noexcept
            : pool_(other.pool_), index_(other.index_), valid_(other.valid_)
        {
            other.valid_ = false;
        }
        Guard &operator=(Guard &&other) noexcept
        {
            if (this != &other)
            {
                if (valid_)
                    pool_->release(index_);
                pool_ = other.pool_;
                index_ = other.index_;
                valid_ = other.valid_;
                other.valid_ = false;
            }
            return *this;
        }

        // Conversion operator to use the object as an integer
        operator int() const
        {
            return index_;
        }

        // Get the index
        int getIndex() const { return index_; }

        // Release the index back to the pool
        void releaseIndex()
        {
            if (valid_ && pool_)
            {
                pool_->release(index_);
                valid_ = false;
            }
        }

        // Check if the index is valid
        bool valid() const
        {
            return valid_;
        }

    private:
        IndexPool *pool_;
        int index_;
        bool valid_;
    };

    // The constructor initializes the pool with "size" indices (from 0 to size-1)
    explicit IndexPool(int size)
    {
        for (int i = 0; i < size; ++i)
            free_idxs_.push(i);
    }

    // The get() function returns a Guard object that blocks if no indices are available.
    Guard getGuard()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        bool was_empty = free_idxs_.empty();
        cv_.wait(lock, [this]
                 { return !free_idxs_.empty(); });
        if (was_empty)
            std::cout << "Thread slept waiting for index\n";

        int index = free_idxs_.front();
        free_idxs_.pop();
        return Guard(this, index);
    }

private:
    // Function called by Guard for release.
    void release(int index)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        free_idxs_.push(index);
        cv_.notify_one();
    }

    std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<int> free_idxs_;
};
