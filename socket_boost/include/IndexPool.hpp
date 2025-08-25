/*#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <iostream>

class IndexPool
{
public:
    class Guard
    {
    public:
        Guard(IndexPool *pool, std::vector<int> indices)
            : pool_(pool), indices_(std::move(indices)), valid_(true) {}

        ~Guard()
        {
            if (valid_)
                pool_->release(indices_);
        }

        Guard(const Guard &) = delete;
        Guard &operator=(const Guard &) = delete;

        Guard(Guard &&other) noexcept
            : pool_(other.pool_), indices_(std::move(other.indices_)), valid_(other.valid_)
        {
            other.valid_ = false;
        }
        Guard &operator=(Guard &&other) noexcept
        {
            if (this != &other)
            {
                if (valid_)
                    pool_->release(indices_);
                pool_ = other.pool_;
                indices_ = std::move(other.indices_);
                valid_ = other.valid_;
                other.valid_ = false;
            }
            return *this;
        }

        operator int() const
        {
            if (indices_.size() != 1)
                throw std::runtime_error("Guard contiene più di un indice");
            return indices_[0];
        }

        const std::vector<int> &getIndexes() const { return indices_; }

        // Rilascio manuale
        void releaseIndexes()
        {
            if (valid_ && pool_)
            {
                pool_->release(indices_);
                valid_ = false;
            }
        }

        bool valid() const { return valid_; }

    private:
        IndexPool *pool_;
        std::vector<int> indices_;
        bool valid_;
    };

    explicit IndexPool(int size)
    {
        for (int i = 0; i < size; ++i)
            free_idxs_.push(i);
    }

    // richiede N indici
    Guard getGuard(size_t count = 1)
    {
        std::unique_lock<std::mutex> lock(mutex_);

        cv_.wait(lock, [this, count]
                 { return free_idxs_.size() >= count; });

        std::vector<int> indices;
        for (size_t i = 0; i < count; ++i)
        {
            indices.push_back(free_idxs_.front());
            free_idxs_.pop();
        }

        return Guard(this, std::move(indices));
    }

private:
    void release(const std::vector<int> &indices)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int idx : indices)
            free_idxs_.push(idx);
        cv_.notify_all();
    }

    std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<int> free_idxs_;
};
*/