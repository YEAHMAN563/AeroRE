#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace aerore {

// Fixed worker pool with per-worker deques. submit() round-robins, workers
// pop locally (LIFO) and steal from peers (FIFO). wait() blocks until every
// submitted job, including ones enqueued by jobs, has finished.
class Pool {
public:
    explicit Pool(unsigned threads = 0) {
        if (threads == 0) threads = std::max(1u, std::thread::hardware_concurrency());
        workers_.reserve(threads);
        for (unsigned i = 0; i < threads; ++i)
            workers_.push_back(std::make_unique<Worker>());
        for (unsigned i = 0; i < threads; ++i)
            threads_.emplace_back([this, i] { run(static_cast<int>(i)); });
    }

    ~Pool() {
        stop_.store(true);
        cv_.notify_all();
        for (auto& t : threads_)
            if (t.joinable()) t.join();
    }

    Pool(const Pool&) = delete;
    Pool& operator=(const Pool&) = delete;

    unsigned size() const { return static_cast<unsigned>(threads_.size()); }

    template <class F>
    void submit(F&& fn) {
        pending_.fetch_add(1, std::memory_order_acq_rel);
        auto job = std::function<void()>(std::forward<F>(fn));
        unsigned i = rr_.fetch_add(1, std::memory_order_relaxed) % threads_.size();
        {
            std::lock_guard lock(workers_[i]->mu);
            workers_[i]->q.push_back(std::move(job));
        }
        cv_.notify_all();
    }

    void wait() {
        std::unique_lock lock(wait_mu_);
        cv_.wait(lock, [&] { return pending_.load(std::memory_order_acquire) == 0; });
    }

private:
    struct Worker {
        std::mutex mu;
        std::deque<std::function<void()>> q;
    };

    bool take(int self, std::function<void()>& out) {
        {
            std::lock_guard lock(workers_[self]->mu);
            if (!workers_[self]->q.empty()) {
                out = std::move(workers_[self]->q.back());
                workers_[self]->q.pop_back();
                return true;
            }
        }
        const int n = static_cast<int>(workers_.size());
        for (int k = 1; k < n; ++k) {
            int other = (self + k) % n;
            std::lock_guard lock(workers_[other]->mu);
            if (!workers_[other]->q.empty()) {
                out = std::move(workers_[other]->q.front());
                workers_[other]->q.pop_front();
                return true;
            }
        }
        return false;
    }

    void run(int self) {
        while (!stop_.load(std::memory_order_acquire)) {
            std::function<void()> job;
            if (!take(self, job)) {
                std::unique_lock lock(wait_mu_);
                cv_.wait_for(lock, std::chrono::milliseconds(2));
                continue;
            }
            try {
                job();
            } catch (...) {
            }
            if (pending_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                std::lock_guard lock(wait_mu_);
                cv_.notify_all();
            }
        }
    }

    std::vector<std::unique_ptr<Worker>> workers_;
    std::vector<std::thread> threads_;
    std::atomic<bool> stop_{false};
    std::atomic<int> pending_{0};
    std::atomic<unsigned> rr_{0};
    std::mutex wait_mu_;
    std::condition_variable cv_;
};

}  // namespace aerore
