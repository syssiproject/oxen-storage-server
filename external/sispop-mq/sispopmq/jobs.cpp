#include "sispopmq.h"
#include "batch.h"
#include "sispopmq-internal.h"

namespace sispopmq {

void SispopMQ::proxy_batch(detail::Batch* batch) {
    const auto [jobs, tagged_threads] = batch->size();
    OMQ_TRACE("proxy queuing batch job with ", jobs, " jobs", tagged_threads ? " (job uses tagged thread(s))" : "");
    if (!tagged_threads) {
        for (size_t i = 0; i < jobs; i++)
            batch_jobs.emplace_back(batch, i);
    } else {
        // Some (or all) jobs have a specific thread target so queue any such jobs in the tagged
        // worker queue.
        auto threads = batch->threads();
        for (size_t i = 0; i < jobs; i++) {
            auto& jobs = threads[i] > 0
                ? std::get<batch_queue>(tagged_workers[threads[i] - 1])
                : batch_jobs;
            jobs.emplace_back(batch, i);
        }
    }

    proxy_skip_one_poll = true;
}

void SispopMQ::job(std::function<void()> f, std::optional<TaggedThreadID> thread) {
    if (thread && thread->_id == -1)
        throw std::logic_error{"job() cannot be used to queue an in-proxy job"};
    auto* j = new Job(std::move(f), thread);
    auto* baseptr = static_cast<detail::Batch*>(j);
    detail::send_control(get_control_socket(), "BATCH", sispopc::bt_serialize(reinterpret_cast<uintptr_t>(baseptr)));
}

void SispopMQ::proxy_schedule_reply_job(std::function<void()> f) {
    auto* j = new Job(std::move(f));
    reply_jobs.emplace_back(static_cast<detail::Batch*>(j), 0);
    proxy_skip_one_poll = true;
}

void SispopMQ::proxy_run_batch_jobs(batch_queue& jobs, const int reserved, int& active, bool reply) {
    while (!jobs.empty() && active_workers() < max_workers &&
            (active < reserved || active_workers() < general_workers)) {
        proxy_run_worker(get_idle_worker().load(std::move(jobs.front()), reply));
        jobs.pop_front();
        active++;
    }
}

// Called either within the proxy thread, or before the proxy thread has been created; actually adds
// the timer.  If the timer object hasn't been set up yet it gets set up here.
void SispopMQ::proxy_timer(int id, std::function<void()> job, std::chrono::milliseconds interval, bool squelch, int thread) {
    if (!timers)
        timers.reset(zmq_timers_new());

    int zmq_timer_id = zmq_timers_add(timers.get(),
            interval.count(),
            [](int timer_id, void* self) { static_cast<SispopMQ*>(self)->_queue_timer_job(timer_id); },
            this);
    if (zmq_timer_id == -1)
        throw zmq::error_t{};
    timer_jobs[zmq_timer_id] = { std::move(job), squelch, false, thread };
    timer_zmq_id[id] = zmq_timer_id;
}

void SispopMQ::proxy_timer(sispopc::bt_list_consumer timer_data) {
    auto timer_id = timer_data.consume_integer<int>();
    std::unique_ptr<std::function<void()>> func{reinterpret_cast<std::function<void()>*>(timer_data.consume_integer<uintptr_t>())};
    auto interval = std::chrono::milliseconds{timer_data.consume_integer<uint64_t>()};
    auto squelch = timer_data.consume_integer<bool>();
    auto thread = timer_data.consume_integer<int>();
    if (!timer_data.is_finished())
        throw std::runtime_error("Internal error: proxied timer request contains unexpected data");
    proxy_timer(timer_id, std::move(*func), interval, squelch, thread);
}

void SispopMQ::_queue_timer_job(int timer_id) {
    auto it = timer_jobs.find(timer_id);
    if (it == timer_jobs.end()) {
        OMQ_LOG(warn, "Could not find timer job ", timer_id);
        return;
    }
    auto& [func, squelch, running, thread] = it->second;
    if (squelch && running) {
        OMQ_LOG(debug, "Not running timer job ", timer_id, " because a job for that timer is still running");
        return;
    }

    if (thread == -1) { // Run directly in proxy thread
        try { func(); }
        catch (const std::exception &e) { OMQ_LOG(warn, "timer job ", timer_id, " raised an exception: ", e.what()); }
        catch (...) { OMQ_LOG(warn, "timer job ", timer_id, " raised a non-std exception"); }
        return;
    }

    detail::Batch* b;
    if (squelch) {
        auto* bv = new Batch<void>;
        bv->add_job(func, thread);
        running = true;
        bv->completion([this,timer_id](auto results) {
            try { results[0].get(); }
            catch (const std::exception &e) { OMQ_LOG(warn, "timer job ", timer_id, " raised an exception: ", e.what()); }
            catch (...) { OMQ_LOG(warn, "timer job ", timer_id, " raised a non-std exception"); }
            auto it = timer_jobs.find(timer_id);
            if (it != timer_jobs.end())
                it->second.running = false;
        }, SispopMQ::run_in_proxy);
        b = bv;
    } else {
        b = new Job(func, thread);
    }
    OMQ_TRACE("b: ", b->size().first, ", ", b->size().second, "; thread = ", thread);
    assert(b->size() == std::make_pair(size_t{1}, thread > 0));
    auto& queue = thread > 0
        ? std::get<batch_queue>(tagged_workers[thread - 1])
        : batch_jobs;
    queue.emplace_back(static_cast<detail::Batch*>(b), 0);
}

void SispopMQ::add_timer(TimerID& timer, std::function<void()> job, std::chrono::milliseconds interval, bool squelch, std::optional<TaggedThreadID> thread) {
    int th_id = thread ? thread->_id : 0;
    timer._id = next_timer_id++;
    if (proxy_thread.joinable()) {
        detail::send_control(get_control_socket(), "TIMER", sispopc::bt_serialize(sispopc::bt_list{{
                    timer._id,
                    detail::serialize_object(std::move(job)),
                    interval.count(),
                    squelch,
                    th_id}}));
    } else {
        proxy_timer(timer._id, std::move(job), interval, squelch, th_id);
    }
}

TimerID SispopMQ::add_timer(std::function<void()> job, std::chrono::milliseconds interval, bool squelch, std::optional<TaggedThreadID> thread) {
    TimerID tid;
    add_timer(tid, std::move(job), interval, squelch, std::move(thread));
    return tid;
}

void SispopMQ::proxy_timer_del(int id) {
    if (!timers)
        return;
    auto it = timer_zmq_id.find(id);
    if (it == timer_zmq_id.end())
        return;
    zmq_timers_cancel(timers.get(), it->second);
    timer_zmq_id.erase(it);
}

void SispopMQ::cancel_timer(TimerID timer_id) {
    if (proxy_thread.joinable()) {
        detail::send_control(get_control_socket(), "TIMER_DEL", sispopc::bt_serialize(timer_id._id));
    } else {
        proxy_timer_del(timer_id._id);
    }
}

void SispopMQ::TimersDeleter::operator()(void* timers) { zmq_timers_destroy(&timers); }

TaggedThreadID SispopMQ::add_tagged_thread(std::string name, std::function<void()> start) {
    if (proxy_thread.joinable())
        throw std::logic_error{"Cannot add tagged threads after calling `start()`"};

    if (name == "_proxy"sv || name.empty() || name.find('\0') != std::string::npos)
        throw std::logic_error{"Invalid tagged thread name `" + name + "'"};

    auto& [run, busy, queue] = tagged_workers.emplace_back();
    busy = false;
    run.worker_id = tagged_workers.size(); // We want index + 1 (b/c 0 is used for non-tagged jobs)
    run.worker_routing_name = "t" + std::to_string(run.worker_id);
    run.worker_routing_id = "t" + std::string{reinterpret_cast<const char*>(&run.worker_id), sizeof(run.worker_id)};
    OMQ_TRACE("Created new tagged thread ", name, " with routing id ", run.worker_routing_name);

    run.worker_thread = std::thread{&SispopMQ::worker_thread, this, run.worker_id, name, std::move(start)};

    return TaggedThreadID{static_cast<int>(run.worker_id)};
}

}
