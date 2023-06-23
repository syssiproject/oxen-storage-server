#include "sispopmq/sispopmq.h"
#include "common.h"
#include <chrono>
#include <future>

TEST_CASE("timer test", "[timer][basic]") {
    sispopmq::SispopMQ omq{get_logger(""), LogLevel::trace};

    omq.set_general_threads(1);
    omq.set_batch_threads(1);

    std::atomic<int> ticks = 0;
    auto timer = omq.add_timer([&] { ticks++; }, 5ms);
    omq.start();
    auto start = std::chrono::steady_clock::now();
    wait_for([&] { return ticks.load() > 3; });
    {
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        auto lock = catch_lock();
        REQUIRE( ticks.load() > 3 );
        REQUIRE( elapsed_ms < 50 * TIME_DILATION );
    }
}

TEST_CASE("timer squelch", "[timer][squelch]") {
    sispopmq::SispopMQ omq{get_logger(""), LogLevel::trace};

    omq.set_general_threads(3);
    omq.set_batch_threads(3);

    std::atomic<bool> first = true;
    std::atomic<bool> done = false;
    std::atomic<int> ticks = 0;

    // Set up a timer with squelch on; the job shouldn't get rescheduled until the first call
    // finishes, by which point we set `done` and so should get exactly 1 tick.
    auto timer = omq.add_timer([&] {
        if (first.exchange(false)) {
            std::this_thread::sleep_for(30ms * TIME_DILATION);
            ticks++;
            done = true;
        } else if (!done) {
            ticks++;
        }
    }, 5ms * TIME_DILATION, true /* squelch */);
    omq.start();

    wait_for([&] { return done.load(); });
    {
        auto lock = catch_lock();
        REQUIRE( done.load() );
        REQUIRE( ticks.load() == 1 );
    }

    // Start another timer with squelch *off*; the subsequent jobs should get scheduled even while
    // the first one blocks
    std::atomic<bool> first2 = true;
    std::atomic<bool> done2 = false;
    std::atomic<int> ticks2 = 0;
    auto timer2 = omq.add_timer([&] {
        if (first2.exchange(false)) {
            std::this_thread::sleep_for(40ms * TIME_DILATION);
            done2 = true;
        } else if (!done2) {
            ticks2++;
        }
    }, 5ms, false /* squelch */);

    wait_for([&] { return done2.load(); });
    {
        auto lock = catch_lock();
        REQUIRE( ticks2.load() > 2 );
        REQUIRE( done2.load() );
    }
}

TEST_CASE("timer cancel", "[timer][cancel]") {
    sispopmq::SispopMQ omq{get_logger(""), LogLevel::trace};

    omq.set_general_threads(1);
    omq.set_batch_threads(1);

    std::atomic<int> ticks = 0;

    // We set up *and cancel* this timer before omq starts, so it should never fire
    auto notimer = omq.add_timer([&] { ticks += 1000; }, 5ms * TIME_DILATION);
    omq.cancel_timer(notimer);

    TimerID timer = omq.add_timer([&] {
        if (++ticks == 3)
            omq.cancel_timer(timer);
    }, 5ms * TIME_DILATION);

    omq.start();

    wait_for([&] { return ticks.load() >= 3; });
    {
        auto lock = catch_lock();
        REQUIRE( ticks.load() == 3 );
    }

    // Test the alternative taking an lvalue reference instead of returning by value (see sispopmq.h
    // for why this is sometimes needed).
    std::atomic<int> ticks3 = 0;
    std::weak_ptr<TimerID> w_timer3;
    {
        auto timer3 = std::make_shared<TimerID>();
        auto& t3ref = *timer3; // Get this reference *before* we move the shared pointer into the lambda
        omq.add_timer(t3ref, [&ticks3, &omq, timer3=std::move(timer3)] {
            if (ticks3 == 0)
                ticks3++;
            else if (ticks3 > 1) {
                omq.cancel_timer(*timer3);
                ticks3++;
            }
        }, 1ms);
    }

    wait_for([&] { return ticks3.load() >= 1; });
    {
        auto lock = catch_lock();
        REQUIRE( ticks3.load() == 1 );
    }
    ticks3++;
    wait_for([&] { return ticks3.load() >= 3 && w_timer3.expired(); });
    {
        auto lock = catch_lock();
        REQUIRE( ticks3.load() == 3 );
        REQUIRE( w_timer3.expired() );
    }
}

