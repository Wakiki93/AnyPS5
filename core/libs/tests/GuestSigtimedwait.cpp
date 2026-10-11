#include "prx/libc/include/general/VabiMacros.hpp"
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#ifndef _WIN32
#include <pthread.h>
#endif
struct GuestSignalSet {
    std::uint32_t bits[4];
};
struct GuestTimespec {
    std::int64_t seconds;
    std::int64_t nanoseconds;
};
struct GuestSiginfo {
    int signo;
    int error;
    int code;
    int pid;
    unsigned int uid;
    int status;
    void* address;
    std::uint64_t value;
    std::uint64_t reason[5];
};
static_assert(sizeof(GuestSiginfo) == 80);
using Handler = void (APS5_VABI *)(int);
extern "C" {
int APS5_VABI sigtimedwait_nid_postfix(const GuestSignalSet*, void*, const GuestTimespec*);
int APS5_VABI sigwaitinfo_nid_postfix(const GuestSignalSet*, void*);
int APS5_VABI sigwait_nid_postfix(const GuestSignalSet*, int*);
int APS5_VABI pause_nid_postfix(void);
Handler APS5_VABI signal_nid_postfix(int, Handler);
int APS5_VABI raise_nid_postfix(int);
int APS5_VABI kill_nid_postfix(int, int);
int APS5_VABI getpid_nid_postfix(void);
int APS5_VABI _sigprocmask_nid_postfix(int, const GuestSignalSet*, GuestSignalSet*);
int* APS5_VABI __error_nid_postfix();
unsigned int APS5_VABI GuestAlarm_nid_no_patch(unsigned int);
}
volatile std::sig_atomic_t received = 0;
volatile std::sig_atomic_t order[4] = {};
volatile std::sig_atomic_t delivered = 0;
void APS5_VABI Callback(int value) {
    received = value;
    if (delivered < 4) order[delivered] = value;
    delivered = delivered + 1;
}
static void Require(bool value) { if (!value) std::abort(); }
static GuestSignalSet Set(int guest) { return GuestSignalSet{{1u << (guest - 1), 0, 0, 0}}; }
static GuestSignalSet Set(int first, int second) { return GuestSignalSet{{(1u << (first - 1)) | (1u << (second - 1)), 0, 0, 0}}; }
static bool Polls(const GuestSignalSet& set, int error) {
    const GuestTimespec poll{0, 0};
    *__error_nid_postfix() = 0;
    return sigtimedwait_nid_postfix(&set, nullptr, &poll) == -1 && *__error_nid_postfix() == error;
}
static int Poll(const GuestSignalSet& set) {
    const GuestTimespec poll{0, 0};
    return sigtimedwait_nid_postfix(&set, nullptr, &poll);
}
static void Block(const GuestSignalSet& set) { Require(_sigprocmask_nid_postfix(1, &set, nullptr) == 0); }
static void Unblock(const GuestSignalSet& set) { Require(_sigprocmask_nid_postfix(2, &set, nullptr) == 0); }
template <typename TCall>
static bool Throws(TCall call, const char* message) {
    try {
        call();
    } catch (const std::runtime_error& error) {
        return std::string(error.what()) == message;
    }
    return false;
}
int main() {
    const auto invalid = reinterpret_cast<Handler>(static_cast<std::uintptr_t>(-1));
    const auto ignore = reinterpret_cast<Handler>(std::uintptr_t{1});
    const GuestSignalSet empty{{0, 0, 0, 0}};
    const auto interrupt = Set(2);
    const auto term = Set(15);
    const auto user1 = Set(30);
    const GuestTimespec poll{0, 0};
    const GuestTimespec malformed{0, 1000000000};
    const GuestTimespec negative{-1, 0};
    const GuestTimespec brief{0, 50000000};
    const GuestTimespec distant{INT64_MAX, 999999999};
    GuestSiginfo info{};
    const GuestSiginfo untouched{};
    int taken = -1;

    Require(Polls(Set(13), 35));
    Require(Polls(empty, 35));
    Require(Polls(Set(9), 35));
    *__error_nid_postfix() = 0;
    Require(sigtimedwait_nid_postfix(&interrupt, &info, &malformed) == -1 && *__error_nid_postfix() == 22);
    Require(sigtimedwait_nid_postfix(&interrupt, &info, &negative) == -1 && *__error_nid_postfix() == 35);
    Require(std::memcmp(&info, &untouched, sizeof(info)) == 0);
    *__error_nid_postfix() = 0;
    Require(sigtimedwait_nid_postfix(nullptr, &info, &poll) == -1 && *__error_nid_postfix() == 14);
    Require(sigwaitinfo_nid_postfix(nullptr, &info) == -1 && *__error_nid_postfix() == 14);
    Require(sigwait_nid_postfix(nullptr, &taken) == 14 && taken == -1);
    {
        const auto started = std::chrono::steady_clock::now();
        *__error_nid_postfix() = 0;
        Require(sigtimedwait_nid_postfix(&interrupt, nullptr, &brief) == -1 && *__error_nid_postfix() == 35);
        Require(std::chrono::steady_clock::now() - started >= std::chrono::milliseconds(50));
    }

    Require(signal_nid_postfix(2, Callback) != invalid);
    Block(interrupt);
    Require(raise_nid_postfix(2) == 0 && received == 0);
    Require(sigwait_nid_postfix(&interrupt, &taken) == 0 && taken == 2 && received == 0);
    Require(Polls(interrupt, 35));
    Require(raise_nid_postfix(2) == 0 && raise_nid_postfix(2) == 0);
    Require(sigwaitinfo_nid_postfix(&interrupt, &info) == 2);
    Require(info.signo == 2 && info.error == 0 && info.code == 0x10007 && info.pid == getpid_nid_postfix() && info.uid == 0);
    Require(info.status == 0 && info.address == nullptr && info.value == 0 && info.reason[0] == 0 && info.reason[4] == 0);
    Require(sigwaitinfo_nid_postfix(&interrupt, &info) == 2 && info.code == 0x10007);
    Require(Polls(interrupt, 35));
    Require(kill_nid_postfix(getpid_nid_postfix(), 2) == 0 && received == 0);
    std::memset(&info, 0xa5, sizeof(info));
    Require(sigtimedwait_nid_postfix(&interrupt, &info, &malformed) == 2 && info.code == 0x10001 && info.reason[4] == 0);
    Require(raise_nid_postfix(2) == 0);
    Require(sigtimedwait_nid_postfix(&interrupt, nullptr, &distant) == 2);
    Require(raise_nid_postfix(2) == 0);
    Require(sigwait_nid_postfix(&interrupt, nullptr) == 14);
    Require(Polls(interrupt, 35));
    Require(raise_nid_postfix(2) == 0);
    Require(signal_nid_postfix(2, ignore) == Callback);
    Require(Polls(interrupt, 35));
    Require(raise_nid_postfix(2) == 0);
    Require(Polls(interrupt, 35));
    Require(signal_nid_postfix(2, Callback) == ignore);
    Unblock(interrupt);
    Require(received == 0);
    Require(raise_nid_postfix(2) == 0 && received == 2);
    received = 0;

    Require(signal_nid_postfix(15, Callback) != invalid);
    Block(term);
    Require(raise_nid_postfix(15) == 0 && received == 0);
    Unblock(term);
    Require(received == 15);
    received = 0;
    {
        const auto both = Set(2, 15);
        GuestSignalSet previous{};
        Require(_sigprocmask_nid_postfix(3, &both, &previous) == 0 && previous.bits[0] == 0);
        Require(raise_nid_postfix(15) == 0 && raise_nid_postfix(2) == 0);
        Require(sigwaitinfo_nid_postfix(&both, nullptr) == 2 && sigwaitinfo_nid_postfix(&both, nullptr) == 15);
        Require(Polls(both, 35));
        Require(raise_nid_postfix(15) == 0 && raise_nid_postfix(2) == 0 && raise_nid_postfix(2) == 0);
        delivered = 0;
        Require(_sigprocmask_nid_postfix(3, &previous, nullptr) == 0);
        Require(delivered == 3 && order[0] == 2 && order[1] == 2 && order[2] == 15);
        received = 0;
    }

    *__error_nid_postfix() = 0;
    Require(raise_nid_postfix(30) == -1 && *__error_nid_postfix() == 22);
    Block(user1);
    Require(raise_nid_postfix(30) == 0);
    Require(sigwait_nid_postfix(&user1, &taken) == 0 && taken == 30);
    Require(Polls(user1, 35));
    Block(Set(20));
    Require(raise_nid_postfix(20) == 0);
    Require(Polls(Set(20), 35));
    Unblock(Set(20));
    Require(signal_nid_postfix(13, ignore) != invalid);
    Require(raise_nid_postfix(13) == 0);
    Require(signal_nid_postfix(13, nullptr) == ignore);
    Block(Set(32));
    *__error_nid_postfix() = 0;
    Require(raise_nid_postfix(32) == -1 && *__error_nid_postfix() == 22);
    Require(Polls(Set(32), 35));
    Unblock(Set(32));

    Block(Set(19));
    Require(raise_nid_postfix(19) == 0);
    Require(Polls(Set(19), 35));
    Require(signal_nid_postfix(19, Callback) == nullptr);
    Require(raise_nid_postfix(19) == 0);
    Require(Poll(Set(19)) == 19);
    Require(raise_nid_postfix(19) == 0);
    Require(signal_nid_postfix(19, nullptr) == Callback);
    Require(Polls(Set(19), 35));
    Unblock(Set(19));
    Block(Set(18));
    Require(raise_nid_postfix(18) == 0);
    Require(Throws([&] { Poll(Set(18)); }, "sigtimedwait: stopping the process for the pending signal 18 is not implemented"));
    Require(signal_nid_postfix(18, Callback) == nullptr);
    Require(Poll(Set(18)) == 18);
    Require(signal_nid_postfix(18, nullptr) == Callback);
    Unblock(Set(18));

    {
        std::atomic<int> polled{-2};
        std::atomic<int> waited{0};
        Require(raise_nid_postfix(30) == 0);
        std::thread waiter([&] {
            polled = Poll(user1);
            int signal = 0;
            const int result = sigwait_nid_postfix(&user1, &signal);
            waited = result == 0 ? signal : -result;
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        Require(polled == -1 && waited == 0);
        Require(Poll(user1) == 30);
        Require(kill_nid_postfix(getpid_nid_postfix(), 30) == 0);
        waiter.join();
        Require(waited == 30);
    }
    Require(Polls(user1, 35));
    Unblock(user1);

    const auto alarm = Set(14);
    Block(alarm);
    Require(GuestAlarm_nid_no_patch(1) == 0);
    Require(sigwaitinfo_nid_postfix(&alarm, &info) == 14 && info.code == 0x10006 && info.pid == getpid_nid_postfix());
    Require(Polls(alarm, 35));
    Unblock(alarm);

#ifdef _WIN32
    Require(Throws([] { pause_nid_postfix(); }, "pause: waiting for a delivered signal not implemented"));
#else
    {
        std::atomic<bool> unblocked{false};
        const pthread_t main = pthread_self();
        std::thread sender([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            Require(pthread_kill(main, SIGTERM) == 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            Unblock(term);
            unblocked = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            Require(pthread_kill(main, SIGTERM) == 0);
        });
        Block(term);
        *__error_nid_postfix() = 0;
        Require(pause_nid_postfix() == -1 && *__error_nid_postfix() == 4);
        Require(unblocked && received == 15);
        sender.join();
    }
#endif
}
