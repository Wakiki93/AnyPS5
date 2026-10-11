#include "SceTypes.hpp"
#include "prx/libc/include/General.hpp"
#include "prx/libkernel/Pthread/Posix/Common.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include <atomic>
#include <bit>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#ifndef _WIN32
#include <unistd.h>
#endif

extern "C" int* APS5_VABI __error_nid_postfix();
extern "C" int APS5_VABI getpid_nid_postfix(void);
extern "C" int APS5_VABI getuid_nid_postfix(void);
extern "C" Pthread APS5_VABI scePthreadSelf(void);

struct GuestSignalSet {
    std::uint32_t bits[4];
};

struct GuestSigaction {
    std::uintptr_t handler;
    int flags;
    GuestSignalSet mask;
};
static_assert(sizeof(GuestSigaction) == 32 && offsetof(GuestSigaction, flags) == 8 && offsetof(GuestSigaction, mask) == 12);

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
static_assert(sizeof(GuestSiginfo) == 80 && offsetof(GuestSiginfo, address) == 24 && offsetof(GuestSiginfo, value) == 32 && offsetof(GuestSiginfo, reason) == 40);

namespace {
using GuestHandler = void (APS5_VABI *)(int);
constexpr int MaxSignal = 128;
constexpr int MaskedSignals = 32;
constexpr int GuestSigkill = 9;
constexpr int GuestSigstop = 17;
constexpr int GuestSigtstp = 18;
constexpr int GuestSigcont = 19;
constexpr int GuestSigttin = 21;
constexpr int GuestSigttou = 22;
constexpr int GuestSigthr = 32;
constexpr int GuestEintr = 4;
constexpr int GuestEfault = 14;
constexpr int GuestEinval = 22;
constexpr int GuestEagain = 35;
constexpr int SiUser = 0x10001;
constexpr int SiKernel = 0x10006;
constexpr int SiLwp = 0x10007;
constexpr int SaRestart = 0x2;
constexpr int SaSiginfo = 0x40;
constexpr std::size_t MaxPendingInstances = 128;
std::atomic<GuestHandler> handlers[MaxSignal + 1]{};
static_assert(std::atomic<GuestHandler>::is_always_lock_free);
std::atomic<std::uint32_t> blockedMask{0};
static_assert(std::atomic<std::uint32_t>::is_always_lock_free);
std::mutex registration;
GuestSigaction dispositions[MaxSignal + 1]{};
thread_local volatile std::sig_atomic_t handledHere = 0;

struct PendingInstance {
    int code;
    Pthread thread;
};

struct PendingSignals {
    std::uint32_t mask = 0;
    std::uint32_t coalesced = 0;
    std::size_t queued = 0;
    std::vector<PendingInstance> instances[MaskedSignals + 1];
    std::condition_variable changed;
};

PendingSignals& Pending() {
    static auto* state = new PendingSignals();
    return *state;
}

std::uint32_t Bit(int guest) {
    return 1u << (guest - 1);
}

bool Maskable(int guest) {
    return guest >= 1 && guest <= MaskedSignals && guest != GuestSigkill && guest != GuestSigstop && guest != GuestSigthr;
}

bool Blocked(int guest) {
    return Maskable(guest) && (blockedMask.load() & Bit(guest)) != 0;
}

bool DefaultIgnored(int guest) {
    return guest == 16 || guest == 20 || guest == 23 || guest == 28 || guest == 29;
}

bool Ignores(int guest, const GuestSigaction& action) {
    return action.handler == 1 || (action.handler == 0 && DefaultIgnored(guest));
}

bool Discards(int guest, const GuestSigaction& action) {
    return Ignores(guest, action) || (guest == GuestSigcont && action.handler <= 1);
}

void ClearPending(int guest) {
    if (!Maskable(guest)) return;
    auto& pending = Pending();
    pending.queued -= pending.instances[guest].size();
    pending.instances[guest].clear();
    pending.coalesced &= ~Bit(guest);
    pending.mask &= ~Bit(guest);
}

void Enqueue(int guest, int code, Pthread thread) {
    auto& pending = Pending();
    if (pending.queued >= MaxPendingInstances) pending.coalesced |= Bit(guest);
    else {
        pending.instances[guest].push_back({code, thread});
        ++pending.queued;
    }
    pending.mask |= Bit(guest);
    pending.changed.notify_all();
}

bool Visible(const PendingInstance& instance, Pthread self) {
    return instance.thread == nullptr || instance.thread == self;
}
int NativeSignal(int guest) {
    switch (guest) {
        case 2: return SIGINT;
        case 4: return SIGILL;
        case 6: return SIGABRT;
        case 8: return SIGFPE;
        case 11: return SIGSEGV;
        case 15: return SIGTERM;
        default: return 0;
    }
}
void Dispatch(int native) {
    int guest = 0;
    for (int candidate : {2, 4, 6, 8, 11, 15})
        if (NativeSignal(candidate) == native) { guest = candidate; break; }
    if (!guest) return;
#ifdef _WIN32
    // Preserve the guest's persistent registration across CRT delivery.
    std::signal(native, Dispatch);
#endif
    if ((blockedMask.load() & (1u << (guest - 1))) != 0) return;
    const auto callback = handlers[guest].load();
    if (reinterpret_cast<std::uintptr_t>(callback) <= 1) return;
    callback(guest);
    handledHere = handledHere + 1;
}
bool Delivered(const GuestSigaction& action) {
    return action.handler > 1 && (action.flags & SaSiginfo) == 0;
}
bool Install(int guest, const GuestSigaction& action) {
    const int native = NativeSignal(guest);
    if (!native) return true;
    const auto previous = handlers[guest].exchange(Delivered(action) ? reinterpret_cast<GuestHandler>(action.handler) : nullptr);
    auto hostHandler = action.handler == 1 ? SIG_IGN : Delivered(action) ? Dispatch : SIG_DFL;
    if (std::signal(native, hostHandler) == SIG_ERR) {
        handlers[guest].store(previous);
        return false;
    }
    return true;
}

int Send(int guest, int code, Pthread thread) {
    const int native = NativeSignal(guest);
    if (guest >= 1 && guest <= MaxSignal) {
        std::lock_guard lock(registration);
        if (Ignores(guest, dispositions[guest])) return 0;
        if (Blocked(guest)) {
            Enqueue(guest, code, thread);
            return 0;
        }
        if (native && dispositions[guest].handler > 1 && !Delivered(dispositions[guest])) throw std::runtime_error("raise: SA_SIGINFO handlers are not delivered");
    }
    if (!native) { *__error_nid_postfix() = GuestEinval; return -1; }
    const int result = std::raise(native);
    if (result) *__error_nid_postfix() = GuestEinval;
    return result ? -1 : 0;
}

void DeliverUnblocked(int guest, std::size_t instances) {
    GuestSigaction action{};
    {
        std::lock_guard lock(registration);
        action = dispositions[guest];
    }
    const int native = NativeSignal(guest);
    if (native && (action.handler == 0 || Delivered(action))) {
        for (std::size_t instance = 0; instance < instances; ++instance)
            if (std::raise(native) != 0) throw std::runtime_error("sigprocmask: raising the unblocked signal " + std::to_string(guest) + " failed");
        return;
    }
    if (action.handler == 0) {
        if (guest == GuestSigcont) return;
        if (guest == GuestSigtstp || guest == GuestSigttin || guest == GuestSigttou) throw std::runtime_error("sigprocmask: stopping the process for the unblocked signal " + std::to_string(guest) + " is not implemented");
        std::fprintf(stderr, "signal %d: unblocked with the default disposition; the process terminates\n", guest);
        std::fflush(stderr);
        std::_Exit(128 + guest);
    }
    throw std::runtime_error("sigprocmask: delivering the unblocked signal " + std::to_string(guest) + " to a guest handler is not implemented");
}

std::uint32_t VisibleSignals(const PendingSignals& pending, Pthread self) {
    std::uint32_t visible = pending.coalesced;
    for (int guest = 1; guest <= MaskedSignals; ++guest)
        for (const auto& instance : pending.instances[guest])
            if (Visible(instance, self)) { visible |= Bit(guest); break; }
    return visible;
}

int TakePending(PendingSignals& pending, int guest, Pthread self) {
    auto& instances = pending.instances[guest];
    int code = 0;
    if ((pending.coalesced & Bit(guest)) != 0) pending.coalesced &= ~Bit(guest);
    else {
        auto chosen = instances.end();
        for (auto it = instances.begin(); it != instances.end(); ++it) {
            if (!Visible(*it, self)) continue;
            if (it->thread == self) { chosen = it; break; }
            if (chosen == instances.end()) chosen = it;
        }
        code = chosen->code;
        instances.erase(chosen);
        --pending.queued;
    }
    if (instances.empty() && (pending.coalesced & Bit(guest)) == 0) pending.mask &= ~Bit(guest);
    return code;
}

int WaitPending(const GuestSignalSet& set, const KernelTimespec* timeout, int* taken, int* code) {
    const std::uint32_t waitset = set.bits[0] & ~(Bit(GuestSigkill) | Bit(GuestSigstop) | Bit(GuestSigthr));
    const bool validTimeout = timeout == nullptr || (timeout->tv_nsec >= 0 && timeout->tv_nsec < 1000000000);
    auto deadline = std::chrono::steady_clock::now();
    if (timeout != nullptr && validTimeout) {
        constexpr std::int64_t limit = 4000000000;
        const auto seconds = timeout->tv_sec > limit ? limit : timeout->tv_sec < -limit ? -limit : timeout->tv_sec;
        deadline += std::chrono::seconds(seconds) + std::chrono::nanoseconds(timeout->tv_nsec);
    }
    const Pthread self = scePthreadSelf();
    std::unique_lock lock(registration);
    auto& pending = Pending();
    for (;;) {
        if (const std::uint32_t ready = VisibleSignals(pending, self) & waitset) {
            const int guest = std::countr_zero(ready) + 1;
            if (guest == GuestSigcont && dispositions[guest].handler <= 1) {
                ClearPending(guest);
                continue;
            }
            if ((guest == GuestSigtstp || guest == GuestSigttin || guest == GuestSigttou) && dispositions[guest].handler == 0)
                throw std::runtime_error("sigtimedwait: stopping the process for the pending signal " + std::to_string(guest) + " is not implemented");
            *taken = guest;
            *code = TakePending(pending, guest, self);
            return 0;
        }
        if (timeout == nullptr) {
            pending.changed.wait(lock);
            continue;
        }
        if (!validTimeout) return GuestEinval;
        if (std::chrono::steady_clock::now() >= deadline) return GuestEagain;
        pending.changed.wait_until(lock, deadline);
    }
}

void FillInfo(void* info, int guest, int code) {
    if (info == nullptr) return;
    GuestSiginfo result{};
    result.signo = guest;
    result.code = code;
    result.pid = getpid_nid_postfix();
    result.uid = static_cast<unsigned int>(getuid_nid_postfix());
    *static_cast<GuestSiginfo*>(info) = result;
}
}

namespace {
constexpr int GuestSigalrm = 14;
struct AlarmState {
    std::mutex lock;
    std::condition_variable changed;
    std::optional<std::chrono::steady_clock::time_point> deadline;
    bool threadStarted = false;
};

AlarmState& Alarms() {
    static auto* state = new AlarmState();
    return *state;
}

void ExpireAlarm() {
    std::uintptr_t handler = 0;
    {
        std::lock_guard lock(registration);
        if (Ignores(GuestSigalrm, dispositions[GuestSigalrm])) return;
        if (Blocked(GuestSigalrm)) {
            Enqueue(GuestSigalrm, SiKernel, nullptr);
            return;
        }
        handler = dispositions[GuestSigalrm].handler;
    }
    if (handler == 0) {
        std::fprintf(stderr, "SIGALRM: the alarm expired with the default disposition; the process terminates\n");
        std::fflush(stderr);
        std::_Exit(128 + GuestSigalrm);
    }
    throw std::runtime_error("alarm: delivering SIGALRM to a guest handler is not implemented");
}

void RunAlarms() {
    auto& alarms = Alarms();
    std::unique_lock lock(alarms.lock);
    for (;;) {
        if (!alarms.deadline) {
            alarms.changed.wait(lock);
            continue;
        }
        const auto deadline = *alarms.deadline;
        if (alarms.changed.wait_until(lock, deadline) != std::cv_status::timeout || alarms.deadline != deadline) continue;
        alarms.deadline.reset();
        lock.unlock();
        ExpireAlarm();
        lock.lock();
    }
}
}

extern "C" unsigned int APS5_VABI GuestAlarm_nid_no_patch(unsigned int seconds) {
    auto& alarms = Alarms();
    std::lock_guard lock(alarms.lock);
    const auto now = std::chrono::steady_clock::now();
    unsigned int remaining = 0;
    if (alarms.deadline && *alarms.deadline > now) {
        const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(*alarms.deadline - now).count();
        remaining = static_cast<unsigned int>((micros + 999999) / 1000000);
    }
    if (seconds == 0) alarms.deadline.reset();
    else alarms.deadline = now + std::chrono::seconds(seconds);
    if (!alarms.threadStarted) {
        std::thread(RunAlarms).detach();
        alarms.threadStarted = true;
    }
    alarms.changed.notify_all();
    return remaining;
}

struct GuestItimerval {
    KernelTimeval interval;
    KernelTimeval value;
};
static_assert(sizeof(GuestItimerval) == 32 && offsetof(GuestItimerval, value) == 16);

extern "C" int APS5_VABI getitimer_nid_postfix(int which, GuestItimerval* output) {
    if (which < 0 || which > 2) {
        *__error_nid_postfix() = 22;
        return -1;
    }
    if (which != 0) throw std::runtime_error("getitimer: CPU interval timers are not implemented");
    if (output == nullptr) {
        *__error_nid_postfix() = 14;
        return -1;
    }
    GuestItimerval result{};
    auto& alarms = Alarms();
    {
        std::lock_guard lock(alarms.lock);
        const auto now = std::chrono::steady_clock::now();
        if (alarms.deadline && *alarms.deadline > now) {
            const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(*alarms.deadline - now).count();
            result.value.tv_sec = micros / 1000000;
            result.value.tv_usec = micros % 1000000;
        }
    }
    *output = result;
    return 0;
}

struct GuestStack {
    void* sp;
    std::size_t size;
    int flags;
};
static_assert(sizeof(GuestStack) == 24 && offsetof(GuestStack, flags) == 16);
namespace {
constexpr int SsDisable = 4;
constexpr std::size_t MinSignalStackSize = 2048;
thread_local GuestStack alternateStack{nullptr, 0, SsDisable};
}

extern "C" {
GuestHandler APS5_VABI signal_nid_postfix(int guest, GuestHandler handler) {
    const auto invalid = reinterpret_cast<GuestHandler>(static_cast<std::uintptr_t>(-1));
    if (guest < 1 || guest > MaxSignal || ((guest == GuestSigkill || guest == GuestSigstop) && handler != nullptr)) { *__error_nid_postfix() = 22; return invalid; }
    std::lock_guard lock(registration);
    const GuestSigaction action{reinterpret_cast<std::uintptr_t>(handler), SaRestart, {}};
    if (!Install(guest, action)) { *__error_nid_postfix() = 22; return invalid; }
    const auto previous = reinterpret_cast<GuestHandler>(dispositions[guest].handler);
    dispositions[guest] = action;
    if (Discards(guest, action)) ClearPending(guest);
    return previous;
}
int APS5_VABI sigaction_nid_postfix(int guest, const GuestSigaction* action, GuestSigaction* previous) {
    if (guest < 1 || guest > MaxSignal) { *__error_nid_postfix() = 22; return -1; }
    if (action && (guest == GuestSigkill || guest == GuestSigstop) && action->handler != 0) { *__error_nid_postfix() = 22; return -1; }
    std::lock_guard lock(registration);
    const GuestSigaction old = dispositions[guest];
    if (action) {
        if (!Install(guest, *action)) { *__error_nid_postfix() = 22; return -1; }
        dispositions[guest] = *action;
        if (Discards(guest, *action)) ClearPending(guest);
    }
    if (previous) *previous = old;
    return 0;
}
int APS5_VABI raise_nid_postfix(int guest) {
    return Send(guest, SiLwp, scePthreadSelf());
}
int APS5_VABI kill_nid_postfix(int pid, int guest) {
    if (guest < 0 || guest > MaxSignal) { *__error_nid_postfix() = 22; return -1; }
    const int self = getpid_nid_postfix();
    if (pid != self && pid != 0 && pid != -self) { *__error_nid_postfix() = 3; return -1; }
    return guest == 0 ? 0 : Send(guest, SiUser, nullptr);
}
int APS5_VABI pthread_kill_nid_postfix(Pthread thread, int guest) {
    if (guest < 0 || guest > MaxSignal) return PosixThread::GUEST_EINVAL;
    if (thread == nullptr) return PosixThread::GUEST_ESRCH;
    if (guest == 0) return 0;
    if (thread != scePthreadSelf()) NotImplemented_nid_no_patch(("pthread_kill signal " + std::to_string(guest) + " to another thread").c_str());
    return Send(guest, SiLwp, thread) == 0 ? 0 : *__error_nid_postfix();
}
int APS5_VABI sigaltstack_nid_postfix(const GuestStack* stack, GuestStack* previous) {
    GuestStack replacement = alternateStack;
    if (stack != nullptr) {
        if ((stack->flags & ~SsDisable) != 0) { *__error_nid_postfix() = 22; return -1; }
        if (stack->flags & SsDisable) replacement.flags = SsDisable;
        else if (stack->size < MinSignalStackSize) { *__error_nid_postfix() = 12; return -1; }
        else replacement = {stack->sp, stack->size, 0};
    }
    if (previous != nullptr) *previous = alternateStack;
    alternateStack = replacement;
    return 0;
}
int APS5_VABI _sigprocmask_nid_postfix(int how, const GuestSignalSet* set, GuestSignalSet* previousSet) {
    std::uint32_t unblocked = 0;
    std::size_t instances[MaskedSignals + 1]{};
    {
        std::lock_guard lock(registration);
        if (previousSet != nullptr) {
            previousSet->bits[0] = blockedMask.load();
            previousSet->bits[1] = 0;
            previousSet->bits[2] = 0;
            previousSet->bits[3] = 0;
        }
        if (set != nullptr) {
            switch (how) {
                case 1: blockedMask.fetch_or(set->bits[0]); break;
                case 2: blockedMask.fetch_and(~set->bits[0]); break;
                case 3: blockedMask.store(set->bits[0]); break;
                default: throw std::invalid_argument("_sigprocmask: invalid how");
            }
            auto& pending = Pending();
            unblocked = pending.mask & ~blockedMask.load();
            for (int guest = 1; guest <= MaskedSignals; ++guest) {
                if ((unblocked & Bit(guest)) == 0) continue;
                instances[guest] = pending.instances[guest].size() + ((pending.coalesced & Bit(guest)) != 0 ? 1 : 0);
                ClearPending(guest);
            }
        }
    }
    while (unblocked != 0) {
        const int guest = std::countr_zero(unblocked) + 1;
        unblocked &= ~Bit(guest);
        DeliverUnblocked(guest, instances[guest]);
    }
    return 0;
}

int APS5_VABI sigprocmask_nid_postfix(int how, const void* set, void* previousSet) {
    return _sigprocmask_nid_postfix(how, static_cast<const GuestSignalSet*>(set),
                                    static_cast<GuestSignalSet*>(previousSet));
}

int APS5_VABI pthread_sigmask_nid_postfix(int how, const GuestSignalSet* set, GuestSignalSet* previousSet) {
    if (set != nullptr && (how < 1 || how > 3)) return 22;
    return _sigprocmask_nid_postfix(how, set, previousSet);
}

int APS5_VABI sigtimedwait_nid_postfix(const GuestSignalSet* set, void* info, const void* timeout) {
    if (set == nullptr) { *__error_nid_postfix() = GuestEfault; return -1; }
    int taken = 0;
    int code = 0;
    if (const int error = WaitPending(*set, static_cast<const KernelTimespec*>(timeout), &taken, &code)) {
        *__error_nid_postfix() = error;
        return -1;
    }
    FillInfo(info, taken, code);
    return taken;
}

int APS5_VABI sigwaitinfo_nid_postfix(const GuestSignalSet* set, void* info) {
    return sigtimedwait_nid_postfix(set, info, nullptr);
}

int APS5_VABI sigwait_nid_postfix(const GuestSignalSet* set, int* received) {
    if (set == nullptr) return GuestEfault;
    int taken = 0;
    int code = 0;
    if (const int error = WaitPending(*set, nullptr, &taken, &code)) return error;
    if (received == nullptr) return GuestEfault;
    *received = taken;
    return 0;
}

int APS5_VABI pause_nid_postfix(void) {
#ifdef _WIN32
    NotImplemented_nid_no_patch("pause: waiting for a delivered signal");
    return -1;
#else
    const std::sig_atomic_t before = handledHere;
    while (handledHere == before) ::pause();
    *__error_nid_postfix() = GuestEintr;
    return -1;
#endif
}
}

extern "C" {

int APS5_VABI _is_signal_return_nid_postfix(std::uint64_t programCounter) {
    (void)programCounter;
    return 0;
}

}
