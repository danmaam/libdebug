//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <nanobind/nanobind.h>
#include <nanobind/stl/bind_vector.h>
#include <nanobind/stl/list.h>
#include <nanobind/stl/function.h>

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#define INSTRUCTION_POINTER(regs) (regs.rip)
#define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFFFFFFFFFF00) | 0xCC)
#define BREAKPOINT_SIZE 1
#define IS_SW_BREAKPOINT(instruction) (instruction == 0xCC)
#define IS_RET_INSTRUCTION(instruction) (instruction == 0xC3 || instruction == 0xCB || instruction == 0xC2 || instruction == 0xCA)

// X86_64 Architecture specific
int IS_CALL_INSTRUCTION(uint8_t* instr)
{
    // Check for direct CALL (E8 xx xx xx xx)
    if (instr[0] == (uint8_t)0xE8) {
        return 1; // It's a CALL
    }
    
    // Check for indirect CALL using ModR/M (FF /2)
    if (instr[0] == (uint8_t)0xFF) {
        // Extract ModR/M byte
        uint8_t modRM = (uint8_t)instr[1];
        uint8_t reg = (modRM >> 3) & 7; // Middle three bits

        if (reg == 2) {
            return 1; // It's a CALL
        }
    }

    return 0; // Not a CALL
}

namespace nb = nanobind;
using namespace nb::literals;

struct user_regs
{
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
    unsigned long fs_base;
    unsigned long gs_base;
    unsigned long ds;
    unsigned long es;
    unsigned long fs;
    unsigned long gs;
};

struct Thread
{
    pid_t tid;
    struct user_regs regs;
    int signal_to_deliver;
};

struct SoftwareBreakpoint
{
    uintptr_t address;
    uint64_t original_instruction;
    uint64_t patched_instruction;
    bool enabled;
};

struct HardwareBreakpoint
{
    uintptr_t address;
    int index;
    int type;
    bool enabled;
};

struct SyscallHook
{
    int syscall_number;
    bool enabled;
};

struct SignalHook
{
    int signal_number;
    bool enabled;
};

using WaitStatus = std::pair<pid_t, int>;
using WaitVector = std::vector<WaitStatus>;

class Ptrace
{

private:
    pid_t pid;
    size_t syscall_hook_count;
    bool syscall_hooks_enabled;

    std::list<Thread> threads;
    std::list<SoftwareBreakpoint> sw_breakpoints;
    std::list<HardwareBreakpoint> hw_breakpoints;
    std::list<SyscallHook> syscall_hooks;
    std::list<SignalHook> signal_hooks;

    std::function<void(pid_t, uintptr_t)> breakpoint_resolver;
    std::function<void(pid_t, int)> syscall_hook_resolver;
    std::function<void(pid_t, int)> signal_hook_resolver;

    int prepare_for_run()
    {
        int status = 0;

        // flush any register changes
        for (auto const& thread : threads)
            if (ptrace(PTRACE_SETREGS, thread.tid, 0, &thread.regs))
                throw std::runtime_error(strerror(errno));

        // iterate over all the threads and check if any of them has hit a software
        // breakpoint
        bool hit;
        for (auto const& thread : threads) {
            hit = false;
            uintptr_t ip = INSTRUCTION_POINTER(thread.regs);

            for (auto const& bp : sw_breakpoints) {
                if (bp.address == ip) {
                    hit = true;
                    break;
                }
            }

            if (hit) {
                // step over the breakpoint
                if (ptrace(PTRACE_SINGLESTEP, thread.tid, 0, 0))
                    return -1;

                // wait for the thread to stop
                waitpid(thread.tid, &status, 0);

                // status == 4991 ==> (WIFSTOPPED(status) && WSTOPSIG(status) ==
                // SIGSTOP) this should happen only if threads are involved
                if (status == 4991) {
                    ptrace(PTRACE_SINGLESTEP, thread.tid, NULL, NULL);
                    waitpid(thread.tid, &status, 0);
                }
            }
        }

        // reset any software breakpoint
        for (auto const& bp : sw_breakpoints)
            if (bp.enabled)
                ptrace(PTRACE_POKEDATA, pid, bp.address, bp.patched_instruction);

        return status;
    }


public:

    Ptrace() {
        pid = 0;
        syscall_hook_count = 0;
        syscall_hooks_enabled = false;

        breakpoint_resolver = nullptr;
        syscall_hook_resolver = nullptr;
        signal_hook_resolver = nullptr;
    }

    user_regs* register_thread(pid_t tid)
    {
        // Verify if the thread is already registered
        for (auto& thread : threads)
            if (thread.tid == tid)
                return &thread.regs;

        if (!pid)
            pid = tid;

        Thread new_thread;
        new_thread.tid = tid;
        new_thread.signal_to_deliver = 0;

        // let's attempt to read the registers of the thread
        ptrace(PTRACE_GETREGS, tid, 0, &new_thread.regs);

        threads.push_front(new_thread);

        return &threads.front().regs;
    }

    void unregister_thread(pid_t tid)
    {
        for (auto it = threads.begin(); it != threads.end(); ++it) {
            if (it->tid == tid) {
                threads.erase(it);
                return;
            }
        }

        throw std::runtime_error("Thread not found");
    }

    void deliver_signal(pid_t tid, int signal)
    {
        for (auto& thread : threads) {
            if (thread.tid == tid) {
                thread.signal_to_deliver = signal;
                return;
            }
        }

        throw std::runtime_error("Thread not found");
    }

    void ptrace_attach(pid_t pid)
    {
        if (ptrace(PTRACE_ATTACH, pid, 0, 0))
            throw std::runtime_error(strerror(errno));

        this->pid = pid;
    }

    void ptrace_detach_for_kill()
    {
        // note that the order is important: the main thread must be detached last
        for (auto& thread : threads) {
            // let's attempt to read the registers of the thread
            if (ptrace(PTRACE_GETREGS, thread.tid, 0, &thread.regs)) {
                // if we can't read the registers, the thread is probably still running
                // ensure that the thread is stopped
                tgkill(pid, thread.tid, SIGSTOP);

                // wait for it to stop
                waitpid(thread.tid, NULL, 0);
            }

            // detach the thread
            ptrace(PTRACE_DETACH, thread.tid, 0, 0);

            // kill it
            tgkill(pid, thread.tid, SIGKILL);
        }

        // final wait to remove the zombies
        waitpid(pid, NULL, 0);
    }

    void ptrace_detach_for_migration()
    {
        // note that the order is important: the main thread must be detached last
        for (auto& thread : threads) {
            // let's attempt to read the registers of the thread
            if (ptrace(PTRACE_SETREGS, thread.tid, 0, &thread.regs)) {
                // if we can't read the registers, the thread is probably still running
                // ensure that the thread is stopped
                tgkill(pid, thread.tid, SIGSTOP);

                // wait for it to stop
                waitpid(thread.tid, NULL, 0);

                // set the registers again
                ptrace(PTRACE_SETREGS, thread.tid, 0, &thread.regs);
            }

            // detach the thread
            if (ptrace(PTRACE_DETACH, thread.tid, 0, 0))
                throw std::runtime_error(strerror(errno));
        }
    }

    void ptrace_reattach_from_gdb()
    {
        for (auto& thread : threads) {
            if (ptrace(PTRACE_ATTACH, thread.tid, 0, 0))
                throw std::runtime_error(strerror(errno));

            if (ptrace(PTRACE_GETREGS, thread.tid, 0, &thread.regs))
                throw std::runtime_error(strerror(errno));
        }
    }

    void ptrace_detach_and_cont()
    {
        this->ptrace_detach_for_migration();

        // continue the process
        kill(pid, SIGCONT);
    }

    void ptrace_set_options()
    {
        int options = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD |
                    PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;

        if (ptrace(PTRACE_SETOPTIONS, pid, NULL, options))
            throw std::runtime_error(strerror(errno));
    }

    uint64_t ptrace_peekdata(uintptr_t address)
    {
        errno = 0;

        uint64_t data = ptrace(PTRACE_PEEKDATA, pid, address, 0);

        if (errno != 0)
            throw std::runtime_error(strerror(errno));

        return data;
    }

    uint64_t ptrace_pokedata(uintptr_t address, uint64_t data)
    {
        return ptrace(PTRACE_POKEDATA, pid, address, data);
    }

    uint64_t ptrace_peekuser(pid_t tid, uintptr_t offset)
    {
        errno = 0;

        uint64_t data = ptrace(PTRACE_PEEKUSER, tid, offset, 0);

        if (errno != 0)
            throw std::runtime_error(strerror(errno));

        return data;
    }

    uint64_t ptrace_pokeuser(pid_t tid, uintptr_t offset, uint64_t data)
    {
        return ptrace(PTRACE_POKEUSER, tid, offset, data);
    }

    uint64_t ptrace_geteventmsg(pid_t tid)
    {
        uint64_t data = 0;

        ptrace(PTRACE_GETEVENTMSG, tid, 0, &data);

        return data;
    }

    uint64_t singlestep(pid_t tid)
    {
        // flush any register changes
        int signal_to_deliver = 0;
        for (auto& thread : threads) {
            if (ptrace(PTRACE_SETREGS, thread.tid, 0, &thread.regs))
                throw std::runtime_error(strerror(errno));

            if (thread.tid == tid) {
                signal_to_deliver = thread.signal_to_deliver;
                thread.signal_to_deliver = 0;
            }
        }

        return ptrace(PTRACE_SINGLESTEP, tid, 0, signal_to_deliver);
    }

    uint64_t step_until(pid_t tid, uintptr_t address, int max_steps)
    {
        // flush any register changes
        Thread &stepping_thread = threads.front();
        
        for (auto& thread : threads) {
            if (ptrace(PTRACE_SETREGS, thread.tid, 0, &thread.regs))
                throw std::runtime_error(strerror(errno));

            if (thread.tid == tid)
                stepping_thread = thread;
        }

        if (stepping_thread.tid != tid)
            throw std::runtime_error("Could not find thread");

        int count = 0, status = 0;
        uintptr_t previous_rip = 0;

        if (!stepping_thread.tid)
            throw std::runtime_error("Thread not found");

        while (max_steps == -1 || count < max_steps) {
            if (ptrace(PTRACE_SINGLESTEP, stepping_thread.tid, 0, 0))
                return -1;
            
            // wait for the thread to stop
            waitpid(stepping_thread.tid, &status, 0);

            previous_rip = INSTRUCTION_POINTER(stepping_thread.regs);

            ptrace(PTRACE_GETREGS, stepping_thread.tid, 0, &stepping_thread.regs);

            if (INSTRUCTION_POINTER(stepping_thread.regs) == address)
                return 0;

            if (INSTRUCTION_POINTER(stepping_thread.regs) == previous_rip)
                continue;

            ++count;
        }

        return 0;
    }

    int cont_all_and_set_bps()
    {
        int status = prepare_for_run();

        // continue all threads
        for (auto& thread : threads) {
            if (ptrace(syscall_hooks_enabled ? PTRACE_SYSCALL : PTRACE_CONT, thread.tid, 0, thread.signal_to_deliver))
                throw std::runtime_error(strerror(errno));

            thread.signal_to_deliver = 0;
        }

        return status;
    }

    WaitVector wait_all_and_update_regs()
    {
        WaitVector wait_statuses;

        int status;
        pid_t tid = waitpid(-getpgid(pid), &status, 0);

        if (tid == -1)
            throw std::runtime_error(strerror(errno));

        wait_statuses.push_back({tid, status});

        // we must interrupt all the other threads with a SIGSTOP
        for (auto& thread : threads) {
            if (thread.tid != tid) {
                // let's attempt to read the registers of the thread
                if (ptrace(PTRACE_GETREGS, thread.tid, 0, &thread.regs)) {
                    // if we can't read the registers, the thread is probably still running
                    // ensure that the thread is stopped
                    tgkill(pid, thread.tid, SIGSTOP);

                    // wait for it to stop
                    int temp_status;
                    pid_t temp_tid = waitpid(thread.tid, &temp_status, 0);

                    // register the wait status
                    wait_statuses.insert(wait_statuses.begin(), {temp_tid, temp_status});
                }
            }
        }

        // keep polling but without blocking
        while (true) {
            tid = waitpid(-getpgid(pid), &status, WNOHANG);

            if (tid <= 0)
                break;

            wait_statuses.insert(wait_statuses.begin(), {tid, status});
        }

        // update the registers of the threads
        for (auto& thread : threads)
            ptrace(PTRACE_GETREGS, thread.tid, 0, &thread.regs);

        // restore the software sw_breakpoints
        for (auto const& bp : sw_breakpoints)
            if (bp.enabled)
                ptrace(PTRACE_POKEDATA, pid, bp.address, bp.original_instruction);

        return wait_statuses;
    }

    void register_breakpoint(uintptr_t address)
    {
        SoftwareBreakpoint bp;
        bp.address = address;
        bp.original_instruction = ptrace_peekdata(address);
        bp.patched_instruction = INSTALL_BREAKPOINT(bp.original_instruction);
        bp.enabled = true;

        ptrace_pokedata(address, bp.patched_instruction);

        // sw_breakpoints should be inserted ordered by address, increasing
        // This is important, because we don't want a breakpoint patching another
        // breakpoint
        auto it = sw_breakpoints.begin();
        while (it != sw_breakpoints.end() && it->address < address)
            ++it;
        sw_breakpoints.insert(it, bp);
    }

    void unregister_breakpoint(uintptr_t address)
    {
        for (auto it = sw_breakpoints.begin(); it != sw_breakpoints.end(); ++it) {
            if (it->address == address) {
                if (it->enabled)
                    ptrace_pokedata(address, it->original_instruction);

                sw_breakpoints.erase(it);
                break;
            }
        }
    }

    void enable_breakpoint(uintptr_t address)
    {
        for (auto& bp : sw_breakpoints) {
            if (bp.address == address) {
                bp.enabled = true;
                break;
            }
        }
    }

    void disable_breakpoint(uintptr_t address)
    {
        for (auto& bp : sw_breakpoints) {
            if (bp.address == address) {
                bp.enabled = false;
                break;
            }
        }
    }

    int exact_finish(pid_t tid)
    {
        int status = prepare_for_run();

        Thread &stepping_thread = threads.front();
        for (auto& thread : threads) {
            if (thread.tid == tid) {
                stepping_thread = thread;
                break;
            }
        }

        if (stepping_thread.tid != tid)
            throw std::runtime_error("Could not find thread");

        uintptr_t previous_ip, current_ip;
        uint64_t opcode_window, first_opcode_byte;

        int nested_call_counter = 1;

        do {
            if (ptrace(PTRACE_SINGLESTEP, stepping_thread.tid, 0, 0))
                return -1;

            // wait for the thread to stop
            waitpid(stepping_thread.tid, &status, 0);

            previous_ip = INSTRUCTION_POINTER(stepping_thread.regs);

            ptrace(PTRACE_GETREGS, stepping_thread.tid, 0, &stepping_thread.regs);

            current_ip = INSTRUCTION_POINTER(stepping_thread.regs);

            // Get value at current instruction pointer
            opcode_window = ptrace(PTRACE_PEEKDATA, pid, current_ip, NULL);
            first_opcode_byte = opcode_window & 0xFF;

            // if the instruction pointer didn't change, we return
            // because we hit a hardware breakpoint
            // we do the same if we hit a software breakpoint
            if (current_ip == previous_ip || IS_SW_BREAKPOINT(first_opcode_byte))
                goto cleanup;

            // If we hit a call instruction, we increment the counter
            if (IS_CALL_INSTRUCTION((uint8_t*) &opcode_window))
                nested_call_counter++;
            else if (IS_RET_INSTRUCTION(first_opcode_byte))
                nested_call_counter--;

        } while (nested_call_counter > 0);

        // we are in a return instruction, do the last step
        if (ptrace(PTRACE_SINGLESTEP, stepping_thread.tid, 0, 0))
            return -1;

        // wait for the thread to stop
        waitpid(stepping_thread.tid, &status, 0);

        // update the registers
        ptrace(PTRACE_GETREGS, stepping_thread.tid, 0, &stepping_thread.regs);
    
    cleanup:
        // restore the software sw_breakpoints
        for (auto& bp : sw_breakpoints)
            if (bp.enabled)
                if (ptrace(PTRACE_POKEDATA, pid, bp.address, bp.original_instruction))
                    throw std::runtime_error(strerror(errno));

        return status;
    }

    void cleanup()
    {
        threads.clear();
        sw_breakpoints.clear();
        pid = 0;
    }

    void set_syscall_hooks_enabled(bool enabled)
    {
        syscall_hooks_enabled = enabled;
    }

    void set_breakpoint_resolver(std::function<void(pid_t, uintptr_t)> resolver)
    {
        breakpoint_resolver = resolver;
    }

    void set_syscall_hook_resolver(std::function<void(pid_t, int)> resolver)
    {
        syscall_hook_resolver = resolver;
    }

    void set_signal_hook_resolver(std::function<void(pid_t, int)> resolver)
    {
        signal_hook_resolver = resolver;
    }

};

NB_MODULE(_ptrace_cffi, m) {
    nb::class_<user_regs>(m, "user_regs")
        .def_rw("r15", &user_regs::r15)
        .def_rw("r14", &user_regs::r14)
        .def_rw("r13", &user_regs::r13)
        .def_rw("r12", &user_regs::r12)
        .def_rw("rbp", &user_regs::rbp)
        .def_rw("rbx", &user_regs::rbx)
        .def_rw("r11", &user_regs::r11)
        .def_rw("r10", &user_regs::r10)
        .def_rw("r9", &user_regs::r9)
        .def_rw("r8", &user_regs::r8)
        .def_rw("rax", &user_regs::rax)
        .def_rw("rcx", &user_regs::rcx)
        .def_rw("rdx", &user_regs::rdx)
        .def_rw("rsi", &user_regs::rsi)
        .def_rw("rdi", &user_regs::rdi)
        .def_rw("orig_rax", &user_regs::orig_rax)
        .def_rw("rip", &user_regs::rip)
        .def_rw("cs", &user_regs::cs)
        .def_rw("eflags", &user_regs::eflags)
        .def_rw("rsp", &user_regs::rsp)
        .def_rw("ss", &user_regs::ss)
        .def_rw("fs_base", &user_regs::fs_base)
        .def_rw("gs_base", &user_regs::gs_base)
        .def_rw("ds", &user_regs::ds)
        .def_rw("es", &user_regs::es)
        .def_rw("fs", &user_regs::fs)
        .def_rw("gs", &user_regs::gs);

    nb::bind_vector<WaitVector>(m, "WaitVector");

    nb::class_<Ptrace>(m, "Ptrace")
        .def(nb::init<>())
        .def("ptrace_attach", &Ptrace::ptrace_attach, nb::arg("pid").noconvert())
        .def("ptrace_detach_for_kill", &Ptrace::ptrace_detach_for_kill)
        .def("ptrace_detach_for_migration", &Ptrace::ptrace_detach_for_migration)
        .def("ptrace_reattach_from_gdb", &Ptrace::ptrace_reattach_from_gdb)
        .def("ptrace_detach_and_cont", &Ptrace::ptrace_detach_and_cont)
        .def("register_thread", &Ptrace::register_thread, nb::arg("tid").noconvert(), nb::rv_policy::reference)
        .def("unregister_thread", &Ptrace::unregister_thread, nb::arg("tid").noconvert())
        .def("deliver_signal", &Ptrace::deliver_signal, nb::arg("tid").noconvert(), nb::arg("signal"))
        .def("ptrace_set_options", &Ptrace::ptrace_set_options)
        .def("ptrace_peekdata", &Ptrace::ptrace_peekdata, nb::arg("address").noconvert())
        .def("ptrace_pokedata", &Ptrace::ptrace_pokedata, nb::arg("address").noconvert(), nb::arg("data").noconvert())
        .def("ptrace_peekuser", &Ptrace::ptrace_peekuser, nb::arg("tid").noconvert(), nb::arg("offset").noconvert())
        .def("ptrace_pokeuser", &Ptrace::ptrace_pokeuser, nb::arg("tid").noconvert(), nb::arg("offset").noconvert(), nb::arg("data").noconvert())
        .def("ptrace_geteventmsg", &Ptrace::ptrace_geteventmsg, nb::arg("tid").noconvert())
        .def("singlestep", &Ptrace::singlestep, nb::arg("tid").noconvert())
        .def("step_until", &Ptrace::step_until, nb::arg("tid").noconvert(), nb::arg("address").noconvert(), nb::arg("max_steps").noconvert(), nb::call_guard<nb::gil_scoped_release>())
        .def("cont_all_and_set_bps", &Ptrace::cont_all_and_set_bps, nb::call_guard<nb::gil_scoped_release>())
        .def("wait_all_and_update_regs", &Ptrace::wait_all_and_update_regs, nb::call_guard<nb::gil_scoped_release>())
        .def("register_breakpoint", &Ptrace::register_breakpoint, nb::arg("address").noconvert())
        .def("unregister_breakpoint", &Ptrace::unregister_breakpoint, nb::arg("address").noconvert())
        .def("enable_breakpoint", &Ptrace::enable_breakpoint, nb::arg("address").noconvert())
        .def("disable_breakpoint", &Ptrace::disable_breakpoint, nb::arg("address").noconvert())
        .def("exact_finish", &Ptrace::exact_finish, nb::call_guard<nb::gil_scoped_release>())
        .def("cleanup", &Ptrace::cleanup)
        .def("set_syscall_hooks_enabled", &Ptrace::set_syscall_hooks_enabled)
        .def("set_breakpoint_resolver", &Ptrace::set_breakpoint_resolver)
        .def("set_syscall_hook_resolver", &Ptrace::set_syscall_hook_resolver)
        .def("set_signal_hook_resolver", &Ptrace::set_signal_hook_resolver);

    nb::set_leak_warnings(false);
}
