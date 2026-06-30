// SPDX-FileCopyrightText: Copyright (c) 2022 merryhime
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <new>
#include <stdexcept>

#if defined(_WIN32)
#    define NOMINMAX
#    include <windows.h>
#elif defined(__APPLE__)
#    include <libkern/OSCacheControl.h>
#    include <pthread.h>
#    include <sys/mman.h>
#    include <TargetConditionals.h>
#    include <unistd.h>
#elif !defined(__SWITCH__)
#    include <sys/mman.h>
#endif

#if defined(__SWITCH__)
// AZAHAR_SWITCH_DUAL_ALIAS_JIT_V3
// Keep libnx headers outside Oaknut/Dynarmic translation units. libnx defines a
// global u128 type which conflicts with Azahar's common_types.h alias.
extern "C" {
void* azahar_switch_dynarmic_jit_create(std::size_t size, std::uint32_t** rw,
                                        std::uint32_t** rx) noexcept;
bool azahar_switch_dynarmic_jit_begin_write(void* handle) noexcept;
bool azahar_switch_dynarmic_jit_end_write(void* handle, std::size_t offset,
                                          std::size_t size) noexcept;
void azahar_switch_dynarmic_jit_destroy(void* handle) noexcept;
}
#endif

namespace oaknut {

class CodeBlock {
public:
    explicit CodeBlock(std::size_t size) : m_size(size) {
#if defined(__SWITCH__)
        m_jit_handle =
            azahar_switch_dynarmic_jit_create(size, &m_write_memory, &m_memory);
        if (m_jit_handle == nullptr || m_write_memory == nullptr || m_memory == nullptr) {
            throw std::bad_alloc{};
        }
        m_dirty_begin = m_size;
        m_dirty_end = 0;
#elif defined(_WIN32)
        m_memory = static_cast<std::uint32_t*>(
            VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
#elif defined(__APPLE__)
#    if TARGET_OS_IPHONE
        m_memory = static_cast<std::uint32_t*>(
            mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0));
#    else
        m_memory = static_cast<std::uint32_t*>(mmap(nullptr, size,
                                                   PROT_READ | PROT_WRITE | PROT_EXEC,
                                                   MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0));
#    endif
#elif defined(__NetBSD__)
        m_memory = static_cast<std::uint32_t*>(
            mmap(nullptr, size, PROT_MPROTECT(PROT_READ | PROT_WRITE | PROT_EXEC),
                 MAP_ANON | MAP_PRIVATE, -1, 0));
#elif defined(__OpenBSD__)
        m_memory = static_cast<std::uint32_t*>(
            mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0));
#else
        m_memory = static_cast<std::uint32_t*>(
            mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_ANON | MAP_PRIVATE, -1, 0));
#endif

#if !defined(__SWITCH__)
#    if defined(_WIN32)
        if (m_memory == nullptr) {
#    else
        if (m_memory == MAP_FAILED) {
#    endif
            m_memory = nullptr;
            throw std::bad_alloc{};
        }
#endif
    }

    ~CodeBlock() {
#if defined(__SWITCH__)
        if (m_jit_handle != nullptr) {
            azahar_switch_dynarmic_jit_destroy(m_jit_handle);
            m_jit_handle = nullptr;
            m_write_memory = nullptr;
            m_memory = nullptr;
        }
#else
        if (m_memory == nullptr) {
            return;
        }
#    if defined(_WIN32)
        VirtualFree(static_cast<void*>(m_memory), 0, MEM_RELEASE);
#    else
        munmap(m_memory, m_size);
#    endif
#endif
    }

    CodeBlock(const CodeBlock&) = delete;
    CodeBlock& operator=(const CodeBlock&) = delete;
    CodeBlock(CodeBlock&&) = delete;
    CodeBlock& operator=(CodeBlock&&) = delete;

#if defined(__SWITCH__)
    std::uint32_t* ptr() const = delete;
#else
    // Historical API: executable address. On platforms with a single mapping,
    // this is also the writable address.
    std::uint32_t* ptr() const {
        return xptr();
    }
#endif

    std::uint32_t* wptr() const {
#if defined(__SWITCH__)
        return m_write_memory;
#else
        return m_memory;
#endif
    }

    std::uint32_t* xptr() const {
        return m_memory;
    }

    template<typename T>
    T* ToExecutable(T* pointer) const {
#if defined(__SWITCH__)
        return reinterpret_cast<T*>(TranslateAlias(reinterpret_cast<std::uintptr_t>(pointer),
                                                  AliasKind::Executable));
#else
        return pointer;
#endif
    }

    template<typename T>
    T* ToWritable(T* pointer) const {
#if defined(__SWITCH__)
        return reinterpret_cast<T*>(TranslateAlias(reinterpret_cast<std::uintptr_t>(pointer),
                                                  AliasKind::Writable));
#else
        return pointer;
#endif
    }

    std::uint32_t* WritableToExecutable(std::uint32_t* pointer) const {
        return ToExecutable(pointer);
    }

    std::uint32_t* ExecutableToWritable(std::uint32_t* pointer) const {
        return ToWritable(pointer);
    }

    void FinalizeCodeRange(std::uint32_t* mem, std::size_t size) {
#if defined(__SWITCH__)
        invalidate(mem, size);
        protect();
#else
        invalidate(mem, size);
#endif
    }

    void protect() {
#if defined(__SWITCH__)
        const std::size_t offset = m_dirty_begin < m_dirty_end ? m_dirty_begin : 0;
        const std::size_t size = m_dirty_begin < m_dirty_end ? m_dirty_end - m_dirty_begin : 0;
        if (!azahar_switch_dynarmic_jit_end_write(m_jit_handle, offset, size)) {
            throw std::runtime_error{"Failed to transition Dynarmic JIT memory to executable"};
        }
        m_dirty_begin = m_size;
        m_dirty_end = 0;
#elif defined(__APPLE__) && !TARGET_OS_IPHONE
        pthread_jit_write_protect_np(1);
#elif defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
        mprotect(m_memory, m_size, PROT_READ | PROT_EXEC);
#endif
    }

    void unprotect() {
#if defined(__SWITCH__)
        if (!azahar_switch_dynarmic_jit_begin_write(m_jit_handle)) {
            throw std::runtime_error{"Failed to transition Dynarmic JIT memory to writable"};
        }
#elif defined(__APPLE__) && !TARGET_OS_IPHONE
        pthread_jit_write_protect_np(0);
#elif defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
        mprotect(m_memory, m_size, PROT_READ | PROT_WRITE);
#endif
    }

    void invalidate(std::uint32_t* mem, std::size_t size) {
#if defined(__SWITCH__)
        if (size == 0) {
            return;
        }

        const std::size_t offset =
            AliasOffset(reinterpret_cast<std::uintptr_t>(mem), size);
        const std::size_t end = std::min(m_size, offset + size);
        m_dirty_begin = std::min(m_dirty_begin, offset);
        m_dirty_end = std::max(m_dirty_end, end);
#elif defined(__APPLE__)
        sys_icache_invalidate(mem, size);
#elif defined(_WIN32)
        FlushInstructionCache(GetCurrentProcess(), mem, size);
#else
        static std::size_t icache_line_size = 0x10000;
        static std::size_t dcache_line_size = 0x10000;
        std::uint64_t ctr;
        __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
        const std::size_t isize =
            icache_line_size = std::min(icache_line_size, 4UL << ((ctr >> 0) & 0xf));
        const std::size_t dsize =
            dcache_line_size = std::min(dcache_line_size, 4UL << ((ctr >> 16) & 0xf));
        const std::uintptr_t end = reinterpret_cast<std::uintptr_t>(mem) + size;
        for (std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(mem) & ~(dsize - 1);
             addr < end; addr += dsize) {
            __asm__ volatile("dc cvau, %0" : : "r"(addr) : "memory");
        }
        __asm__ volatile("dsb ish\n" : : : "memory");
        for (std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(mem) & ~(isize - 1);
             addr < end; addr += isize) {
            __asm__ volatile("ic ivau, %0" : : "r"(addr) : "memory");
        }
        __asm__ volatile("dsb ish\nisb\n" : : : "memory");
#endif
    }

    void invalidate_all() {
#if defined(__SWITCH__)
        m_dirty_begin = 0;
        m_dirty_end = m_size;
#else
        invalidate(m_memory, m_size);
#endif
    }

protected:
#if defined(__SWITCH__)
    enum class AliasKind {
        Writable,
        Executable,
    };

    std::size_t AliasOffset(std::uintptr_t address, std::size_t size) const {
        const auto write_base = reinterpret_cast<std::uintptr_t>(m_write_memory);
        const auto exec_base = reinterpret_cast<std::uintptr_t>(m_memory);
        std::size_t offset = 0;

        if (address >= exec_base && address <= exec_base + m_size) {
            offset = static_cast<std::size_t>(address - exec_base);
        } else if (address >= write_base && address <= write_base + m_size) {
            offset = static_cast<std::size_t>(address - write_base);
        } else {
            ReportBadAlias(address, "outside code block");
        }

        if (offset > m_size || size > m_size - offset) {
            ReportBadAlias(address, "range exceeds code block");
        }

        return offset;
    }

    std::uintptr_t TranslateAlias(std::uintptr_t address, AliasKind target) const {
        const std::size_t offset = AliasOffset(address, 0);
        const auto base = target == AliasKind::Executable
                              ? reinterpret_cast<std::uintptr_t>(m_memory)
                              : reinterpret_cast<std::uintptr_t>(m_write_memory);
        return base + offset;
    }

    [[noreturn]] void ReportBadAlias(std::uintptr_t address, const char* reason) const {
        std::fprintf(stderr,
                     "[Dynarmic.JIT] invalid alias address=0x%016llx reason=%s rw=%p rx=%p size=0x%zx\n",
                     static_cast<unsigned long long>(address), reason,
                     static_cast<void*>(m_write_memory), static_cast<void*>(m_memory), m_size);
        std::fflush(stderr);
        throw std::invalid_argument{"JIT address is outside the code block alias range"};
    }
#endif

    // Executable alias. It remains the historical m_memory member to minimize
    // changes in users that inspect CodeBlock internals.
    std::uint32_t* m_memory = nullptr;
    std::size_t m_size = 0;

#if defined(__SWITCH__)
    std::uint32_t* m_write_memory = nullptr;
    void* m_jit_handle = nullptr;
    std::size_t m_dirty_begin = 0;
    std::size_t m_dirty_end = 0;
#endif
};

}  // namespace oaknut
