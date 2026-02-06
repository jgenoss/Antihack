/**
 * AntiCheatCore - RAII Handle Guard
 *
 * Provides automatic lifetime management for Windows HANDLE objects.
 * Eliminates manual CloseHandle calls and prevents resource leaks.
 *
 * Follows: RAII, Single Responsibility Principle, Move Semantics (C++17)
 */

#pragma once

#ifndef AC_HANDLE_GUARD_HPP
#define AC_HANDLE_GUARD_HPP

#include <Windows.h>
#include <utility>

namespace AntiCheat {

/**
 * Policy-based RAII wrapper for Windows HANDLE types.
 *
 * Template parameter TPolicy defines:
 *   - static HANDLE InvalidValue()   -> the sentinel value for "no handle"
 *   - static void Close(HANDLE h)    -> how to release the handle
 *
 * Usage:
 *   HandleGuard<KernelHandlePolicy> thread(CreateThread(...));
 *   HandleGuard<EventHandlePolicy>  event(CreateEventW(...));
 *   // Handles are automatically closed on destruction or reassignment.
 */
template<typename TPolicy>
class HandleGuard final {
public:
    /** Constructs an empty guard (no handle). */
    HandleGuard() noexcept
        : m_handle(TPolicy::InvalidValue()) {
    }

    /** Takes ownership of the given handle. */
    explicit HandleGuard(HANDLE handle) noexcept
        : m_handle(handle) {
    }

    /** Move constructor - transfers ownership. */
    HandleGuard(HandleGuard&& other) noexcept
        : m_handle(other.Release()) {
    }

    /** Move assignment - releases current handle, takes ownership of other. */
    HandleGuard& operator=(HandleGuard&& other) noexcept {
        if (this != &other) {
            Reset(other.Release());
        }
        return *this;
    }

    /** Destructor - closes the handle if valid. */
    ~HandleGuard() noexcept {
        CloseIfValid();
    }

    // Non-copyable: each handle has exactly one owner.
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;

    /** Returns the raw handle without releasing ownership. */
    [[nodiscard]] HANDLE Get() const noexcept {
        return m_handle;
    }

    /** Checks whether the guard holds a valid handle. */
    [[nodiscard]] bool IsValid() const noexcept {
        return m_handle != TPolicy::InvalidValue();
    }

    /** Explicit bool conversion for use in conditions. */
    [[nodiscard]] explicit operator bool() const noexcept {
        return IsValid();
    }

    /**
     * Releases ownership of the handle WITHOUT closing it.
     * The caller becomes responsible for closing the handle.
     *
     * @return The raw handle (may be invalid).
     */
    [[nodiscard]] HANDLE Release() noexcept {
        HANDLE temp = m_handle;
        m_handle = TPolicy::InvalidValue();
        return temp;
    }

    /**
     * Closes the current handle (if valid) and takes ownership of a new one.
     *
     * @param newHandle The new handle to manage (default: invalid).
     */
    void Reset(HANDLE newHandle = TPolicy::InvalidValue()) noexcept {
        if (m_handle != newHandle) {
            CloseIfValid();
            m_handle = newHandle;
        }
    }

    /**
     * Swaps handles between two guards.
     */
    void Swap(HandleGuard& other) noexcept {
        std::swap(m_handle, other.m_handle);
    }

private:
    HANDLE m_handle;

    void CloseIfValid() noexcept {
        if (m_handle != TPolicy::InvalidValue()) {
            TPolicy::Close(m_handle);
            m_handle = TPolicy::InvalidValue();
        }
    }
};

// ============================================================================
// HANDLE POLICIES
// ============================================================================

/**
 * Policy for kernel objects (threads, events, mutexes, semaphores).
 * Invalid value: NULL.
 */
struct KernelHandlePolicy {
    static HANDLE InvalidValue() noexcept { return NULL; }
    static void Close(HANDLE h) noexcept { ::CloseHandle(h); }
};

/**
 * Policy for file handles and Toolhelp snapshots.
 * Invalid value: INVALID_HANDLE_VALUE.
 */
struct FileHandlePolicy {
    static HANDLE InvalidValue() noexcept { return INVALID_HANDLE_VALUE; }
    static void Close(HANDLE h) noexcept { ::CloseHandle(h); }
};

/**
 * Policy for named pipe handles.
 * Invalid value: INVALID_HANDLE_VALUE.
 */
struct PipeHandlePolicy {
    static HANDLE InvalidValue() noexcept { return INVALID_HANDLE_VALUE; }
    static void Close(HANDLE h) noexcept {
        ::FlushFileBuffers(h);
        ::DisconnectNamedPipe(h);
        ::CloseHandle(h);
    }
};

// ============================================================================
// CONVENIENT TYPE ALIASES
// ============================================================================

/** RAII guard for thread, event, mutex handles (NULL = invalid). */
using KernelHandle = HandleGuard<KernelHandlePolicy>;

/** RAII guard for file and snapshot handles (INVALID_HANDLE_VALUE = invalid). */
using FileHandle = HandleGuard<FileHandlePolicy>;

/** RAII guard for named pipe handles with proper disconnect. */
using PipeHandle = HandleGuard<PipeHandlePolicy>;

// ============================================================================
// FACTORY FUNCTIONS
// ============================================================================

/**
 * Creates a manual-reset event wrapped in RAII guard.
 *
 * @param initialState  true = signaled, false = non-signaled.
 * @return KernelHandle owning the event, or invalid on failure.
 */
[[nodiscard]] inline KernelHandle MakeEvent(bool manualReset = true,
                                             bool initialState = false) noexcept {
    HANDLE h = ::CreateEventW(nullptr, manualReset ? TRUE : FALSE,
                               initialState ? TRUE : FALSE, nullptr);
    return KernelHandle(h);
}

/**
 * Creates a Toolhelp snapshot wrapped in RAII guard.
 *
 * @param flags      Snapshot flags (TH32CS_SNAPMODULE, etc.).
 * @param processId  Process ID (0 = current process).
 * @return FileHandle owning the snapshot, or invalid on failure.
 */
[[nodiscard]] inline FileHandle MakeSnapshot(DWORD flags,
                                              DWORD processId = 0) noexcept {
    HANDLE h = ::CreateToolhelp32Snapshot(flags, processId);
    return FileHandle(h);
}

} // namespace AntiCheat

#endif // AC_HANDLE_GUARD_HPP
