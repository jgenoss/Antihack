/**
 * AntiCheatCore - Precompiled Header
 * Common includes for faster compilation
 */

#pragma once

#ifndef AC_STDAFX_H
#define AC_STDAFX_H

// Windows headers
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <wincrypt.h>

// C++ Standard Library
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <queue>
#include <deque>
#include <memory>
#include <functional>
#include <algorithm>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <cstring>

// Internal common header
#include "internal/common.h"

#endif // AC_STDAFX_H
