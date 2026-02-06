/**
 * AntiCheatCore - Platform Header
 *
 * CRITICAL: This header MUST be included FIRST in any file that uses
 * Windows networking APIs. WinSock2.h must be included before Windows.h.
 *
 * Author: AntiCheat Team
 * Standard: C++17
 */

#pragma once

#ifndef AC_PLATFORM_H
#define AC_PLATFORM_H

// ============================================================================
// CRITICAL: WINSOCK2 MUST BE INCLUDED BEFORE WINDOWS.H
// ============================================================================
// The Windows SDK has a known issue where including Windows.h before WinSock2.h
// causes redefinition errors. This header ensures correct include order.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

// Network headers FIRST (before Windows.h)
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>

// Windows core headers
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

// Link required libraries
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#endif // AC_PLATFORM_H
