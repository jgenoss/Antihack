/**
 * AntiCheatCore - HWID Collector Module
 * Collects hardware identifiers for ban systems
 */

#pragma once

#ifndef AC_HWID_COLLECTOR_H
#define AC_HWID_COLLECTOR_H

#include "common.h"
#include <intrin.h>

namespace AntiCheat {

class HWIDCollector {
public:
    // Hardware component info
    struct CPUInfo {
        std::string vendor;
        std::string brand;
        std::string processorId;
        int family;
        int model;
        int stepping;
        int cores;
        int threads;
    };

    struct DiskInfo {
        std::string model;
        std::string serialNumber;
        std::string interfaceType;
        uint64_t size;
    };

    struct NetworkInfo {
        std::string adapterName;
        std::string macAddress;
        std::string ipAddress;
        bool isPhysical;
    };

    struct MotherboardInfo {
        std::string manufacturer;
        std::string product;
        std::string serialNumber;
        std::string biosSerial;
        std::string biosVersion;
    };

    struct GPUInfo {
        std::string name;
        std::string driverVersion;
        std::string vendorId;
        std::string deviceId;
        uint64_t memory;
    };

    struct SystemInfo {
        std::string computerName;
        std::string userName;
        std::string windowsVersion;
        std::string windowsSerial;
        std::string installDate;
        uint64_t totalRAM;
    };

    // Complete HWID structure
    struct HWID {
        CPUInfo cpu;
        std::vector<DiskInfo> disks;
        std::vector<NetworkInfo> networks;
        MotherboardInfo motherboard;
        std::vector<GPUInfo> gpus;
        SystemInfo system;

        std::string uniqueHash;      // Combined hash of all components
        std::string shortHash;       // Short version for display
        DWORD collectionTime;
    };

private:
    HWID m_hwid;
    bool m_collected;
    std::string m_lastError;
    std::mutex m_mutex;

    // WMI helpers
    bool QueryWMI(const std::wstring& query, const std::wstring& property,
                  std::vector<std::string>& results);
    std::string QueryWMISingle(const std::wstring& wmiClass, const std::wstring& property);

    // Collection methods
    bool CollectCPUInfo();
    bool CollectDiskInfo();
    bool CollectNetworkInfo();
    bool CollectMotherboardInfo();
    bool CollectGPUInfo();
    bool CollectSystemInfo();

    // CPUID helper
    void GetCPUID(int function, int subfunction, int* regs);

    // Hash generation
    std::string GenerateHash(const std::string& input);
    std::string GenerateUniqueHash();
    std::string GenerateShortHash();

    // MAC address helpers
    std::string FormatMACAddress(const uint8_t* mac);
    bool IsVirtualMAC(const std::string& mac);

public:
    HWIDCollector();
    ~HWIDCollector();

    // Collection
    bool Collect();
    bool Refresh();
    bool IsCollected() const { return m_collected; }

    // Get complete HWID
    const HWID& GetHWID() const { return m_hwid; }

    // Get individual components
    const CPUInfo& GetCPUInfo() const { return m_hwid.cpu; }
    const std::vector<DiskInfo>& GetDiskInfo() const { return m_hwid.disks; }
    const std::vector<NetworkInfo>& GetNetworkInfo() const { return m_hwid.networks; }
    const MotherboardInfo& GetMotherboardInfo() const { return m_hwid.motherboard; }
    const std::vector<GPUInfo>& GetGPUInfo() const { return m_hwid.gpus; }
    const SystemInfo& GetSystemInfo() const { return m_hwid.system; }

    // Get hashes
    std::string GetUniqueHash();
    std::string GetShortHash();
    std::string GetComponentHash(const std::string& components); // e.g., "cpu+disk+mac"

    // Specific identifiers
    std::string GetCPUID();
    std::string GetPrimaryDiskSerial();
    std::string GetPrimaryMAC();
    std::string GetMotherboardSerial();
    std::string GetBIOSSerial();
    std::string GetWindowsProductID();
    std::string GetMachineGUID();

    // Validation
    bool ValidateHWID(const std::string& hash);
    bool HasVirtualizationIndicators();
    bool HasSpoofingIndicators();

    // Serialization
    std::string ToJSON();
    std::string ToBase64();
    bool FromJSON(const std::string& json);

    // Status
    const std::string& GetLastError() const { return m_lastError; }
};

} // namespace AntiCheat

#endif // AC_HWID_COLLECTOR_H
