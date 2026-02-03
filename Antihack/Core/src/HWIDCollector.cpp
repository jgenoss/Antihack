/**
 * AntiCheatCore - HWID Collector Implementation
 * Collects hardware identifiers for ban systems
 */

#include "stdafx.h"
#include "../include/internal/HWIDCollector.h"
#include <comdef.h>
#include <Wbemidl.h>
#include <iphlpapi.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace AntiCheat {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

HWIDCollector::HWIDCollector()
    : m_collected(false) {
}

HWIDCollector::~HWIDCollector() {
}

// ============================================================================
// COLLECTION
// ============================================================================

bool HWIDCollector::Collect() {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_hwid = HWID();
    m_collected = false;

    // Initialize COM
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    bool comInitialized = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;

    if (!comInitialized) {
        m_lastError = "Failed to initialize COM";
        return false;
    }

    // Collect all components
    CollectCPUInfo();
    CollectDiskInfo();
    CollectNetworkInfo();
    CollectMotherboardInfo();
    CollectGPUInfo();
    CollectSystemInfo();

    // Generate hashes
    m_hwid.uniqueHash = GenerateUniqueHash();
    m_hwid.shortHash = GenerateShortHash();
    m_hwid.collectionTime = GetTickCount();

    if (comInitialized && hr != RPC_E_CHANGED_MODE) {
        CoUninitialize();
    }

    m_collected = true;
    return true;
}

bool HWIDCollector::Refresh() {
    return Collect();
}

// ============================================================================
// CPU INFO
// ============================================================================

void HWIDCollector::GetCPUID(int function, int subfunction, int* regs) {
    __cpuidex(regs, function, subfunction);
}

bool HWIDCollector::CollectCPUInfo() {
    int regs[4];

    // Get vendor string
    GetCPUID(0, 0, regs);
    char vendor[13];
    memcpy(vendor, &regs[1], 4);
    memcpy(vendor + 4, &regs[3], 4);
    memcpy(vendor + 8, &regs[2], 4);
    vendor[12] = '\0';
    m_hwid.cpu.vendor = vendor;

    // Get brand string
    char brand[49] = { 0 };
    GetCPUID(0x80000002, 0, regs);
    memcpy(brand, regs, 16);
    GetCPUID(0x80000003, 0, regs);
    memcpy(brand + 16, regs, 16);
    GetCPUID(0x80000004, 0, regs);
    memcpy(brand + 32, regs, 16);
    m_hwid.cpu.brand = brand;

    // Get processor ID (from function 1)
    GetCPUID(1, 0, regs);
    m_hwid.cpu.family = ((regs[0] >> 8) & 0xF) + ((regs[0] >> 20) & 0xFF);
    m_hwid.cpu.model = ((regs[0] >> 4) & 0xF) + (((regs[0] >> 16) & 0xF) << 4);
    m_hwid.cpu.stepping = regs[0] & 0xF;

    // Generate processor ID string
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    ss << std::setw(8) << regs[3] << std::setw(8) << regs[0];
    m_hwid.cpu.processorId = ss.str();

    // Get core/thread count
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    m_hwid.cpu.threads = sysInfo.dwNumberOfProcessors;

    // Try to get physical core count from WMI
    std::string cores = QueryWMISingle(L"Win32_Processor", L"NumberOfCores");
    m_hwid.cpu.cores = cores.empty() ? m_hwid.cpu.threads : std::stoi(cores);

    return true;
}

// ============================================================================
// DISK INFO
// ============================================================================

bool HWIDCollector::CollectDiskInfo() {
    m_hwid.disks.clear();

    // Query WMI for disk drives
    std::vector<std::string> serials, models, interfaces, sizes;

    QueryWMI(L"SELECT * FROM Win32_DiskDrive", L"SerialNumber", serials);
    QueryWMI(L"SELECT * FROM Win32_DiskDrive", L"Model", models);
    QueryWMI(L"SELECT * FROM Win32_DiskDrive", L"InterfaceType", interfaces);
    QueryWMI(L"SELECT * FROM Win32_DiskDrive", L"Size", sizes);

    size_t count = serials.size();
    for (size_t i = 0; i < count; i++) {
        DiskInfo disk;
        disk.serialNumber = i < serials.size() ? serials[i] : "";
        disk.model = i < models.size() ? models[i] : "";
        disk.interfaceType = i < interfaces.size() ? interfaces[i] : "";
        disk.size = i < sizes.size() && !sizes[i].empty() ? std::stoull(sizes[i]) : 0;

        // Trim whitespace from serial
        size_t start = disk.serialNumber.find_first_not_of(" \t");
        size_t end = disk.serialNumber.find_last_not_of(" \t");
        if (start != std::string::npos && end != std::string::npos) {
            disk.serialNumber = disk.serialNumber.substr(start, end - start + 1);
        }

        if (!disk.serialNumber.empty()) {
            m_hwid.disks.push_back(disk);
        }
    }

    return !m_hwid.disks.empty();
}

// ============================================================================
// NETWORK INFO
// ============================================================================

std::string HWIDCollector::FormatMACAddress(const uint8_t* mac) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (int i = 0; i < 6; i++) {
        if (i > 0) ss << ":";
        ss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return ss.str();
}

bool HWIDCollector::IsVirtualMAC(const std::string& mac) {
    // Common virtual adapter MAC prefixes
    static const char* virtualPrefixes[] = {
        "00:05:69",  // VMware
        "00:0C:29",  // VMware
        "00:1C:14",  // VMware
        "00:50:56",  // VMware
        "08:00:27",  // VirtualBox
        "0A:00:27",  // VirtualBox
        "00:15:5D",  // Hyper-V
        "00:03:FF",  // Microsoft Virtual
        "00:1C:42",  // Parallels
        "00:16:3E",  // Xen
        nullptr
    };

    std::string upperMAC = mac;
    std::transform(upperMAC.begin(), upperMAC.end(), upperMAC.begin(), ::toupper);

    for (int i = 0; virtualPrefixes[i]; i++) {
        if (upperMAC.find(virtualPrefixes[i]) == 0) {
            return true;
        }
    }

    return false;
}

bool HWIDCollector::CollectNetworkInfo() {
    m_hwid.networks.clear();

    ULONG bufferSize = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bufferSize);

    std::vector<uint8_t> buffer(bufferSize);
    PIP_ADAPTER_ADDRESSES adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &bufferSize) != NO_ERROR) {
        return false;
    }

    for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter; adapter = adapter->Next) {
        // Skip loopback and non-physical adapters
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (adapter->PhysicalAddressLength != 6) continue;

        NetworkInfo net;
        net.adapterName = WStringToString(adapter->FriendlyName);
        net.macAddress = FormatMACAddress(adapter->PhysicalAddress);
        net.isPhysical = (adapter->IfType == IF_TYPE_ETHERNET_CSMACD ||
                          adapter->IfType == IF_TYPE_IEEE80211);

        // Get IP address
        for (PIP_ADAPTER_UNICAST_ADDRESS addr = adapter->FirstUnicastAddress; addr; addr = addr->Next) {
            if (addr->Address.lpSockaddr->sa_family == AF_INET) {
                sockaddr_in* sa = reinterpret_cast<sockaddr_in*>(addr->Address.lpSockaddr);
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sa->sin_addr, ip, INET_ADDRSTRLEN);
                net.ipAddress = ip;
                break;
            }
        }

        // Skip virtual MACs for primary identification
        if (!IsVirtualMAC(net.macAddress) || m_hwid.networks.empty()) {
            m_hwid.networks.push_back(net);
        }
    }

    return !m_hwid.networks.empty();
}

// ============================================================================
// MOTHERBOARD INFO
// ============================================================================

bool HWIDCollector::CollectMotherboardInfo() {
    m_hwid.motherboard.manufacturer = QueryWMISingle(L"Win32_BaseBoard", L"Manufacturer");
    m_hwid.motherboard.product = QueryWMISingle(L"Win32_BaseBoard", L"Product");
    m_hwid.motherboard.serialNumber = QueryWMISingle(L"Win32_BaseBoard", L"SerialNumber");

    m_hwid.motherboard.biosSerial = QueryWMISingle(L"Win32_BIOS", L"SerialNumber");
    m_hwid.motherboard.biosVersion = QueryWMISingle(L"Win32_BIOS", L"SMBIOSBIOSVersion");

    return !m_hwid.motherboard.serialNumber.empty() || !m_hwid.motherboard.biosSerial.empty();
}

// ============================================================================
// GPU INFO
// ============================================================================

bool HWIDCollector::CollectGPUInfo() {
    m_hwid.gpus.clear();

    std::vector<std::string> names, drivers, vram;

    QueryWMI(L"SELECT * FROM Win32_VideoController", L"Name", names);
    QueryWMI(L"SELECT * FROM Win32_VideoController", L"DriverVersion", drivers);
    QueryWMI(L"SELECT * FROM Win32_VideoController", L"AdapterRAM", vram);

    for (size_t i = 0; i < names.size(); i++) {
        GPUInfo gpu;
        gpu.name = names[i];
        gpu.driverVersion = i < drivers.size() ? drivers[i] : "";
        gpu.memory = i < vram.size() && !vram[i].empty() ? std::stoull(vram[i]) : 0;

        m_hwid.gpus.push_back(gpu);
    }

    return !m_hwid.gpus.empty();
}

// ============================================================================
// SYSTEM INFO
// ============================================================================

bool HWIDCollector::CollectSystemInfo() {
    // Computer name
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(computerName, &size)) {
        m_hwid.system.computerName = WStringToString(computerName);
    }

    // User name
    wchar_t userName[256];
    size = 256;
    if (GetUserNameW(userName, &size)) {
        m_hwid.system.userName = WStringToString(userName);
    }

    // Windows version
    m_hwid.system.windowsVersion = QueryWMISingle(L"Win32_OperatingSystem", L"Caption");

    // Windows serial
    m_hwid.system.windowsSerial = QueryWMISingle(L"Win32_OperatingSystem", L"SerialNumber");

    // Install date
    m_hwid.system.installDate = QueryWMISingle(L"Win32_OperatingSystem", L"InstallDate");

    // Total RAM
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        m_hwid.system.totalRAM = memInfo.ullTotalPhys;
    }

    return true;
}

// ============================================================================
// WMI HELPERS
// ============================================================================

std::string HWIDCollector::QueryWMISingle(const std::wstring& wmiClass, const std::wstring& property) {
    std::vector<std::string> results;
    std::wstring query = L"SELECT " + property + L" FROM " + wmiClass;
    if (QueryWMI(query, property, results) && !results.empty()) {
        return results[0];
    }
    return "";
}

bool HWIDCollector::QueryWMI(const std::wstring& query, const std::wstring& property,
                              std::vector<std::string>& results) {
    results.clear();

    HRESULT hr;
    IWbemLocator* locator = nullptr;
    IWbemServices* services = nullptr;
    IEnumWbemClassObject* enumerator = nullptr;

    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, reinterpret_cast<void**>(&locator));
    if (FAILED(hr)) return false;

    hr = locator->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0,
                                 0, 0, 0, &services);
    if (FAILED(hr)) {
        locator->Release();
        return false;
    }

    hr = CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        services->Release();
        locator->Release();
        return false;
    }

    hr = services->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()),
                              WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                              nullptr, &enumerator);
    if (FAILED(hr)) {
        services->Release();
        locator->Release();
        return false;
    }

    IWbemClassObject* obj = nullptr;
    ULONG returned = 0;

    while (enumerator) {
        hr = enumerator->Next(WBEM_INFINITE, 1, &obj, &returned);
        if (returned == 0) break;

        VARIANT vtProp;
        hr = obj->Get(property.c_str(), 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
            results.push_back(WStringToString(vtProp.bstrVal));
        }
        VariantClear(&vtProp);
        obj->Release();
    }

    if (enumerator) enumerator->Release();
    services->Release();
    locator->Release();

    return !results.empty();
}

// ============================================================================
// HASH GENERATION
// ============================================================================

std::string HWIDCollector::GenerateHash(const std::string& input) {
    // Use CRC32 combined with some mixing for a simple hash
    uint32_t hash = CalculateCRC32(reinterpret_cast<const uint8_t*>(input.c_str()), input.size());

    // Additional mixing
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);

    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << hash;
    return ss.str();
}

std::string HWIDCollector::GenerateUniqueHash() {
    std::stringstream ss;

    // Combine all hardware identifiers
    ss << m_hwid.cpu.processorId;
    ss << m_hwid.cpu.brand;

    for (const auto& disk : m_hwid.disks) {
        ss << disk.serialNumber;
    }

    for (const auto& net : m_hwid.networks) {
        if (net.isPhysical && !IsVirtualMAC(net.macAddress)) {
            ss << net.macAddress;
        }
    }

    ss << m_hwid.motherboard.serialNumber;
    ss << m_hwid.motherboard.biosSerial;
    ss << m_hwid.system.windowsSerial;

    // Generate multiple rounds of hashing
    std::string combined = ss.str();
    std::string hash1 = GenerateHash(combined);
    std::string hash2 = GenerateHash(combined + hash1);
    std::string hash3 = GenerateHash(hash1 + hash2);

    return hash1 + hash2 + hash3;
}

std::string HWIDCollector::GenerateShortHash() {
    std::string fullHash = m_hwid.uniqueHash.empty() ? GenerateUniqueHash() : m_hwid.uniqueHash;
    return fullHash.substr(0, 16);
}

// ============================================================================
// SPECIFIC IDENTIFIERS
// ============================================================================

std::string HWIDCollector::GetUniqueHash() {
    if (!m_collected) Collect();
    return m_hwid.uniqueHash;
}

std::string HWIDCollector::GetShortHash() {
    if (!m_collected) Collect();
    return m_hwid.shortHash;
}

std::string HWIDCollector::GetComponentHash(const std::string& components) {
    if (!m_collected) Collect();

    std::stringstream ss;

    if (components.find("cpu") != std::string::npos) {
        ss << m_hwid.cpu.processorId;
    }
    if (components.find("disk") != std::string::npos && !m_hwid.disks.empty()) {
        ss << m_hwid.disks[0].serialNumber;
    }
    if (components.find("mac") != std::string::npos && !m_hwid.networks.empty()) {
        ss << m_hwid.networks[0].macAddress;
    }
    if (components.find("bios") != std::string::npos) {
        ss << m_hwid.motherboard.biosSerial;
    }
    if (components.find("board") != std::string::npos) {
        ss << m_hwid.motherboard.serialNumber;
    }

    return GenerateHash(ss.str());
}

std::string HWIDCollector::GetCPUID() {
    if (!m_collected) Collect();
    return m_hwid.cpu.processorId;
}

std::string HWIDCollector::GetPrimaryDiskSerial() {
    if (!m_collected) Collect();
    return m_hwid.disks.empty() ? "" : m_hwid.disks[0].serialNumber;
}

std::string HWIDCollector::GetPrimaryMAC() {
    if (!m_collected) Collect();
    for (const auto& net : m_hwid.networks) {
        if (net.isPhysical && !IsVirtualMAC(net.macAddress)) {
            return net.macAddress;
        }
    }
    return m_hwid.networks.empty() ? "" : m_hwid.networks[0].macAddress;
}

std::string HWIDCollector::GetMotherboardSerial() {
    if (!m_collected) Collect();
    return m_hwid.motherboard.serialNumber;
}

std::string HWIDCollector::GetBIOSSerial() {
    if (!m_collected) Collect();
    return m_hwid.motherboard.biosSerial;
}

std::string HWIDCollector::GetWindowsProductID() {
    if (!m_collected) Collect();
    return m_hwid.system.windowsSerial;
}

std::string HWIDCollector::GetMachineGUID() {
    // Read from registry
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        wchar_t guid[256];
        DWORD size = sizeof(guid);
        DWORD type;

        if (RegQueryValueExW(hKey, L"MachineGuid", nullptr, &type,
                             reinterpret_cast<LPBYTE>(guid), &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return WStringToString(guid);
        }
        RegCloseKey(hKey);
    }
    return "";
}

// ============================================================================
// VALIDATION
// ============================================================================

bool HWIDCollector::ValidateHWID(const std::string& hash) {
    if (!m_collected) Collect();
    return hash == m_hwid.uniqueHash || hash == m_hwid.shortHash;
}

bool HWIDCollector::HasVirtualizationIndicators() {
    if (!m_collected) Collect();

    // Check for virtual MAC addresses
    for (const auto& net : m_hwid.networks) {
        if (IsVirtualMAC(net.macAddress)) {
            return true;
        }
    }

    // Check for VM-related strings in hardware names
    std::string combined = m_hwid.cpu.brand + m_hwid.motherboard.manufacturer +
                           m_hwid.motherboard.product;
    std::transform(combined.begin(), combined.end(), combined.begin(), ::tolower);

    if (combined.find("vmware") != std::string::npos ||
        combined.find("virtualbox") != std::string::npos ||
        combined.find("hyper-v") != std::string::npos ||
        combined.find("qemu") != std::string::npos ||
        combined.find("xen") != std::string::npos ||
        combined.find("parallels") != std::string::npos) {
        return true;
    }

    // Check CPUID for hypervisor
    int regs[4];
    GetCPUID(1, 0, regs);
    if (regs[2] & (1 << 31)) {  // Hypervisor bit
        return true;
    }

    return false;
}

bool HWIDCollector::HasSpoofingIndicators() {
    if (!m_collected) Collect();

    // Check for generic/default serial numbers
    std::string diskSerial = GetPrimaryDiskSerial();
    if (diskSerial == "0" || diskSerial == "00000000" ||
        diskSerial == "123456789" || diskSerial.empty()) {
        return true;
    }

    std::string biosSerial = GetBIOSSerial();
    if (biosSerial == "0" || biosSerial == "Default string" ||
        biosSerial == "To Be Filled By O.E.M." || biosSerial.empty()) {
        return true;
    }

    return false;
}

// ============================================================================
// SERIALIZATION
// ============================================================================

std::string HWIDCollector::ToJSON() {
    if (!m_collected) Collect();

    std::stringstream ss;
    ss << "{\n";
    ss << "  \"uniqueHash\": \"" << m_hwid.uniqueHash << "\",\n";
    ss << "  \"shortHash\": \"" << m_hwid.shortHash << "\",\n";
    ss << "  \"cpu\": {\n";
    ss << "    \"vendor\": \"" << m_hwid.cpu.vendor << "\",\n";
    ss << "    \"brand\": \"" << m_hwid.cpu.brand << "\",\n";
    ss << "    \"processorId\": \"" << m_hwid.cpu.processorId << "\"\n";
    ss << "  },\n";
    ss << "  \"primaryDisk\": \"" << GetPrimaryDiskSerial() << "\",\n";
    ss << "  \"primaryMAC\": \"" << GetPrimaryMAC() << "\",\n";
    ss << "  \"motherboard\": \"" << m_hwid.motherboard.serialNumber << "\",\n";
    ss << "  \"bios\": \"" << m_hwid.motherboard.biosSerial << "\",\n";
    ss << "  \"machineGUID\": \"" << GetMachineGUID() << "\"\n";
    ss << "}";

    return ss.str();
}

std::string HWIDCollector::ToBase64() {
    std::string json = ToJSON();

    // Simple Base64 encoding
    static const char* base64Chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string result;
    int val = 0, valb = -6;

    for (unsigned char c : json) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(base64Chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) {
        result.push_back(base64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (result.size() % 4) {
        result.push_back('=');
    }

    return result;
}

bool HWIDCollector::FromJSON(const std::string& json) {
    // Simple JSON parsing - would need a proper JSON library for production
    m_lastError = "JSON parsing not fully implemented";
    return false;
}

} // namespace AntiCheat
