/**
 * AntiCheatCore - INI Configuration Parser Implementation
 */

#include "../include/internal/ConfigParser.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <Windows.h>

namespace AntiCheat {

// ============================================================================
// FILE I/O
// ============================================================================

bool ConfigParser::LoadFromFile(const std::wstring& filePath) {
    std::string narrowPath = WideToUtf8(filePath);
    std::ifstream file(narrowPath, std::ios::in);

    if (!file.is_open()) {
        m_lastError = "Failed to open config file: " + narrowPath;
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    return ParseString(buffer.str());
}

bool ConfigParser::SaveToFile(const std::wstring& filePath) const {
    std::string narrowPath = WideToUtf8(filePath);
    std::ofstream file(narrowPath, std::ios::out | std::ios::trunc);

    if (!file.is_open()) {
        return false;
    }

    file << "; AntiCheatCore Configuration\n";
    file << "; Auto-generated - manual edits are preserved on next save\n\n";

    for (const auto& [sectionName, sectionData] : m_sections) {
        file << "[" << sectionName << "]\n";

        for (const auto& [key, value] : sectionData) {
            file << key << " = " << value << "\n";
        }

        file << "\n";
    }

    file.flush();
    return file.good();
}

// ============================================================================
// PARSING
// ============================================================================

bool ConfigParser::ParseString(const std::string& content) {
    m_sections.clear();

    std::istringstream stream(content);
    std::string line;
    std::string currentSection;

    int lineNumber = 0;

    while (std::getline(stream, line)) {
        lineNumber++;
        line = Trim(line);

        // Skip empty lines and comments
        if (line.empty() || line[0] == ';' || line[0] == '#') {
            continue;
        }

        // Section header: [SectionName]
        if (line.front() == '[' && line.back() == ']') {
            currentSection = Trim(line.substr(1, line.size() - 2));
            if (currentSection.empty()) {
                m_lastError = "Empty section name at line " + std::to_string(lineNumber);
                return false;
            }
            // Ensure section exists in the map even if it has no keys
            m_sections[currentSection];
            continue;
        }

        // Key = Value pair
        size_t equalsPos = line.find('=');
        if (equalsPos == std::string::npos) {
            m_lastError = "Malformed line (no '=') at line " + std::to_string(lineNumber);
            return false;
        }

        std::string key = Trim(line.substr(0, equalsPos));
        std::string value = Trim(line.substr(equalsPos + 1));

        if (key.empty()) {
            m_lastError = "Empty key at line " + std::to_string(lineNumber);
            return false;
        }

        // If no section header has been seen yet, use a default section
        if (currentSection.empty()) {
            currentSection = "General";
        }

        m_sections[currentSection][key] = value;
    }

    return true;
}

// ============================================================================
// MODULE REGISTRATION AND DISTRIBUTION
// ============================================================================

void ConfigParser::RegisterModule(IConfigurable* module) {
    if (module == nullptr) {
        return;
    }

    // Avoid duplicate registration
    for (const auto* existingModule : m_modules) {
        if (existingModule == module) {
            return;
        }
    }

    m_modules.push_back(module);
}

bool ConfigParser::DistributeConfig() {
    bool allSucceeded = true;

    for (auto* module : m_modules) {
        const std::string sectionName = module->GetConfigSection();

        auto sectionIter = m_sections.find(sectionName);
        if (sectionIter != m_sections.end()) {
            if (!module->ApplyConfig(sectionIter->second)) {
                m_lastError = "Module '" + sectionName + "' rejected configuration";
                allSucceeded = false;
            }
        }
        // If the section doesn't exist, the module will use its defaults.
        // This is not an error.
    }

    return allSucceeded;
}

void ConfigParser::CollectConfig() {
    for (const auto* module : m_modules) {
        const std::string sectionName = module->GetConfigSection();
        ConfigMap sectionData;
        module->ExportConfig(sectionData);
        m_sections[sectionName] = std::move(sectionData);
    }
}

// ============================================================================
// VALUE ACCESSORS
// ============================================================================

std::string ConfigParser::GetValue(const std::string& section,
                                    const std::string& key,
                                    const std::string& fallback) const {
    auto sectionIter = m_sections.find(section);
    if (sectionIter == m_sections.end()) {
        return fallback;
    }

    auto keyIter = sectionIter->second.find(key);
    if (keyIter == sectionIter->second.end()) {
        return fallback;
    }

    return keyIter->second;
}

int ConfigParser::GetInt(const std::string& section,
                          const std::string& key,
                          int fallback) const {
    std::string value = GetValue(section, key);
    if (value.empty()) {
        return fallback;
    }

    try {
        return std::stoi(value);
    } catch (const std::exception&) {
        return fallback;
    }
}

bool ConfigParser::GetBool(const std::string& section,
                            const std::string& key,
                            bool fallback) const {
    std::string value = GetValue(section, key);
    if (value.empty()) {
        return fallback;
    }

    // Lowercase for comparison
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (lower == "true" || lower == "1" || lower == "yes" || lower == "on") {
        return true;
    }
    if (lower == "false" || lower == "0" || lower == "no" || lower == "off") {
        return false;
    }

    return fallback;
}

void ConfigParser::SetValue(const std::string& section,
                             const std::string& key,
                             const std::string& value) {
    m_sections[section][key] = value;
}

// ============================================================================
// UTILITY
// ============================================================================

std::string ConfigParser::Trim(const std::string& str) {
    size_t start = 0;
    while (start < str.size() && std::isspace(static_cast<unsigned char>(str[start]))) {
        start++;
    }

    size_t end = str.size();
    while (end > start && std::isspace(static_cast<unsigned char>(str[end - 1]))) {
        end--;
    }

    return str.substr(start, end - start);
}

std::string ConfigParser::WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    int sizeNeeded = ::WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(),
                                            static_cast<int>(wstr.size()),
                                            nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return std::string();

    std::string result(static_cast<size_t>(sizeNeeded), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(),
                           static_cast<int>(wstr.size()),
                           &result[0], sizeNeeded, nullptr, nullptr);
    return result;
}

std::wstring ConfigParser::Utf8ToWide(const std::string& str) {
    if (str.empty()) return std::wstring();

    int sizeNeeded = ::MultiByteToWideChar(CP_UTF8, 0, str.c_str(),
                                            static_cast<int>(str.size()),
                                            nullptr, 0);
    if (sizeNeeded <= 0) return std::wstring();

    std::wstring result(static_cast<size_t>(sizeNeeded), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, str.c_str(),
                           static_cast<int>(str.size()),
                           &result[0], sizeNeeded);
    return result;
}

} // namespace AntiCheat
