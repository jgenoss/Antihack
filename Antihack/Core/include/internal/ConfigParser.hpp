/**
 * AntiCheatCore - INI Configuration Parser
 *
 * Reads and writes INI-format configuration files.
 * Routes sections to IConfigurable modules.
 *
 * Follows: Single Responsibility, Open/Closed Principle
 */

#pragma once

#ifndef AC_CONFIG_PARSER_HPP
#define AC_CONFIG_PARSER_HPP

#include "IConfigurable.hpp"
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>

namespace AntiCheat {

/**
 * Parses INI files into section-based key-value maps and
 * distributes configuration to registered IConfigurable modules.
 *
 * File format:
 *   [SectionName]
 *   key = value
 *   ; comment
 *   # comment
 */
class ConfigParser final {
public:
    using ConfigMap = IConfigurable::ConfigMap;
    using SectionMap = std::unordered_map<std::string, ConfigMap>;

    ConfigParser() = default;
    ~ConfigParser() = default;

    // Non-copyable, movable
    ConfigParser(const ConfigParser&) = delete;
    ConfigParser& operator=(const ConfigParser&) = delete;
    ConfigParser(ConfigParser&&) noexcept = default;
    ConfigParser& operator=(ConfigParser&&) noexcept = default;

    /**
     * Loads and parses an INI file from disk.
     *
     * @param filePath  Wide-string path to the INI file.
     * @return true if the file was read and parsed successfully.
     */
    bool LoadFromFile(const std::wstring& filePath);

    /**
     * Saves the current configuration state to an INI file.
     *
     * @param filePath  Wide-string path for the output file.
     * @return true if the file was written successfully.
     */
    bool SaveToFile(const std::wstring& filePath) const;

    /**
     * Parses INI content from a string (for testing or embedded configs).
     *
     * @param content  The INI-formatted string to parse.
     * @return true if parsing succeeded.
     */
    bool ParseString(const std::string& content);

    /**
     * Registers a configurable module. When LoadFromFile completes,
     * the parser will call ApplyConfig on each registered module
     * with the matching section data.
     *
     * @param module  Non-owning pointer to the module. Must outlive this parser.
     */
    void RegisterModule(IConfigurable* module);

    /**
     * Distributes loaded configuration to all registered modules.
     * Call this after LoadFromFile or ParseString.
     *
     * @return true if all modules accepted their configuration.
     */
    bool DistributeConfig();

    /**
     * Collects configuration from all registered modules into the
     * internal section map. Call SaveToFile after this to persist.
     */
    void CollectConfig();

    /**
     * Gets a value from a specific section.
     *
     * @param section   Section name (case-sensitive).
     * @param key       Key name (case-sensitive).
     * @param fallback  Value returned if the key is not found.
     * @return The value string, or fallback.
     */
    [[nodiscard]] std::string GetValue(const std::string& section,
                                        const std::string& key,
                                        const std::string& fallback = "") const;

    /**
     * Gets an integer value with fallback.
     */
    [[nodiscard]] int GetInt(const std::string& section,
                              const std::string& key,
                              int fallback = 0) const;

    /**
     * Gets a boolean value with fallback.
     * Accepts: "true", "1", "yes" as true; everything else as false.
     */
    [[nodiscard]] bool GetBool(const std::string& section,
                                const std::string& key,
                                bool fallback = false) const;

    /**
     * Sets a value in a specific section.
     */
    void SetValue(const std::string& section,
                  const std::string& key,
                  const std::string& value);

    /**
     * Returns all parsed sections.
     */
    [[nodiscard]] const SectionMap& GetAllSections() const noexcept {
        return m_sections;
    }

    /**
     * Returns the last error message, if any.
     */
    [[nodiscard]] const std::string& GetLastError() const noexcept {
        return m_lastError;
    }

private:
    SectionMap                    m_sections;
    std::vector<IConfigurable*>  m_modules;
    std::string                   m_lastError;

    /**
     * Trims leading and trailing whitespace from a string.
     */
    static std::string Trim(const std::string& str);

    /**
     * Converts a wide path to narrow UTF-8 string for file I/O.
     */
    static std::string WideToUtf8(const std::wstring& wstr);

    /**
     * Converts a narrow UTF-8 string to wide string.
     */
    static std::wstring Utf8ToWide(const std::string& str);
};

} // namespace AntiCheat

#endif // AC_CONFIG_PARSER_HPP
