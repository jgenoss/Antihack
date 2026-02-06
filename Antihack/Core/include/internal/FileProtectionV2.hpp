/**
 * AntiCheatCore - Refactored File Protection Module (V2)
 *
 * Monitors game file integrity using CRC32 checksums.
 *
 * Improvements over V1 (FileProtection.h):
 *   - Properly in AntiCheat namespace
 *   - Inherits from IMonitorModule for periodic monitoring
 *   - Implements IConfigurable for runtime reconfiguration
 *   - Uses shared CRC32 from common.h (no duplicate table)
 *   - Adds missing methods: Initialize, Shutdown, StartMonitoring, etc.
 *   - VerificationResult struct for structured results
 *   - Violation callback for event-driven detection
 *   - Const-correctness throughout
 *
 * Follows: SOLID, RAII, Template Method (IMonitorModule)
 */

#pragma once

#ifndef AC_FILE_PROTECTION_V2_HPP
#define AC_FILE_PROTECTION_V2_HPP

#include "IMonitorModule.h"
#include "IConfigurable.hpp"
#include <fstream>

namespace AntiCheat {

class FileProtectionV2 final : public IMonitorModule, public IConfigurable {
public:
    /**
     * Result of verifying a single protected file.
     */
    struct VerificationResult {
        std::wstring path;
        uint32_t     expectedCrc;
        uint32_t     actualCrc;
        bool         isValid;
        bool         isRequired;
        bool         fileExists;
        std::string  errorMessage;

        VerificationResult()
            : expectedCrc(0)
            , actualCrc(0)
            , isValid(false)
            , isRequired(false)
            , fileExists(false) {
        }
    };

    using ViolationCallback = std::function<void(const VerificationResult&)>;

    FileProtectionV2();
    ~FileProtectionV2() override;

    // Non-copyable
    FileProtectionV2(const FileProtectionV2&) = delete;
    FileProtectionV2& operator=(const FileProtectionV2&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    bool Initialize() override;
    void Shutdown() override;

    // ========================================================================
    // PATH CONFIGURATION
    // ========================================================================

    /** Sets the base directory for resolving relative file paths. */
    void SetBasePath(const std::wstring& basePath);

    /** Gets the current base path. */
    [[nodiscard]] const std::wstring& GetBasePath() const noexcept { return m_basePath; }

    // ========================================================================
    // FILE REGISTRATION
    // ========================================================================

    /**
     * Adds a file to the protection list with a known CRC32 checksum.
     *
     * @param relativePath  Path relative to the base path.
     * @param expectedCrc   Known-good CRC32 value.
     * @param isRequired    If true, modification triggers a critical alert.
     */
    void AddProtectedFile(const std::wstring& relativePath,
                          uint32_t expectedCrc,
                          bool isRequired = true);

    /**
     * Adds a file to the protection list, computing CRC32 from its current contents.
     * The current file state is treated as the "known good" state.
     *
     * @param relativePath  Path relative to the base path.
     * @param isRequired    If true, modification triggers a critical alert.
     * @return true if the file was read and registered successfully.
     */
    bool AddProtectedFileAuto(const std::wstring& relativePath,
                               bool isRequired = true);

    /**
     * Removes a file from the protection list.
     *
     * @param relativePath  Path relative to the base path.
     */
    void RemoveProtectedFile(const std::wstring& relativePath);

    /** Clears all protected files. */
    void ClearProtectedFiles();

    /** Returns the number of registered protected files. */
    [[nodiscard]] int GetProtectedFileCount() const;

    // ========================================================================
    // CONFIGURATION FILE
    // ========================================================================

    /**
     * Loads protected file definitions from a configuration file.
     * Format: relative_path,CRC32_hex,required(true/false)
     *
     * @param configPath  Path to the configuration file.
     * @return true if loaded successfully.
     */
    bool LoadConfiguration(const std::wstring& configPath);

    /**
     * Generates a configuration file from the current protected files.
     *
     * @param outputPath  Path for the output file.
     * @return true if written successfully.
     */
    bool GenerateConfiguration(const std::wstring& outputPath) const;

    // ========================================================================
    // VERIFICATION
    // ========================================================================

    /**
     * Verifies all protected files and returns results.
     *
     * @param outResults  Vector to populate with verification results.
     * @return true if ALL files passed verification.
     */
    bool VerifyAllFiles(std::vector<VerificationResult>& outResults) const;

    /**
     * Verifies a single file.
     *
     * @param relativePath  Path relative to the base path.
     * @return Verification result.
     */
    [[nodiscard]] VerificationResult VerifyFile(const std::wstring& relativePath) const;

    /**
     * Quick check: are all required files intact?
     */
    [[nodiscard]] bool VerifyIntegrity() const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    /** Sets the callback invoked when a file integrity violation is detected. */
    void SetViolationCallback(ViolationCallback callback);

    // ========================================================================
    // IConfigurable
    // ========================================================================

    bool ApplyConfig(const ConfigMap& config) override;
    void ExportConfig(ConfigMap& outConfig) const override;
    [[nodiscard]] std::string GetConfigSection() const override { return "FileProtection"; }

protected:
    // ========================================================================
    // IMonitorModule overrides
    // ========================================================================

    void DoMonitorCycle() override;
    void OnMonitorStart() override;

private:
    /**
     * Protected file entry.
     */
    struct ProtectedFileEntry {
        std::wstring relativePath;
        std::wstring fullPath;
        uint32_t     expectedCrc;
        bool         isRequired;
    };

    std::vector<ProtectedFileEntry> m_protectedFiles;
    std::wstring                    m_basePath;
    ViolationCallback               m_violationCallback;

    // ========================================================================
    // UTILITY
    // ========================================================================

    /** Resolves a relative path against the base path. */
    [[nodiscard]] std::wstring ResolvePath(const std::wstring& relativePath) const;

    /** Reads the entire contents of a file into a byte vector. */
    [[nodiscard]] static ByteVector ReadFileBytes(const std::wstring& path);

    /**
     * Computes CRC32 of a file on disk.
     *
     * @param path    Full path to the file.
     * @param outCrc  Receives the computed CRC32.
     * @return true if the file was read and CRC computed successfully.
     */
    [[nodiscard]] static bool ComputeFileCrc(const std::wstring& path, uint32_t& outCrc);
};

} // namespace AntiCheat

#endif // AC_FILE_PROTECTION_V2_HPP
