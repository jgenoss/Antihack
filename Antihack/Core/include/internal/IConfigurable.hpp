/**
 * AntiCheatCore - Configurable Module Interface
 *
 * Interface Segregation Principle: Modules that support runtime
 * configuration implement this interface independently of their
 * monitoring capabilities.
 *
 * Follows: ISP (SOLID), Dependency Inversion
 */

#pragma once

#ifndef AC_ICONFIGURABLE_HPP
#define AC_ICONFIGURABLE_HPP

#include <string>
#include <unordered_map>

namespace AntiCheat {

/**
 * Abstract interface for modules that can load/save configuration.
 *
 * Each configurable module receives a flat key-value map from the
 * configuration parser. The module is responsible for interpreting
 * its own keys and applying defaults for missing values.
 */
class IConfigurable {
public:
    using ConfigMap = std::unordered_map<std::string, std::string>;

    virtual ~IConfigurable() = default;

    /**
     * Apply configuration values from a key-value map.
     *
     * @param config  Key-value pairs relevant to this module.
     * @return true if all required keys were present and valid.
     */
    virtual bool ApplyConfig(const ConfigMap& config) = 0;

    /**
     * Export the current configuration state as key-value pairs.
     *
     * @param outConfig  Map to populate with current settings.
     */
    virtual void ExportConfig(ConfigMap& outConfig) const = 0;

    /**
     * Returns the configuration section name for this module.
     * Used by the config parser to route INI sections to the correct module.
     *
     * Example: "ProcessMonitor", "HookDetector", "MacroDetector"
     */
    [[nodiscard]] virtual std::string GetConfigSection() const = 0;
};

} // namespace AntiCheat

#endif // AC_ICONFIGURABLE_HPP
