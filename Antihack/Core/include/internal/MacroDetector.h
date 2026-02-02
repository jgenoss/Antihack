/**
 * AntiCheatCore - Macro/Autoclicker Detection Module
 * Detects automated input patterns with advanced statistical analysis
 */

#pragma once

#ifndef AC_MACRO_DETECTOR_H
#define AC_MACRO_DETECTOR_H

#include "common.h"
#include <deque>
#include <cmath>

namespace AntiCheat {

class MacroDetector {
public:
    struct ClickEvent {
        DWORD timestamp;
        POINT position;
        DWORD button;  // VK_LBUTTON, VK_RBUTTON, etc.
    };

    struct KeyEvent {
        DWORD timestamp;
        DWORD vkCode;
        bool isDown;
    };

    struct AnalysisResult {
        bool isSuspicious;
        double confidence;
        std::string reason;
        double variance;
        double meanInterval;
        double autocorrelation;
    };

    struct CalibrationData {
        double minVariance;
        double maxVariance;
        double minMeanInterval;
        double maxMeanInterval;
        int sampleCount;
        bool isCalibrated;
    };

private:
    static const size_t MAX_CLICK_HISTORY = 100;
    static const size_t MAX_KEY_HISTORY = 200;
    static const size_t MIN_SAMPLES_FOR_ANALYSIS = 10;

    std::deque<ClickEvent> m_clickHistory;
    std::deque<KeyEvent> m_keyHistory;
    std::map<DWORD, std::deque<KeyEvent>> m_keyHistoryByKey;

    CalibrationData m_calibration;
    DetectionCallback m_callback;
    std::mutex m_mutex;
    std::atomic<bool> m_enabled{false};
    std::atomic<bool> m_calibrating{false};

    // Thresholds
    double m_varianceThreshold;
    double m_autocorrelationThreshold;
    double m_minClickInterval;
    double m_maxClicksPerSecond;

    // Statistical analysis
    double CalculateVariance(const std::vector<double>& intervals);
    double CalculateMean(const std::vector<double>& values);
    double CalculateAutocorrelation(const std::vector<double>& intervals, int lag = 1);
    double CalculateStandardDeviation(const std::vector<double>& values);

    // Detection methods
    bool DetectConstantTiming(const std::vector<double>& intervals);
    bool DetectPeriodicPattern(const std::vector<double>& intervals);
    bool DetectStatisticalAnomaly(const std::vector<double>& intervals);

public:
    MacroDetector();
    ~MacroDetector();

    // Initialization
    bool Initialize();
    void Shutdown();
    void SetDetectionCallback(DetectionCallback callback);

    // Event recording
    void RecordClick(const ClickEvent& event);
    void RecordClick(DWORD timestamp, const POINT& position, DWORD button);
    void RecordKeyPress(const KeyEvent& event);
    void RecordKeyPress(DWORD timestamp, DWORD vkCode, bool isDown);

    // Analysis
    AnalysisResult AnalyzeClickPattern();
    AnalysisResult AnalyzeKeyPattern(DWORD vkCode = 0);
    bool IsAutoclickerDetected();
    bool IsAutoKeyerDetected(DWORD vkCode = 0);

    // Calibration (learn normal player behavior)
    void StartCalibration();
    void EndCalibration();
    bool IsCalibrating() const { return m_calibrating; }
    bool IsCalibrated() const { return m_calibration.isCalibrated; }
    const CalibrationData& GetCalibrationData() const { return m_calibration; }

    // Configuration
    void SetVarianceThreshold(double threshold) { m_varianceThreshold = threshold; }
    void SetAutocorrelationThreshold(double threshold) { m_autocorrelationThreshold = threshold; }
    void SetMinClickInterval(double intervalMs) { m_minClickInterval = intervalMs; }
    void SetMaxClicksPerSecond(double cps) { m_maxClicksPerSecond = cps; }

    // State management
    void Enable() { m_enabled = true; }
    void Disable() { m_enabled = false; }
    bool IsEnabled() const { return m_enabled; }
    void ClearHistory();

    // Getters
    size_t GetClickHistorySize() const { return m_clickHistory.size(); }
    size_t GetKeyHistorySize() const { return m_keyHistory.size(); }
};

} // namespace AntiCheat

#endif // AC_MACRO_DETECTOR_H
