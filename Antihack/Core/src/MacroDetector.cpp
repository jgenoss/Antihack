/**
 * AntiCheatCore - Macro/Autoclicker Detection Implementation
 * Advanced statistical analysis for detecting automated input
 */

#include "../include/internal/MacroDetector.h"
#include <numeric>
#include <algorithm>

namespace AntiCheat {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

MacroDetector::MacroDetector()
    : m_varianceThreshold(5.0),
      m_autocorrelationThreshold(0.9),
      m_minClickInterval(20.0),
      m_maxClicksPerSecond(20.0) {
    m_calibration = {};
}

MacroDetector::~MacroDetector() {
    Shutdown();
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool MacroDetector::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_enabled = true;
    return true;
}

void MacroDetector::Shutdown() {
    m_enabled = false;
    ClearHistory();
}

void MacroDetector::SetDetectionCallback(DetectionCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_callback = callback;
}

// ============================================================================
// EVENT RECORDING
// ============================================================================

void MacroDetector::RecordClick(const ClickEvent& event) {
    if (!m_enabled) return;

    std::lock_guard<std::mutex> lock(m_mutex);

    m_clickHistory.push_back(event);
    while (m_clickHistory.size() > MAX_CLICK_HISTORY) {
        m_clickHistory.pop_front();
    }

    // Auto-analyze after enough samples
    if (m_clickHistory.size() >= MIN_SAMPLES_FOR_ANALYSIS && !m_calibrating) {
        AnalysisResult result = AnalyzeClickPattern();
        if (result.isSuspicious && m_callback) {
            DetectionEvent detection;
            detection.type = DetectionType::MacroDetected;
            detection.severity = Severity::Warning;
            detection.description = result.reason;
            detection.timestamp = GetTickCount();
            m_callback(detection);
        }
    }
}

void MacroDetector::RecordClick(DWORD timestamp, const POINT& position, DWORD button) {
    ClickEvent event;
    event.timestamp = timestamp;
    event.position = position;
    event.button = button;
    RecordClick(event);
}

void MacroDetector::RecordKeyPress(const KeyEvent& event) {
    if (!m_enabled) return;

    std::lock_guard<std::mutex> lock(m_mutex);

    m_keyHistory.push_back(event);
    while (m_keyHistory.size() > MAX_KEY_HISTORY) {
        m_keyHistory.pop_front();
    }

    // Track by key
    auto& keyQueue = m_keyHistoryByKey[event.vkCode];
    keyQueue.push_back(event);
    while (keyQueue.size() > MAX_CLICK_HISTORY) {
        keyQueue.pop_front();
    }
}

void MacroDetector::RecordKeyPress(DWORD timestamp, DWORD vkCode, bool isDown) {
    KeyEvent event;
    event.timestamp = timestamp;
    event.vkCode = vkCode;
    event.isDown = isDown;
    RecordKeyPress(event);
}

// ============================================================================
// STATISTICAL ANALYSIS
// ============================================================================

double MacroDetector::CalculateMean(const std::vector<double>& values) {
    if (values.empty()) return 0.0;
    double sum = std::accumulate(values.begin(), values.end(), 0.0);
    return sum / values.size();
}

double MacroDetector::CalculateVariance(const std::vector<double>& intervals) {
    if (intervals.size() < 2) return 0.0;

    double mean = CalculateMean(intervals);
    double variance = 0.0;

    for (double val : intervals) {
        variance += (val - mean) * (val - mean);
    }

    return variance / (intervals.size() - 1);
}

double MacroDetector::CalculateStandardDeviation(const std::vector<double>& values) {
    return std::sqrt(CalculateVariance(values));
}

double MacroDetector::CalculateAutocorrelation(const std::vector<double>& intervals, int lag) {
    if (intervals.size() < static_cast<size_t>(lag + 2)) return 0.0;

    double mean = CalculateMean(intervals);
    double variance = CalculateVariance(intervals);

    if (variance < 0.0001) return 1.0; // Perfect correlation if no variance

    double autocorr = 0.0;
    size_t n = intervals.size() - lag;

    for (size_t i = 0; i < n; i++) {
        autocorr += (intervals[i] - mean) * (intervals[i + lag] - mean);
    }

    return autocorr / (n * variance);
}

// ============================================================================
// DETECTION METHODS
// ============================================================================

bool MacroDetector::DetectConstantTiming(const std::vector<double>& intervals) {
    double variance = CalculateVariance(intervals);

    // Extremely low variance indicates constant timing (autoclicker)
    if (variance < m_varianceThreshold) {
        return true;
    }

    return false;
}

bool MacroDetector::DetectPeriodicPattern(const std::vector<double>& intervals) {
    // Check autocorrelation at different lags
    for (int lag = 1; lag <= 5; lag++) {
        double autocorr = CalculateAutocorrelation(intervals, lag);
        if (autocorr > m_autocorrelationThreshold) {
            return true;
        }
    }

    return false;
}

bool MacroDetector::DetectStatisticalAnomaly(const std::vector<double>& intervals) {
    if (!m_calibration.isCalibrated) return false;

    double mean = CalculateMean(intervals);
    double variance = CalculateVariance(intervals);

    // Check if outside calibrated ranges
    if (variance < m_calibration.minVariance * 0.5 ||
        mean < m_calibration.minMeanInterval * 0.5 ||
        mean > m_calibration.maxMeanInterval * 2.0) {
        return true;
    }

    return false;
}

// ============================================================================
// PATTERN ANALYSIS
// ============================================================================

MacroDetector::AnalysisResult MacroDetector::AnalyzeClickPattern() {
    AnalysisResult result = {};
    result.isSuspicious = false;
    result.confidence = 0.0;

    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_clickHistory.size() < MIN_SAMPLES_FOR_ANALYSIS) {
        result.reason = "Insufficient data";
        return result;
    }

    // Calculate intervals between clicks
    std::vector<double> intervals;
    for (size_t i = 1; i < m_clickHistory.size(); i++) {
        double interval = static_cast<double>(
            m_clickHistory[i].timestamp - m_clickHistory[i - 1].timestamp);
        intervals.push_back(interval);
    }

    result.meanInterval = CalculateMean(intervals);
    result.variance = CalculateVariance(intervals);
    result.autocorrelation = CalculateAutocorrelation(intervals);

    // Check for impossibly fast clicking
    if (result.meanInterval < m_minClickInterval) {
        result.isSuspicious = true;
        result.confidence = 0.95;
        result.reason = "Click rate exceeds human capability";
        return result;
    }

    // Check clicks per second
    double cps = 1000.0 / result.meanInterval;
    if (cps > m_maxClicksPerSecond) {
        result.isSuspicious = true;
        result.confidence = 0.90;
        result.reason = "Excessive clicks per second: " + std::to_string(cps);
        return result;
    }

    // Check for constant timing (autoclicker signature)
    if (DetectConstantTiming(intervals)) {
        result.isSuspicious = true;
        result.confidence = 0.85;
        result.reason = "Suspiciously consistent click timing (variance: " +
                       std::to_string(result.variance) + ")";
        return result;
    }

    // Check for periodic patterns
    if (DetectPeriodicPattern(intervals)) {
        result.isSuspicious = true;
        result.confidence = 0.80;
        result.reason = "Periodic click pattern detected (autocorr: " +
                       std::to_string(result.autocorrelation) + ")";
        return result;
    }

    // Check against calibration data
    if (DetectStatisticalAnomaly(intervals)) {
        result.isSuspicious = true;
        result.confidence = 0.70;
        result.reason = "Click pattern deviates from calibrated baseline";
        return result;
    }

    return result;
}

MacroDetector::AnalysisResult MacroDetector::AnalyzeKeyPattern(DWORD vkCode) {
    AnalysisResult result = {};
    result.isSuspicious = false;

    std::lock_guard<std::mutex> lock(m_mutex);

    const std::deque<KeyEvent>* history = nullptr;

    if (vkCode != 0) {
        auto it = m_keyHistoryByKey.find(vkCode);
        if (it == m_keyHistoryByKey.end() || it->second.size() < MIN_SAMPLES_FOR_ANALYSIS) {
            result.reason = "Insufficient data for key";
            return result;
        }
        history = &it->second;
    } else {
        if (m_keyHistory.size() < MIN_SAMPLES_FOR_ANALYSIS) {
            result.reason = "Insufficient data";
            return result;
        }
        history = &m_keyHistory;
    }

    // Calculate intervals
    std::vector<double> intervals;
    for (size_t i = 1; i < history->size(); i++) {
        if ((*history)[i].isDown && (*history)[i - 1].isDown) {
            double interval = static_cast<double>(
                (*history)[i].timestamp - (*history)[i - 1].timestamp);
            intervals.push_back(interval);
        }
    }

    if (intervals.size() < MIN_SAMPLES_FOR_ANALYSIS / 2) {
        result.reason = "Insufficient key-down events";
        return result;
    }

    result.meanInterval = CalculateMean(intervals);
    result.variance = CalculateVariance(intervals);
    result.autocorrelation = CalculateAutocorrelation(intervals);

    // Similar checks as click analysis
    if (result.variance < m_varianceThreshold) {
        result.isSuspicious = true;
        result.confidence = 0.85;
        result.reason = "Suspiciously consistent key timing";
    }

    return result;
}

bool MacroDetector::IsAutoclickerDetected() {
    AnalysisResult result = AnalyzeClickPattern();
    return result.isSuspicious && result.confidence > 0.7;
}

bool MacroDetector::IsAutoKeyerDetected(DWORD vkCode) {
    AnalysisResult result = AnalyzeKeyPattern(vkCode);
    return result.isSuspicious && result.confidence > 0.7;
}

// ============================================================================
// CALIBRATION
// ============================================================================

void MacroDetector::StartCalibration() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_calibrating = true;
    m_calibration = {};
    ClearHistory();
}

void MacroDetector::EndCalibration() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_calibrating = false;

    if (m_clickHistory.size() >= MIN_SAMPLES_FOR_ANALYSIS) {
        std::vector<double> intervals;
        for (size_t i = 1; i < m_clickHistory.size(); i++) {
            double interval = static_cast<double>(
                m_clickHistory[i].timestamp - m_clickHistory[i - 1].timestamp);
            intervals.push_back(interval);
        }

        double mean = CalculateMean(intervals);
        double variance = CalculateVariance(intervals);
        double stddev = std::sqrt(variance);

        m_calibration.minVariance = variance * 0.5;
        m_calibration.maxVariance = variance * 2.0;
        m_calibration.minMeanInterval = mean - 2 * stddev;
        m_calibration.maxMeanInterval = mean + 2 * stddev;
        m_calibration.sampleCount = static_cast<int>(m_clickHistory.size());
        m_calibration.isCalibrated = true;
    }
}

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

void MacroDetector::ClearHistory() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_clickHistory.clear();
    m_keyHistory.clear();
    m_keyHistoryByKey.clear();
}

} // namespace AntiCheat
