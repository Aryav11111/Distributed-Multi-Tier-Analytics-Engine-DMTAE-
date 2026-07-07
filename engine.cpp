#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cctype>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
using socket_t = SOCKET;
static constexpr socket_t invalid_socket_value = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t invalid_socket_value = -1;
#endif

namespace dmtae {

using Clock = std::chrono::steady_clock;
using SystemClock = std::chrono::system_clock;

static std::atomic_bool g_running{true};

void handleSignal(int) {
    g_running.store(false);
}

uint64_t unixMillis() {
    const auto now = SystemClock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

std::string isoUtcNow() {
    const auto now = SystemClock::now();
    const auto tt = SystemClock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

double clampDouble(double value, double low, double high) {
    return std::max(low, std::min(value, high));
}

std::string trim(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return "";
    }
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

std::string jsonEscape(const std::string& value) {
    std::ostringstream out;
    for (char c : value) {
        switch (c) {
            case '\\':
                out << "\\\\";
                break;
            case '"':
                out << "\\\"";
                break;
            case '\b':
                out << "\\b";
                break;
            case '\f':
                out << "\\f";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(static_cast<unsigned char>(c)) << std::dec;
                } else {
                    out << c;
                }
                break;
        }
    }
    return out.str();
}

struct TelemetryConfig {
    uint16_t formatVersion = 1;
    uint16_t engineTcpPort = 8080;
    uint16_t middlewareHttpPort = 5000;
    uint32_t syntheticIngestIntervalMs = 250;
    uint32_t decayScanIntervalMs = 1000;
    uint64_t baseRetentionWeightMs = 15000;
    uint64_t maxActiveMetrics = 512;
    uint32_t evictionThresholdPpm = 150000;
    uint32_t healthyThresholdPpm = 600000;
    uint64_t maxPayloadBytes = 4096;
    uint32_t streamHeartbeatMs = 1000;
    uint64_t metricWeightFloorMs = 4000;
    uint64_t metricWeightCeilingMs = 60000;

    double evictionThreshold() const {
        return static_cast<double>(evictionThresholdPpm) / 1000000.0;
    }

    double healthyThreshold() const {
        return static_cast<double>(healthyThresholdPpm) / 1000000.0;
    }
};

class BinaryConfigStore {
public:
    explicit BinaryConfigStore(std::string path) : path_(std::move(path)) {}

    TelemetryConfig loadOrInitialize() const {
        auto loaded = tryLoad();
        if (loaded.has_value()) {
            return loaded.value();
        }
        TelemetryConfig defaults;
        write(defaults);
        return defaults;
    }

private:
    static constexpr std::array<uint8_t, 8> kMagic{{'D', 'M', 'T', 'A', 'E', 'C', 'F', 'G'}};

    static uint32_t fnv1a(const std::vector<uint8_t>& bytes, size_t count) {
        uint32_t hash = 2166136261u;
        for (size_t i = 0; i < count; ++i) {
            hash ^= bytes[i];
            hash *= 16777619u;
        }
        return hash;
    }

    static void appendU16(std::vector<uint8_t>& out, uint16_t value) {
        out.push_back(static_cast<uint8_t>((value >> 8) & 0xffu));
        out.push_back(static_cast<uint8_t>(value & 0xffu));
    }

    static void appendU32(std::vector<uint8_t>& out, uint32_t value) {
        out.push_back(static_cast<uint8_t>((value >> 24) & 0xffu));
        out.push_back(static_cast<uint8_t>((value >> 16) & 0xffu));
        out.push_back(static_cast<uint8_t>((value >> 8) & 0xffu));
        out.push_back(static_cast<uint8_t>(value & 0xffu));
    }

    static void appendU64(std::vector<uint8_t>& out, uint64_t value) {
        out.push_back(static_cast<uint8_t>((value >> 56) & 0xffu));
        out.push_back(static_cast<uint8_t>((value >> 48) & 0xffu));
        out.push_back(static_cast<uint8_t>((value >> 40) & 0xffu));
        out.push_back(static_cast<uint8_t>((value >> 32) & 0xffu));
        out.push_back(static_cast<uint8_t>((value >> 24) & 0xffu));
        out.push_back(static_cast<uint8_t>((value >> 16) & 0xffu));
        out.push_back(static_cast<uint8_t>((value >> 8) & 0xffu));
        out.push_back(static_cast<uint8_t>(value & 0xffu));
    }

    static uint16_t readU16(const std::vector<uint8_t>& bytes, size_t& offset) {
        if (offset + 2 > bytes.size()) {
            throw std::runtime_error("config underrun while reading u16");
        }
        const uint16_t value = static_cast<uint16_t>((static_cast<uint16_t>(bytes[offset]) << 8) |
                                                     static_cast<uint16_t>(bytes[offset + 1]));
        offset += 2;
        return value;
    }

    static uint32_t readU32(const std::vector<uint8_t>& bytes, size_t& offset) {
        if (offset + 4 > bytes.size()) {
            throw std::runtime_error("config underrun while reading u32");
        }
        const uint32_t value = (static_cast<uint32_t>(bytes[offset]) << 24) |
                               (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
                               (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
                               static_cast<uint32_t>(bytes[offset + 3]);
        offset += 4;
        return value;
    }

    static uint64_t readU64(const std::vector<uint8_t>& bytes, size_t& offset) {
        if (offset + 8 > bytes.size()) {
            throw std::runtime_error("config underrun while reading u64");
        }
        const uint64_t value = (static_cast<uint64_t>(bytes[offset]) << 56) |
                               (static_cast<uint64_t>(bytes[offset + 1]) << 48) |
                               (static_cast<uint64_t>(bytes[offset + 2]) << 40) |
                               (static_cast<uint64_t>(bytes[offset + 3]) << 32) |
                               (static_cast<uint64_t>(bytes[offset + 4]) << 24) |
                               (static_cast<uint64_t>(bytes[offset + 5]) << 16) |
                               (static_cast<uint64_t>(bytes[offset + 6]) << 8) |
                               static_cast<uint64_t>(bytes[offset + 7]);
        offset += 8;
        return value;
    }

    static TelemetryConfig sanitized(TelemetryConfig config) {
        TelemetryConfig defaults;
        if (config.formatVersion != 1) {
            return defaults;
        }
        if (config.engineTcpPort == 0) {
            config.engineTcpPort = defaults.engineTcpPort;
        }
        if (config.middlewareHttpPort == 0) {
            config.middlewareHttpPort = defaults.middlewareHttpPort;
        }
        config.syntheticIngestIntervalMs = std::max<uint32_t>(50, config.syntheticIngestIntervalMs);
        config.decayScanIntervalMs = std::max<uint32_t>(100, config.decayScanIntervalMs);
        config.baseRetentionWeightMs = std::max<uint64_t>(1000, config.baseRetentionWeightMs);
        config.maxActiveMetrics = clampU64(config.maxActiveMetrics, 32, 20000);
        config.evictionThresholdPpm = clampU32(config.evictionThresholdPpm, 10000, 950000);
        config.healthyThresholdPpm = clampU32(config.healthyThresholdPpm, config.evictionThresholdPpm + 10000, 990000);
        config.maxPayloadBytes = clampU64(config.maxPayloadBytes, 256, 1048576);
        config.streamHeartbeatMs = std::max<uint32_t>(250, config.streamHeartbeatMs);
        config.metricWeightFloorMs = clampU64(config.metricWeightFloorMs, 500, 300000);
        config.metricWeightCeilingMs = clampU64(config.metricWeightCeilingMs, config.metricWeightFloorMs, 600000);
        return config;
    }

    static uint32_t clampU32(uint32_t value, uint32_t low, uint32_t high) {
        return std::max(low, std::min(value, high));
    }

    static uint64_t clampU64(uint64_t value, uint64_t low, uint64_t high) {
        return std::max(low, std::min(value, high));
    }

    std::optional<TelemetryConfig> tryLoad() const {
        std::ifstream in(path_, std::ios::binary);
        if (!in.good()) {
            return std::nullopt;
        }
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        constexpr size_t minimumSize = 8 + 2 + 2 + 2 + 4 + 4 + 8 + 8 + 4 + 4 + 8 + 4 + 8 + 8 + 4;
        if (bytes.size() != minimumSize) {
            return std::nullopt;
        }
        for (size_t i = 0; i < kMagic.size(); ++i) {
            if (bytes[i] != kMagic[i]) {
                return std::nullopt;
            }
        }
        const uint32_t actualChecksum = readChecksumAtEnd(bytes);
        const uint32_t expectedChecksum = fnv1a(bytes, bytes.size() - 4);
        if (actualChecksum != expectedChecksum) {
            return std::nullopt;
        }

        size_t offset = kMagic.size();
        TelemetryConfig config;
        config.formatVersion = readU16(bytes, offset);
        config.engineTcpPort = readU16(bytes, offset);
        config.middlewareHttpPort = readU16(bytes, offset);
        config.syntheticIngestIntervalMs = readU32(bytes, offset);
        config.decayScanIntervalMs = readU32(bytes, offset);
        config.baseRetentionWeightMs = readU64(bytes, offset);
        config.maxActiveMetrics = readU64(bytes, offset);
        config.evictionThresholdPpm = readU32(bytes, offset);
        config.healthyThresholdPpm = readU32(bytes, offset);
        config.maxPayloadBytes = readU64(bytes, offset);
        config.streamHeartbeatMs = readU32(bytes, offset);
        config.metricWeightFloorMs = readU64(bytes, offset);
        config.metricWeightCeilingMs = readU64(bytes, offset);
        return sanitized(config);
    }

    static uint32_t readChecksumAtEnd(const std::vector<uint8_t>& bytes) {
        size_t offset = bytes.size() - 4;
        return readU32(bytes, offset);
    }

    void write(const TelemetryConfig& config) const {
        std::vector<uint8_t> bytes;
        bytes.insert(bytes.end(), kMagic.begin(), kMagic.end());
        appendU16(bytes, config.formatVersion);
        appendU16(bytes, config.engineTcpPort);
        appendU16(bytes, config.middlewareHttpPort);
        appendU32(bytes, config.syntheticIngestIntervalMs);
        appendU32(bytes, config.decayScanIntervalMs);
        appendU64(bytes, config.baseRetentionWeightMs);
        appendU64(bytes, config.maxActiveMetrics);
        appendU32(bytes, config.evictionThresholdPpm);
        appendU32(bytes, config.healthyThresholdPpm);
        appendU64(bytes, config.maxPayloadBytes);
        appendU32(bytes, config.streamHeartbeatMs);
        appendU64(bytes, config.metricWeightFloorMs);
        appendU64(bytes, config.metricWeightCeilingMs);
        appendU32(bytes, fnv1a(bytes, bytes.size()));

        std::ofstream out(path_, std::ios::binary | std::ios::trunc);
        if (!out.good()) {
            throw std::runtime_error("unable to create storage.dat");
        }
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }

    std::string path_;
};

template <typename T>
class BlockingQueue {
public:
    explicit BlockingQueue(size_t maxDepth) : maxDepth_(maxDepth) {}

    bool push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        notFull_.wait(lock, [&]() { return closed_ || queue_.size() < maxDepth_; });
        if (closed_) {
            return false;
        }
        queue_.push(std::move(item));
        notEmpty_.notify_one();
        return true;
    }

    bool waitPop(T& item, const std::atomic_bool& running) {
        std::unique_lock<std::mutex> lock(mutex_);
        notEmpty_.wait(lock, [&]() { return closed_ || !queue_.empty() || !running.load(); });
        if (queue_.empty()) {
            return false;
        }
        item = std::move(queue_.front());
        queue_.pop();
        notFull_.notify_one();
        return true;
    }

    void close() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        notFull_.notify_all();
        notEmpty_.notify_all();
    }

    size_t depth() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable notEmpty_;
    std::condition_variable notFull_;
    std::queue<T> queue_;
    size_t maxDepth_;
    bool closed_ = false;
};

struct MetricPacket {
    uint64_t id = 0;
    std::string metric;
    double value = 0.0;
    uint64_t createdAtMs = 0;
};

struct MetricRecord {
    MetricPacket packet;
    Clock::time_point insertedAt;
    double weightSeconds = 1.0;
    double retention = 1.0;
    std::string state = "healthy";
};

struct EngineStats {
    std::atomic<uint64_t> rawReceived{0};
    std::atomic<uint64_t> parsed{0};
    std::atomic<uint64_t> malformed{0};
    std::atomic<uint64_t> evicted{0};
    std::atomic<uint64_t> streamed{0};
    Clock::time_point startedAt = Clock::now();

    double throughputPerSecond() const {
        const auto elapsed = std::chrono::duration<double>(Clock::now() - startedAt).count();
        if (elapsed <= 0.0) {
            return 0.0;
        }
        return static_cast<double>(parsed.load()) / elapsed;
    }
};

class RawLogParser {
public:
    explicit RawLogParser(TelemetryConfig config) : config_(config) {}

    std::optional<MetricPacket> parse(const std::string& raw, uint64_t id) const {
        if (raw.size() > config_.maxPayloadBytes) {
            return std::nullopt;
        }
        const std::string line = trim(raw);
        if (line.empty()) {
            return std::nullopt;
        }

        std::string metric;
        double value = 0.0;
        if (parseJsonLike(line, metric, value) || parseLogfmt(line, metric, value) || parseAssignment(line, metric, value)) {
            if (!isMetricNameValid(metric) || !std::isfinite(value)) {
                return std::nullopt;
            }
            MetricPacket packet;
            packet.id = id;
            packet.metric = metric;
            packet.value = value;
            packet.createdAtMs = unixMillis();
            return packet;
        }
        return std::nullopt;
    }

private:
    static bool parseJsonLike(const std::string& line, std::string& metric, double& value) {
        static const std::regex metricPattern(R"json("metric"\s*:\s*"([A-Za-z][A-Za-z0-9_.:-]{0,63})")json");
        static const std::regex valuePattern(R"json("value"\s*:\s*(-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?))json");
        std::smatch metricMatch;
        std::smatch valueMatch;
        if (!std::regex_search(line, metricMatch, metricPattern) || !std::regex_search(line, valueMatch, valuePattern)) {
            return false;
        }
        metric = metricMatch[1].str();
        value = std::stod(valueMatch[1].str());
        return true;
    }

    static bool parseLogfmt(const std::string& line, std::string& metric, double& value) {
        static const std::regex metricPattern(R"((?:^|\s)(?:metric|name)=([A-Za-z][A-Za-z0-9_.:-]{0,63})(?:\s|$))");
        static const std::regex valuePattern(R"((?:^|\s)value=(-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)(?:\s|$))");
        std::smatch metricMatch;
        std::smatch valueMatch;
        if (!std::regex_search(line, metricMatch, metricPattern) || !std::regex_search(line, valueMatch, valuePattern)) {
            return false;
        }
        metric = metricMatch[1].str();
        value = std::stod(valueMatch[1].str());
        return true;
    }

    static bool parseAssignment(const std::string& line, std::string& metric, double& value) {
        static const std::regex pattern(R"(^\s*([A-Za-z][A-Za-z0-9_.:-]{0,63})\s*[:=]\s*(-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)\s*$)");
        std::smatch match;
        if (!std::regex_match(line, match, pattern)) {
            return false;
        }
        metric = match[1].str();
        value = std::stod(match[2].str());
        return true;
    }

    static bool isMetricNameValid(const std::string& metric) {
        if (metric.empty() || metric.size() > 64) {
            return false;
        }
        return std::all_of(metric.begin(), metric.end(), [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == ':' || c == '-';
        });
    }

    TelemetryConfig config_;
};

class EbbinghausDecay {
public:
    explicit EbbinghausDecay(TelemetryConfig config) : config_(config) {}

    double weightFor(const MetricPacket& packet) const {
        const double baseSeconds = static_cast<double>(config_.baseRetentionWeightMs) / 1000.0;
        const double valueInfluence = std::log1p(std::abs(packet.value)) * 1.7;
        const double metricBias = metricBiasSeconds(packet.metric);
        const double floorSeconds = static_cast<double>(config_.metricWeightFloorMs) / 1000.0;
        const double ceilingSeconds = static_cast<double>(config_.metricWeightCeilingMs) / 1000.0;
        return clampDouble(baseSeconds + valueInfluence + metricBias, floorSeconds, ceilingSeconds);
    }

    double retentionFor(const MetricRecord& record, Clock::time_point now) const {
        const double elapsed = std::chrono::duration<double>(now - record.insertedAt).count();
        const double safeWeight = std::max(0.001, record.weightSeconds);
        return clampDouble(std::exp(-elapsed / safeWeight), 0.0, 1.0);
    }

    std::string stateFor(double retention) const {
        if (retention < config_.evictionThreshold()) {
            return "evicted";
        }
        if (retention < config_.healthyThreshold()) {
            return "decaying";
        }
        return "healthy";
    }

private:
    static double metricBiasSeconds(const std::string& metric) {
        if (metric.find("error") != std::string::npos || metric.find("fault") != std::string::npos) {
            return -3.0;
        }
        if (metric.find("latency") != std::string::npos || metric.find("queue") != std::string::npos) {
            return -1.5;
        }
        if (metric.find("memory") != std::string::npos || metric.find("throughput") != std::string::npos) {
            return 2.0;
        }
        return 0.0;
    }

    TelemetryConfig config_;
};

class ActiveMetricCache {
public:
    explicit ActiveMetricCache(TelemetryConfig config) : config_(config), decay_(config) {}

    std::vector<MetricRecord> insert(const MetricPacket& packet) {
        MetricRecord record;
        record.packet = packet;
        record.insertedAt = Clock::now();
        record.weightSeconds = decay_.weightFor(packet);
        record.retention = 1.0;
        record.state = "healthy";

        std::lock_guard<std::mutex> lock(mutex_);
        cache_[packet.id] = record;
        return enforceCapacityLocked();
    }

    std::pair<std::vector<MetricRecord>, std::vector<MetricRecord>> scanAndEvict() {
        std::vector<MetricRecord> active;
        std::vector<MetricRecord> evicted;
        const auto now = Clock::now();
        std::lock_guard<std::mutex> lock(mutex_);

        for (auto it = cache_.begin(); it != cache_.end();) {
            it->second.retention = decay_.retentionFor(it->second, now);
            it->second.state = decay_.stateFor(it->second.retention);
            if (it->second.retention < config_.evictionThreshold()) {
                MetricRecord removed = it->second;
                removed.retention = it->second.retention;
                removed.state = "evicted";
                evicted.push_back(removed);
                it = cache_.erase(it);
            } else {
                active.push_back(it->second);
                ++it;
            }
        }
        return {active, evicted};
    }

    std::vector<MetricRecord> snapshot() const {
        std::vector<MetricRecord> records;
        const auto now = Clock::now();
        std::lock_guard<std::mutex> lock(mutex_);
        records.reserve(cache_.size());
        for (const auto& pair : cache_) {
            MetricRecord copy = pair.second;
            copy.retention = decay_.retentionFor(copy, now);
            copy.state = decay_.stateFor(copy.retention);
            records.push_back(std::move(copy));
        }
        std::sort(records.begin(), records.end(), [](const MetricRecord& left, const MetricRecord& right) {
            return left.packet.id > right.packet.id;
        });
        return records;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cache_.size();
    }

    uint64_t estimateMemoryBytes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t total = static_cast<uint64_t>(sizeof(*this));
        for (const auto& pair : cache_) {
            total += static_cast<uint64_t>(sizeof(pair));
            total += static_cast<uint64_t>(pair.second.packet.metric.capacity());
        }
        return total;
    }

private:
    std::vector<MetricRecord> enforceCapacityLocked() {
        std::vector<MetricRecord> evicted;
        while (cache_.size() > config_.maxActiveMetrics) {
            auto oldest = std::min_element(cache_.begin(), cache_.end(), [](const auto& left, const auto& right) {
                return left.second.retention < right.second.retention;
            });
            if (oldest == cache_.end()) {
                break;
            }
            MetricRecord removed = oldest->second;
            removed.state = "evicted";
            removed.retention = std::min(removed.retention, config_.evictionThreshold() * 0.999);
            evicted.push_back(removed);
            cache_.erase(oldest);
        }
        return evicted;
    }

    TelemetryConfig config_;
    EbbinghausDecay decay_;
    mutable std::mutex mutex_;
    std::unordered_map<uint64_t, MetricRecord> cache_;
};

class EventBus {
public:
    explicit EventBus(size_t maxBacklog) : maxBacklog_(maxBacklog) {}

    void publish(std::string payload) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            events_.push_back({++nextSequence_, std::move(payload)});
            while (events_.size() > maxBacklog_) {
                events_.pop_front();
            }
        }
        cv_.notify_all();
    }

    uint64_t cursorFromNow() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return nextSequence_;
    }

    std::vector<std::string> waitFor(uint64_t& cursor, const std::atomic_bool& running, uint32_t timeoutMs) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [&]() {
            return nextSequence_ > cursor || !running.load();
        });
        std::vector<std::string> payloads;
        if (!running.load()) {
            return payloads;
        }
        if (!events_.empty() && cursor < events_.front().sequence - 1) {
            cursor = events_.front().sequence - 1;
        }
        for (const auto& event : events_) {
            if (event.sequence > cursor) {
                payloads.push_back(event.payload);
            }
        }
        if (!payloads.empty()) {
            cursor = events_.back().sequence;
        }
        return payloads;
    }

private:
    struct EventEnvelope {
        uint64_t sequence;
        std::string payload;
    };

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<EventEnvelope> events_;
    uint64_t nextSequence_ = 0;
    size_t maxBacklog_;
};

std::string serializeMetricEvent(const MetricRecord& record,
                                 const TelemetryConfig& config,
                                 const EngineStats& stats,
                                 size_t activeCacheSize,
                                 uint64_t memoryBytes,
                                 bool evicted) {
    const double ageSeconds = std::max<uint64_t>(0, unixMillis() - record.packet.createdAtMs) / 1000.0;
    std::ostringstream out;
    out << std::fixed << std::setprecision(6);
    out << "{";
    out << "\"schema\":\"dmtae.metric.v1\",";
    out << "\"event\":\"metric_update\",";
    out << "\"generated_at\":\"" << isoUtcNow() << "\",";
    out << "\"id\":" << record.packet.id << ",";
    out << "\"metric\":\"" << jsonEscape(record.packet.metric) << "\",";
    out << "\"value\":" << record.packet.value << ",";
    out << "\"created_at_ms\":" << record.packet.createdAtMs << ",";
    out << "\"age_seconds\":" << ageSeconds << ",";
    out << "\"weight_seconds\":" << record.weightSeconds << ",";
    out << "\"retention\":" << record.retention << ",";
    out << "\"state\":\"" << (evicted ? "evicted" : record.state) << "\",";
    out << "\"evicted\":" << (evicted ? "true" : "false") << ",";
    out << "\"active_cache_size\":" << activeCacheSize << ",";
    out << "\"active_cache_capacity\":" << config.maxActiveMetrics << ",";
    out << "\"memory_bytes\":" << memoryBytes << ",";
    out << "\"raw_received_total\":" << stats.rawReceived.load() << ",";
    out << "\"parsed_total\":" << stats.parsed.load() << ",";
    out << "\"malformed_total\":" << stats.malformed.load() << ",";
    out << "\"evicted_total\":" << stats.evicted.load() << ",";
    out << "\"throughput_per_second\":" << stats.throughputPerSecond();
    out << "}";
    return out.str();
}

std::string serializeHeartbeat(const TelemetryConfig& config,
                               const EngineStats& stats,
                               const ActiveMetricCache& cache) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(6);
    out << "{";
    out << "\"schema\":\"dmtae.metric.v1\",";
    out << "\"event\":\"heartbeat\",";
    out << "\"generated_at\":\"" << isoUtcNow() << "\",";
    out << "\"active_cache_size\":" << cache.size() << ",";
    out << "\"active_cache_capacity\":" << config.maxActiveMetrics << ",";
    out << "\"memory_bytes\":" << cache.estimateMemoryBytes() << ",";
    out << "\"raw_received_total\":" << stats.rawReceived.load() << ",";
    out << "\"parsed_total\":" << stats.parsed.load() << ",";
    out << "\"malformed_total\":" << stats.malformed.load() << ",";
    out << "\"evicted_total\":" << stats.evicted.load() << ",";
    out << "\"throughput_per_second\":" << stats.throughputPerSecond();
    out << "}";
    return out.str();
}

class EnginePipeline {
public:
    EnginePipeline(BlockingQueue<std::string>& queue,
                   ActiveMetricCache& cache,
                   EventBus& bus,
                   EngineStats& stats,
                   TelemetryConfig config)
        : queue_(queue), cache_(cache), bus_(bus), stats_(stats), config_(config), parser_(config) {}

    void start() {
        parserThread_ = std::thread(&EnginePipeline::parserLoop, this);
        decayThread_ = std::thread(&EnginePipeline::decayLoop, this);
    }

    void stop() {
        queue_.close();
        if (parserThread_.joinable()) {
            parserThread_.join();
        }
        if (decayThread_.joinable()) {
            decayThread_.join();
        }
    }

private:
    void parserLoop() {
        while (g_running.load()) {
            std::string raw;
            if (!queue_.waitPop(raw, g_running)) {
                continue;
            }
            stats_.rawReceived.fetch_add(1);
            const auto id = nextId_.fetch_add(1);
            auto packet = parser_.parse(raw, id);
            if (!packet.has_value()) {
                stats_.malformed.fetch_add(1);
                continue;
            }

            stats_.parsed.fetch_add(1);
            auto forcedEvictions = cache_.insert(packet.value());
            const size_t activeSize = cache_.size();
            const uint64_t memoryBytes = cache_.estimateMemoryBytes();

            MetricRecord inserted;
            inserted.packet = packet.value();
            inserted.insertedAt = Clock::now();
            inserted.weightSeconds = EbbinghausDecay(config_).weightFor(packet.value());
            inserted.retention = 1.0;
            inserted.state = "healthy";
            bus_.publish(serializeMetricEvent(inserted, config_, stats_, activeSize, memoryBytes, false));

            for (const auto& evicted : forcedEvictions) {
                stats_.evicted.fetch_add(1);
                bus_.publish(serializeMetricEvent(evicted, config_, stats_, cache_.size(), cache_.estimateMemoryBytes(), true));
            }
        }
    }

    void decayLoop() {
        while (g_running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.decayScanIntervalMs));
            auto [active, evicted] = cache_.scanAndEvict();
            const size_t activeSize = cache_.size();
            const uint64_t memoryBytes = cache_.estimateMemoryBytes();
            for (const auto& removed : evicted) {
                stats_.evicted.fetch_add(1);
                bus_.publish(serializeMetricEvent(removed, config_, stats_, activeSize, memoryBytes, true));
            }
            for (const auto& record : active) {
                bus_.publish(serializeMetricEvent(record, config_, stats_, activeSize, memoryBytes, false));
            }
        }
    }

    BlockingQueue<std::string>& queue_;
    ActiveMetricCache& cache_;
    EventBus& bus_;
    EngineStats& stats_;
    TelemetryConfig config_;
    RawLogParser parser_;
    std::atomic<uint64_t> nextId_{1};
    std::thread parserThread_;
    std::thread decayThread_;
};

class SyntheticTelemetrySource {
public:
    SyntheticTelemetrySource(BlockingQueue<std::string>& queue, TelemetryConfig config)
        : queue_(queue), config_(config), rng_(std::random_device{}()) {}

    void start() {
        worker_ = std::thread(&SyntheticTelemetrySource::run, this);
    }

    void stop() {
        if (worker_.joinable()) {
            worker_.join();
        }
    }

private:
    void run() {
        const std::array<std::string, 10> metrics{{
            "cpu.load",
            "memory.rss",
            "ingest.queue.depth",
            "request.latency.p95",
            "disk.io.wait",
            "cache.hit_ratio",
            "network.egress.mbps",
            "stream.throughput",
            "worker.error_rate",
            "scheduler.backpressure"
        }};
        std::normal_distribution<double> jitter(0.0, 4.5);
        uint64_t tick = 0;
        while (g_running.load()) {
            const size_t index = static_cast<size_t>(tick % metrics.size());
            const double wave = std::sin(static_cast<double>(tick) / 8.0) * 18.0;
            double base = 50.0 + wave + jitter(rng_);
            if (metrics[index].find("hit_ratio") != std::string::npos) {
                base = clampDouble(92.0 - std::abs(wave) * 0.7 + jitter(rng_) * 0.25, 0.0, 100.0);
            } else if (metrics[index].find("error_rate") != std::string::npos) {
                base = clampDouble(std::abs(jitter(rng_)) * 0.8 + (tick % 37 == 0 ? 12.0 : 0.4), 0.0, 100.0);
            } else if (metrics[index].find("queue") != std::string::npos) {
                base = clampDouble(20.0 + std::abs(wave) * 1.4 + std::abs(jitter(rng_)), 0.0, 200.0);
            } else {
                base = clampDouble(base, 0.0, 100.0);
            }

            std::ostringstream raw;
            raw << "metric=" << metrics[index] << " value=" << std::fixed << std::setprecision(4) << base;
            queue_.push(raw.str());
            ++tick;
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.syntheticIngestIntervalMs));
        }
    }

    BlockingQueue<std::string>& queue_;
    TelemetryConfig config_;
    std::mt19937_64 rng_;
    std::thread worker_;
};

class SocketRuntime {
public:
    SocketRuntime() {
#ifdef _WIN32
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif
    }

    ~SocketRuntime() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
};

void closeSocket(socket_t socket) {
    if (socket == invalid_socket_value) {
        return;
    }
#ifdef _WIN32
    closesocket(socket);
#else
    close(socket);
#endif
}

bool setNonBlocking(socket_t socket) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(socket, FIONBIO, &mode) == 0;
#else
    const int flags = fcntl(socket, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return fcntl(socket, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

bool lastSocketErrorWouldBlock() {
#ifdef _WIN32
    const int error = WSAGetLastError();
    return error == WSAEWOULDBLOCK || error == WSAEINTR;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

bool sendAll(socket_t socket, const std::string& payload) {
    const char* data = payload.data();
    size_t remaining = payload.size();
    while (remaining > 0 && g_running.load()) {
#ifdef _WIN32
        const int sent = send(socket, data, static_cast<int>(std::min<size_t>(remaining, std::numeric_limits<int>::max())), 0);
#else
        #ifdef MSG_NOSIGNAL
        const int flags = MSG_NOSIGNAL;
        #else
        const int flags = 0;
        #endif
        const ssize_t sent = send(socket, data, remaining, flags);
#endif
        if (sent > 0) {
            data += sent;
            remaining -= static_cast<size_t>(sent);
            continue;
        }
        if (lastSocketErrorWouldBlock()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        return false;
    }
    return remaining == 0;
}

class TcpMetricServer {
public:
    TcpMetricServer(TelemetryConfig config, EventBus& bus, ActiveMetricCache& cache, EngineStats& stats)
        : config_(config), bus_(bus), cache_(cache), stats_(stats) {}

    void run() {
        listenSocket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listenSocket_ == invalid_socket_value) {
            throw std::runtime_error("unable to create TCP socket");
        }

        int yes = 1;
        setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_ANY);
        address.sin_port = htons(config_.engineTcpPort);

        if (bind(listenSocket_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            closeSocket(listenSocket_);
            listenSocket_ = invalid_socket_value;
            throw std::runtime_error("unable to bind TCP port " + std::to_string(config_.engineTcpPort));
        }
        if (listen(listenSocket_, 16) != 0) {
            closeSocket(listenSocket_);
            listenSocket_ = invalid_socket_value;
            throw std::runtime_error("unable to listen on TCP port " + std::to_string(config_.engineTcpPort));
        }
        setNonBlocking(listenSocket_);

        std::cout << "DMTAE engine streaming newline-delimited JSON on TCP port "
                  << config_.engineTcpPort << std::endl;

        while (g_running.load()) {
            sockaddr_in clientAddress{};
#ifdef _WIN32
            int clientLength = sizeof(clientAddress);
#else
            socklen_t clientLength = sizeof(clientAddress);
#endif
            socket_t client = accept(listenSocket_, reinterpret_cast<sockaddr*>(&clientAddress), &clientLength);
            if (client == invalid_socket_value) {
                if (lastSocketErrorWouldBlock()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                continue;
            }

            setNonBlocking(client);
            std::string peer = describePeer(clientAddress);
            clientThreads_.emplace_back(&TcpMetricServer::clientLoop, this, client, peer);
        }

        closeSocket(listenSocket_);
        listenSocket_ = invalid_socket_value;
        for (auto& thread : clientThreads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
    }

private:
    static std::string describePeer(const sockaddr_in& address) {
        char buffer[INET_ADDRSTRLEN] = {0};
        const char* converted = inet_ntop(AF_INET, &address.sin_addr, buffer, sizeof(buffer));
        if (converted == nullptr) {
            return "unknown";
        }
        std::ostringstream out;
        out << converted << ":" << ntohs(address.sin_port);
        return out.str();
    }

    void clientLoop(socket_t client, const std::string& peer) {
        std::cout << "middleware subscriber connected from " << peer << std::endl;
        for (const auto& record : cache_.snapshot()) {
            const std::string payload = serializeMetricEvent(record, config_, stats_, cache_.size(), cache_.estimateMemoryBytes(), false) + "\n";
            if (!sendAll(client, payload)) {
                closeSocket(client);
                return;
            }
            stats_.streamed.fetch_add(1);
        }

        uint64_t cursor = bus_.cursorFromNow();
        while (g_running.load()) {
            auto payloads = bus_.waitFor(cursor, g_running, config_.streamHeartbeatMs);
            if (payloads.empty()) {
                payloads.push_back(serializeHeartbeat(config_, stats_, cache_));
            }
            for (const auto& payload : payloads) {
                if (!sendAll(client, payload + "\n")) {
                    std::cout << "middleware subscriber disconnected from " << peer << std::endl;
                    closeSocket(client);
                    return;
                }
                stats_.streamed.fetch_add(1);
            }
        }
        closeSocket(client);
    }

    TelemetryConfig config_;
    EventBus& bus_;
    ActiveMetricCache& cache_;
    EngineStats& stats_;
    socket_t listenSocket_ = invalid_socket_value;
    std::vector<std::thread> clientThreads_;
};

void printBootBanner(const TelemetryConfig& config) {
    std::cout << "DMTAE boot configuration loaded from storage.dat" << std::endl;
    std::cout << "  binary layout: magic[8], version:u16, engine_port:u16, http_port:u16,"
              << " ingest_ms:u32, scan_ms:u32, retention_ms:u64, capacity:u64,"
              << " eviction_ppm:u32, healthy_ppm:u32, payload_bytes:u64,"
              << " heartbeat_ms:u32, floor_ms:u64, ceiling_ms:u64, checksum:u32" << std::endl;
    std::cout << "  engine_port=" << config.engineTcpPort
              << " http_port=" << config.middlewareHttpPort
              << " capacity=" << config.maxActiveMetrics
              << " eviction_threshold=" << config.evictionThreshold()
              << " healthy_threshold=" << config.healthyThreshold() << std::endl;
}

}  // namespace dmtae

int main() {
    using namespace dmtae;

    std::signal(SIGINT, handleSignal);
#ifdef SIGTERM
    std::signal(SIGTERM, handleSignal);
#endif

    try {
        SocketRuntime sockets;
        BinaryConfigStore configStore("storage.dat");
        const TelemetryConfig config = configStore.loadOrInitialize();
        printBootBanner(config);

        BlockingQueue<std::string> ingestionQueue(static_cast<size_t>(config.maxActiveMetrics * 2));
        ActiveMetricCache cache(config);
        EventBus eventBus(8192);
        EngineStats stats;

        EnginePipeline pipeline(ingestionQueue, cache, eventBus, stats, config);
        SyntheticTelemetrySource source(ingestionQueue, config);

        try {
            pipeline.start();
            source.start();

            TcpMetricServer server(config, eventBus, cache, stats);
            server.run();
        } catch (...) {
            g_running.store(false);
            ingestionQueue.close();
            source.stop();
            pipeline.stop();
            throw;
        }

        g_running.store(false);
        ingestionQueue.close();
        source.stop();
        pipeline.stop();
        std::cout << "DMTAE engine stopped cleanly" << std::endl;
    } catch (const std::exception& ex) {
        std::cerr << "DMTAE engine fatal error: " << ex.what() << std::endl;
        g_running.store(false);
        return 1;
    }

    return 0;
}
