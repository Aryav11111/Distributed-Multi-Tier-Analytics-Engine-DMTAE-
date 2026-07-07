from __future__ import annotations

import json
import math
import pathlib
import socket
import threading
import time
import traceback
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Deque, Dict, Iterable, List, Tuple
from urllib.parse import urlparse


CONFIG_MAGIC = b"DMTAECFG"


@dataclass(frozen=True)
class TelemetryConfig:
    format_version: int = 1
    engine_tcp_port: int = 8080
    middleware_http_port: int = 5000
    synthetic_ingest_interval_ms: int = 250
    decay_scan_interval_ms: int = 1000
    base_retention_weight_ms: int = 15000
    max_active_metrics: int = 512
    eviction_threshold_ppm: int = 150000
    healthy_threshold_ppm: int = 600000
    max_payload_bytes: int = 4096
    stream_heartbeat_ms: int = 1000
    metric_weight_floor_ms: int = 4000
    metric_weight_ceiling_ms: int = 60000

    @property
    def eviction_threshold(self) -> float:
        return self.eviction_threshold_ppm / 1_000_000.0

    @property
    def healthy_threshold(self) -> float:
        return self.healthy_threshold_ppm / 1_000_000.0


class BinaryConfigStore:
    def __init__(self, path: pathlib.Path) -> None:
        self.path = path

    def load_or_initialize(self) -> TelemetryConfig:
        config = self._try_load()
        if config is not None:
            return config
        defaults = TelemetryConfig()
        self.write(defaults)
        return defaults

    def write(self, config: TelemetryConfig) -> None:
        data = bytearray(CONFIG_MAGIC)
        self._append_u16(data, config.format_version)
        self._append_u16(data, config.engine_tcp_port)
        self._append_u16(data, config.middleware_http_port)
        self._append_u32(data, config.synthetic_ingest_interval_ms)
        self._append_u32(data, config.decay_scan_interval_ms)
        self._append_u64(data, config.base_retention_weight_ms)
        self._append_u64(data, config.max_active_metrics)
        self._append_u32(data, config.eviction_threshold_ppm)
        self._append_u32(data, config.healthy_threshold_ppm)
        self._append_u64(data, config.max_payload_bytes)
        self._append_u32(data, config.stream_heartbeat_ms)
        self._append_u64(data, config.metric_weight_floor_ms)
        self._append_u64(data, config.metric_weight_ceiling_ms)
        self._append_u32(data, self._fnv1a(data))
        self.path.write_bytes(bytes(data))

    def _try_load(self) -> TelemetryConfig | None:
        if not self.path.exists():
            return None
        data = self.path.read_bytes()
        expected_size = 78
        if len(data) != expected_size or not data.startswith(CONFIG_MAGIC):
            return None
        stored_checksum, _ = self._read_u32(data, len(data) - 4)
        actual_checksum = self._fnv1a(data[:-4])
        if stored_checksum != actual_checksum:
            return None

        offset = len(CONFIG_MAGIC)
        version, offset = self._read_u16(data, offset)
        engine_port, offset = self._read_u16(data, offset)
        http_port, offset = self._read_u16(data, offset)
        ingest_ms, offset = self._read_u32(data, offset)
        scan_ms, offset = self._read_u32(data, offset)
        retention_ms, offset = self._read_u64(data, offset)
        capacity, offset = self._read_u64(data, offset)
        eviction_ppm, offset = self._read_u32(data, offset)
        healthy_ppm, offset = self._read_u32(data, offset)
        payload_bytes, offset = self._read_u64(data, offset)
        heartbeat_ms, offset = self._read_u32(data, offset)
        floor_ms, offset = self._read_u64(data, offset)
        ceiling_ms, offset = self._read_u64(data, offset)

        if version != 1:
            return None

        return TelemetryConfig(
            format_version=version,
            engine_tcp_port=engine_port or 8080,
            middleware_http_port=http_port or 5000,
            synthetic_ingest_interval_ms=max(50, ingest_ms),
            decay_scan_interval_ms=max(100, scan_ms),
            base_retention_weight_ms=max(1000, retention_ms),
            max_active_metrics=min(max(32, capacity), 20_000),
            eviction_threshold_ppm=min(max(10_000, eviction_ppm), 950_000),
            healthy_threshold_ppm=min(max(eviction_ppm + 10_000, healthy_ppm), 990_000),
            max_payload_bytes=min(max(256, payload_bytes), 1_048_576),
            stream_heartbeat_ms=max(250, heartbeat_ms),
            metric_weight_floor_ms=min(max(500, floor_ms), 300_000),
            metric_weight_ceiling_ms=min(max(floor_ms, ceiling_ms), 600_000),
        )

    @staticmethod
    def _fnv1a(data: bytes | bytearray) -> int:
        value = 2166136261
        for byte in data:
            value ^= byte
            value = (value * 16777619) & 0xFFFFFFFF
        return value

    @staticmethod
    def _append_u16(buffer: bytearray, value: int) -> None:
        buffer.append((value >> 8) & 0xFF)
        buffer.append(value & 0xFF)

    @staticmethod
    def _append_u32(buffer: bytearray, value: int) -> None:
        buffer.append((value >> 24) & 0xFF)
        buffer.append((value >> 16) & 0xFF)
        buffer.append((value >> 8) & 0xFF)
        buffer.append(value & 0xFF)

    @staticmethod
    def _append_u64(buffer: bytearray, value: int) -> None:
        buffer.append((value >> 56) & 0xFF)
        buffer.append((value >> 48) & 0xFF)
        buffer.append((value >> 40) & 0xFF)
        buffer.append((value >> 32) & 0xFF)
        buffer.append((value >> 24) & 0xFF)
        buffer.append((value >> 16) & 0xFF)
        buffer.append((value >> 8) & 0xFF)
        buffer.append(value & 0xFF)

    @staticmethod
    def _read_u16(data: bytes, offset: int) -> Tuple[int, int]:
        value = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF)
        return value, offset + 2

    @staticmethod
    def _read_u32(data: bytes, offset: int) -> Tuple[int, int]:
        value = (
            ((data[offset] & 0xFF) << 24)
            | ((data[offset + 1] & 0xFF) << 16)
            | ((data[offset + 2] & 0xFF) << 8)
            | (data[offset + 3] & 0xFF)
        )
        return value, offset + 4

    @staticmethod
    def _read_u64(data: bytes, offset: int) -> Tuple[int, int]:
        value = (
            ((data[offset] & 0xFF) << 56)
            | ((data[offset + 1] & 0xFF) << 48)
            | ((data[offset + 2] & 0xFF) << 40)
            | ((data[offset + 3] & 0xFF) << 32)
            | ((data[offset + 4] & 0xFF) << 24)
            | ((data[offset + 5] & 0xFF) << 16)
            | ((data[offset + 6] & 0xFF) << 8)
            | (data[offset + 7] & 0xFF)
        )
        return value, offset + 8


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def now_ms() -> int:
    return int(time.time() * 1000)


def finite_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(number):
        return default
    return number


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(value, high))


class TelemetryStore:
    def __init__(self, config: TelemetryConfig) -> None:
        self.config = config
        self.lock = threading.RLock()
        self.active: Dict[int, Dict[str, Any]] = {}
        self.evicted: Deque[Dict[str, Any]] = deque(maxlen=240)
        self.event_times: Deque[float] = deque(maxlen=20_000)
        self.decay_samples: Deque[float] = deque(maxlen=4096)
        self.connection_errors: Deque[str] = deque(maxlen=20)
        self.engine_connected = False
        self.last_engine_event_ms = 0
        self.last_stream_error = ""
        self.raw_received_total = 0
        self.parsed_total = 0
        self.malformed_total = 0
        self.evicted_total = 0
        self.engine_memory_bytes = 0
        self.engine_throughput_per_second = 0.0
        self.started_at = time.time()

    def mark_connected(self) -> None:
        with self.lock:
            self.engine_connected = True
            self.last_stream_error = ""

    def mark_disconnected(self, reason: str) -> None:
        with self.lock:
            self.engine_connected = False
            self.last_stream_error = reason
            if reason:
                self.connection_errors.appendleft(f"{now_iso()} {reason}")

    def apply_stream_object(self, payload: Dict[str, Any]) -> None:
        event = str(payload.get("event", ""))
        with self.lock:
            self.last_engine_event_ms = now_ms()
            self.raw_received_total = int(payload.get("raw_received_total", self.raw_received_total) or self.raw_received_total)
            self.parsed_total = int(payload.get("parsed_total", self.parsed_total) or self.parsed_total)
            self.malformed_total = int(payload.get("malformed_total", self.malformed_total) or self.malformed_total)
            self.evicted_total = int(payload.get("evicted_total", self.evicted_total) or self.evicted_total)
            self.engine_memory_bytes = int(payload.get("memory_bytes", self.engine_memory_bytes) or self.engine_memory_bytes)
            self.engine_throughput_per_second = finite_float(
                payload.get("throughput_per_second", self.engine_throughput_per_second),
                self.engine_throughput_per_second,
            )
            if event == "heartbeat":
                self.event_times.append(time.time())
                return
            if event != "metric_update":
                self.malformed_total += 1
                return

            try:
                item = self._normalize_metric(payload)
            except (KeyError, TypeError, ValueError) as exc:
                self.malformed_total += 1
                self.connection_errors.appendleft(f"{now_iso()} invalid metric event: {exc}")
                return
            self.event_times.append(time.time())
            self.decay_samples.append(1.0 - item["retention"])

            if item["evicted"] or item["state"] == "evicted":
                self.active.pop(item["id"], None)
                self.evicted.appendleft(item)
                return

            self.active[item["id"]] = item
            while len(self.active) > self.config.max_active_metrics:
                oldest_id = min(self.active, key=lambda metric_id: self.active[metric_id]["retention"])
                removed = self.active.pop(oldest_id)
                removed["state"] = "evicted"
                removed["evicted"] = True
                self.evicted.appendleft(removed)

    def register_malformed_payload(self, reason: str) -> None:
        with self.lock:
            self.malformed_total += 1
            self.connection_errors.appendleft(f"{now_iso()} malformed stream payload: {reason}")

    def live_snapshot(self) -> Dict[str, Any]:
        with self.lock:
            active_items = [self._recompute_decay(dict(item)) for item in self.active.values()]
            active_items.sort(key=lambda item: item["id"], reverse=True)
            healthy = sum(1 for item in active_items if item["state"] == "healthy")
            decaying = sum(1 for item in active_items if item["state"] == "decaying")
            evicted_recent = list(self.evicted)[:80]
            cache_size = len(active_items)
            capacity = self.config.max_active_metrics
            last_age_ms = 0 if self.last_engine_event_ms == 0 else max(0, now_ms() - self.last_engine_event_ms)

            return {
                "schema": "dmtae.live.v1",
                "generatedAt": now_iso(),
                "status": {
                    "engineConnected": self.engine_connected,
                    "lastEngineEventAgeMs": last_age_ms,
                    "state": self._overall_state(healthy, decaying, cache_size, last_age_ms),
                    "lastStreamError": self.last_stream_error,
                },
                "cache": {
                    "size": cache_size,
                    "capacity": capacity,
                    "utilization": 0.0 if capacity == 0 else round(cache_size / capacity, 6),
                    "healthy": healthy,
                    "decaying": decaying,
                    "evictedRecent": len(evicted_recent),
                    "items": active_items[:250],
                    "evicted": evicted_recent,
                },
            }

    def analytics_snapshot(self) -> Dict[str, Any]:
        with self.lock:
            active_items = [self._recompute_decay(dict(item)) for item in self.active.values()]
            through_1s = self._count_events_since(1.0)
            through_10s = self._count_events_since(10.0) / 10.0
            through_60s = self._count_events_since(60.0) / 60.0
            retentions = [item["retention"] for item in active_items]
            avg_retention = sum(retentions) / len(retentions) if retentions else 0.0
            min_retention = min(retentions) if retentions else 0.0
            avg_decay_loss = sum(self.decay_samples) / len(self.decay_samples) if self.decay_samples else 0.0
            local_memory = self._estimate_local_memory(active_items)
            uptime = max(0.001, time.time() - self.started_at)

            return {
                "schema": "dmtae.analytics.v1",
                "generatedAt": now_iso(),
                "decay": {
                    "formula": "Retention = exp(-time_elapsed / weight)",
                    "evictionThreshold": self.config.eviction_threshold,
                    "healthyThreshold": self.config.healthy_threshold,
                    "averageRetention": round(avg_retention, 6),
                    "minimumRetention": round(min_retention, 6),
                    "averageDecayLoss": round(avg_decay_loss, 6),
                    "evictedTotal": self.evicted_total,
                    "evictedRecent": len(self.evicted),
                },
                "memory": {
                    "engineBytes": self.engine_memory_bytes,
                    "middlewareEstimatedBytes": local_memory,
                    "activeCacheSize": len(active_items),
                    "activeCacheCapacity": self.config.max_active_metrics,
                    "cacheUtilization": round(len(active_items) / max(1, self.config.max_active_metrics), 6),
                },
                "throughput": {
                    "streamEventsLastSecond": through_1s,
                    "streamEventsPerSecond10s": round(through_10s, 6),
                    "streamEventsPerSecond60s": round(through_60s, 6),
                    "engineParsedPerSecond": round(self.engine_throughput_per_second, 6),
                    "middlewareEventsPerSecond": round(len(self.event_times) / uptime, 6),
                    "rawReceivedTotal": self.raw_received_total,
                    "parsedTotal": self.parsed_total,
                    "malformedTotal": self.malformed_total,
                },
                "configuration": {
                    "engineTcpPort": self.config.engine_tcp_port,
                    "middlewareHttpPort": self.config.middleware_http_port,
                    "decayScanIntervalMs": self.config.decay_scan_interval_ms,
                    "streamHeartbeatMs": self.config.stream_heartbeat_ms,
                    "maxPayloadBytes": self.config.max_payload_bytes,
                },
                "connection": {
                    "engineConnected": self.engine_connected,
                    "lastEngineEventAgeMs": 0 if self.last_engine_event_ms == 0 else max(0, now_ms() - self.last_engine_event_ms),
                    "recentErrors": list(self.connection_errors),
                },
            }

    def _normalize_metric(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        metric_id = int(payload["id"])
        retention = clamp(finite_float(payload.get("retention"), 0.0), 0.0, 1.0)
        weight = max(0.001, finite_float(payload.get("weight_seconds"), self.config.base_retention_weight_ms / 1000.0))
        created_at = int(payload.get("created_at_ms") or now_ms())
        state = str(payload.get("state") or self._state_for_retention(retention))
        evicted = bool(payload.get("evicted")) or state == "evicted" or retention < self.config.eviction_threshold

        if evicted:
            state = "evicted"
        elif retention < self.config.healthy_threshold:
            state = "decaying"
        else:
            state = "healthy"

        return {
            "id": metric_id,
            "metric": str(payload.get("metric", "unknown.metric"))[:96],
            "value": finite_float(payload.get("value"), 0.0),
            "createdAtMs": created_at,
            "ageSeconds": finite_float(payload.get("age_seconds"), 0.0),
            "weightSeconds": weight,
            "retention": retention,
            "retentionPercent": round(retention * 100.0, 3),
            "state": state,
            "evicted": evicted,
            "receivedAtMs": now_ms(),
        }

    def _recompute_decay(self, item: Dict[str, Any]) -> Dict[str, Any]:
        age_seconds = max(0.0, (now_ms() - int(item.get("createdAtMs", now_ms()))) / 1000.0)
        weight = max(0.001, finite_float(item.get("weightSeconds"), self.config.base_retention_weight_ms / 1000.0))
        retention = clamp(math.exp(-age_seconds / weight), 0.0, 1.0)
        item["ageSeconds"] = round(age_seconds, 3)
        item["retention"] = round(retention, 6)
        item["retentionPercent"] = round(retention * 100.0, 3)
        item["state"] = self._state_for_retention(retention)
        item["evicted"] = item["state"] == "evicted"
        return item

    def _state_for_retention(self, retention: float) -> str:
        if retention < self.config.eviction_threshold:
            return "evicted"
        if retention < self.config.healthy_threshold:
            return "decaying"
        return "healthy"

    def _overall_state(self, healthy: int, decaying: int, cache_size: int, last_age_ms: int) -> str:
        if not self.engine_connected or last_age_ms > self.config.stream_heartbeat_ms * 5:
            return "offline"
        if cache_size == 0:
            return "warming"
        if decaying > healthy:
            return "decaying"
        return "healthy"

    def _count_events_since(self, seconds: float) -> int:
        cutoff = time.time() - seconds
        while self.event_times and self.event_times[0] < time.time() - 120.0:
            self.event_times.popleft()
        return sum(1 for event_time in self.event_times if event_time >= cutoff)

    @staticmethod
    def _estimate_local_memory(items: Iterable[Dict[str, Any]]) -> int:
        total = 0
        for item in items:
            total += 216
            total += len(str(item.get("metric", ""))) * 2
            total += len(json.dumps(item, separators=(",", ":")))
        return total


class EngineStreamClient(threading.Thread):
    def __init__(self, host: str, port: int, store: TelemetryStore, stop_event: threading.Event, max_payload_bytes: int) -> None:
        super().__init__(name="dmtae-engine-stream", daemon=True)
        self.host = host
        self.port = port
        self.store = store
        self.stop_event = stop_event
        self.max_payload_bytes = max_payload_bytes

    def run(self) -> None:
        backoff = 0.5
        while not self.stop_event.is_set():
            try:
                with socket.create_connection((self.host, self.port), timeout=5.0) as sock:
                    sock.settimeout(2.0)
                    self.store.mark_connected()
                    backoff = 0.5
                    self._read_stream(sock)
            except (OSError, TimeoutError) as exc:
                self.store.mark_disconnected(f"engine socket unavailable at {self.host}:{self.port}: {exc}")
            except Exception as exc:
                self.store.mark_disconnected(f"engine stream failure: {exc}")
                traceback.print_exc()

            if not self.stop_event.is_set():
                time.sleep(backoff)
                backoff = min(backoff * 1.7, 8.0)

    def _read_stream(self, sock: socket.socket) -> None:
        buffer = bytearray()
        while not self.stop_event.is_set():
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                continue
            if not chunk:
                self.store.mark_disconnected("engine closed TCP stream")
                return
            buffer.extend(chunk)
            if len(buffer) > self.max_payload_bytes * 8:
                buffer.clear()
                self.store.register_malformed_payload("stream frame exceeded rolling buffer budget")
                continue

            while True:
                newline_index = buffer.find(b"\n")
                if newline_index < 0:
                    break
                line = bytes(buffer[:newline_index]).strip()
                del buffer[: newline_index + 1]
                if not line:
                    continue
                if len(line) > self.max_payload_bytes:
                    self.store.register_malformed_payload("single JSON event exceeded max_payload_bytes")
                    continue
                try:
                    payload = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    self.store.register_malformed_payload(str(exc))
                    continue
                if not isinstance(payload, dict) or payload.get("schema") != "dmtae.metric.v1":
                    self.store.register_malformed_payload("invalid schema")
                    continue
                self.store.apply_stream_object(payload)


class DMTAEHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: Tuple[str, int], handler_class: type[BaseHTTPRequestHandler], store: TelemetryStore, web_root: pathlib.Path) -> None:
        super().__init__(server_address, handler_class)
        self.store = store
        self.web_root = web_root


class DMTAERequestHandler(BaseHTTPRequestHandler):
    server: DMTAEHTTPServer

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._send_common_headers("text/plain; charset=utf-8")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/metrics/live":
            self._send_json(self.server.store.live_snapshot())
            return
        if path == "/api/metrics/analytics":
            self._send_json(self.server.store.analytics_snapshot())
            return
        if path in ("/", "/index.html"):
            self._send_static_index()
            return
        self._send_json(
            {
                "schema": "dmtae.error.v1",
                "generatedAt": now_iso(),
                "error": "not_found",
                "path": path,
            },
            status=404,
        )

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._send_common_headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_static_index(self) -> None:
        index_path = self.server.web_root / "index.html"
        if not index_path.exists():
            self._send_json(
                {
                    "schema": "dmtae.error.v1",
                    "generatedAt": now_iso(),
                    "error": "dashboard_missing",
                    "path": str(index_path),
                },
                status=500,
            )
            return
        body = index_path.read_bytes()
        self.send_response(200)
        self._send_common_headers("text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_common_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent
    config = BinaryConfigStore(root / "storage.dat").load_or_initialize()
    store = TelemetryStore(config)
    stop_event = threading.Event()

    stream_client = EngineStreamClient(
        host="127.0.0.1",
        port=config.engine_tcp_port,
        store=store,
        stop_event=stop_event,
        max_payload_bytes=config.max_payload_bytes,
    )
    stream_client.start()

    httpd = DMTAEHTTPServer(("0.0.0.0", config.middleware_http_port), DMTAERequestHandler, store, root)
    http_thread = threading.Thread(target=httpd.serve_forever, name="dmtae-http-server", daemon=True)
    http_thread.start()

    print("DMTAE middleware online")
    print(f"  TCP client target: 127.0.0.1:{config.engine_tcp_port}")
    print(f"  HTTP API: http://127.0.0.1:{config.middleware_http_port}/api/metrics/live")
    print(f"  Dashboard: http://127.0.0.1:{config.middleware_http_port}/")
    print("  binary config: storage.dat")

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        httpd.shutdown()
        httpd.server_close()
        stream_client.join(timeout=3.0)
        http_thread.join(timeout=3.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
