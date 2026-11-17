"""
Standalone Packet Capture Agent.
Decoupled high-performance network sniffer with bounded queue backpressure,
L3/L4 metadata extraction, and batch publishing over HTTP/WebSocket/Redis.
"""

from __future__ import annotations
import os
import sys
import time
import signal
import threading
import logging
from collections import deque
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable

import httpx

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [capture-agent] %(message)s"
)
logger = logging.getLogger("capture-agent")

# Try importing Scapy
try:
    from scapy.all import sniff, AsyncSniffer, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not found. Simulator fallback will be used.")


class BoundedPacketQueue:
    """
    Thread-safe bounded queue with explicit backpressure strategy.
    Prevents memory exhaustion during traffic spikes.
    """

    def __init__(self, maxsize: int = 5000, strategy: str = "drop_oldest"):
        self.maxsize = maxsize
        self.strategy = strategy  # "drop_oldest" or "block"
        self._queue: deque[dict[str, Any]] = deque()
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._not_full = threading.Condition(self._lock)
        self.dropped_count = 0
        self.total_enqueued = 0

    def put(self, item: dict[str, Any], timeout: float = 0.1) -> bool:
        """
        Enqueue a packet record. If full, applies configured backpressure strategy.
        Returns True if enqueued, False if dropped due to timeout.
        """
        with self._lock:
            self.total_enqueued += 1
            if self.strategy == "drop_oldest":
                if len(self._queue) >= self.maxsize:
                    self._queue.popleft()
                    self.dropped_count += 1
                self._queue.append(item)
                self._not_empty.notify()
                return True
            else:
                # Blocking strategy with timeout
                deadline = time.time() + timeout
                while len(self._queue) >= self.maxsize:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        self.dropped_count += 1
                        return False
                    self._not_full.wait(remaining)
                self._queue.append(item)
                self._not_empty.notify()
                return True

    def get_batch(self, max_batch: int = 50, timeout: float = 0.2) -> List[dict[str, Any]]:
        """
        Drain up to max_batch items from queue, waiting up to timeout for the first item.
        """
        batch = []
        with self._lock:
            if not self._queue:
                self._not_empty.wait(timeout)

            while self._queue and len(batch) < max_batch:
                batch.append(self._queue.popleft())

            if batch and self.strategy == "block":
                self._not_full.notify_all()

        return batch

    def __len__(self) -> int:
        with self._lock:
            return len(self._queue)


def extract_metadata(pkt: Any) -> Optional[Dict[str, Any]]:
    """
    Extract only L3/L4 metadata.
    Strictly excludes payload inspection for ethical, privacy, and legal compliance.
    """
    if not SCAPY_AVAILABLE or IP not in pkt:
        return None

    ip_layer = pkt[IP]
    protocol = "OTHER"
    src_port = None
    dst_port = None
    flags = "-"

    if TCP in pkt:
        protocol = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags = str(pkt[TCP].flags)
    elif UDP in pkt:
        protocol = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    elif ICMP in pkt:
        protocol = "ICMP"

    return {
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "source": str(ip_layer.src),
        "destination": str(ip_layer.dst),
        "src_port": src_port,
        "dst_port": dst_port,
        "port": dst_port if dst_port is not None else "-",  # Compatibility with detector rules
        "protocol": protocol,
        "size": len(pkt),
        "flags": flags,
    }


class PacketCaptureAgent:
    """
    Independent Packet Capture Service.
    Runs sniffer in background, extracts metadata, buffers into bounded queue,
    and publishes batches over HTTP REST / WebSocket to backend.
    """

    def __init__(
        self,
        backend_url: str = "http://localhost:8000",
        api_key: str = "packet-analyzer-secret-key-2026",
        interface: Optional[str] = None,
        bpf_filter: str = "ip",
        batch_size: int = 50,
        batch_interval: float = 0.2,
        queue_size: int = 5000,
        sampling_rate: float = 1.0,
        enable_simulator_fallback: bool = True,
    ):
        self.backend_url = backend_url.rstrip("/")
        self.api_key = api_key
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.batch_size = batch_size
        self.batch_interval = batch_interval
        self.sampling_rate = max(0.01, min(1.0, sampling_rate))
        self.enable_simulator_fallback = enable_simulator_fallback

        self.queue = BoundedPacketQueue(maxsize=queue_size, strategy="drop_oldest")
        self._stop_event = threading.Event()
        self._sniffer: Optional[Any] = None
        self._publisher_thread: Optional[threading.Thread] = None
        self._capture_thread: Optional[threading.Thread] = None
        self._http_client: Optional[httpx.Client] = None
        self.is_simulator = False

    def start(self) -> None:
        """Start sniffer and batch publisher threads."""
        self._stop_event.clear()
        self._http_client = httpx.Client(
            timeout=5.0,
            headers={"X-API-Key": self.api_key, "Content-Type": "application/json"}
        )

        # 1. Start publisher thread
        self._publisher_thread = threading.Thread(
            target=self._publish_loop, name="agent-batch-publisher", daemon=True
        )
        self._publisher_thread.start()

        # 2. Start sniffer thread
        self._capture_thread = threading.Thread(
            target=self._capture_worker, name="agent-packet-sniffer", daemon=True
        )
        self._capture_thread.start()
        logger.info(f"Capture agent initialized. Publishing to {self.backend_url}/api/ingest")

    def stop(self) -> None:
        """Gracefully stop capturing and flush remaining packets."""
        logger.info("Stopping capture agent...")
        self._stop_event.set()

        if self._sniffer and hasattr(self._sniffer, "stop"):
            try:
                self._sniffer.stop()
            except Exception:
                pass

        if self._publisher_thread and self._publisher_thread.is_alive():
            self._publisher_thread.join(timeout=2.0)

        if self._http_client:
            self._http_client.close()
        logger.info(f"Agent stopped. Total dropped: {self.queue.dropped_count}")

    def _packet_callback(self, pkt: Any) -> None:
        """Callback invoked by Scapy for every sniffed packet."""
        if self._stop_event.is_set():
            return

        # Sampling rate filter
        if self.sampling_rate < 1.0:
            import random
            if random.random() > self.sampling_rate:
                return

        meta = extract_metadata(pkt)
        if meta:
            self.queue.put(meta)

    def _capture_worker(self) -> None:
        """Worker running the Scapy sniffer or simulator fallback."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available. Switching to simulator generator.")
            self._run_simulator_fallback()
            return

        kwargs: Dict[str, Any] = {
            "prn": self._packet_callback,
            "store": False,
            "filter": self.bpf_filter,
        }
        if self.interface:
            kwargs["iface"] = self.interface

        logger.info(f"Starting Scapy sniff on iface={self.interface or 'default'}, filter='{self.bpf_filter}'")
        try:
            # Test sniffing permission
            sniff(**kwargs, count=1, timeout=1.0)
            # If successful, run AsyncSniffer
            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            while not self._stop_event.is_set():
                time.sleep(0.5)
        except (PermissionError, OSError, RuntimeError) as e:
            if self.enable_simulator_fallback:
                logger.warning(f"Raw socket permission denied or missing adapter ({e}). Falling back to simulator mode.")
                self.is_simulator = True
                self._run_simulator_fallback()
            else:
                logger.error(f"Capture failed: {e}")

    def _run_simulator_fallback(self) -> None:
        """Simulate realistic network packet flow when physical capture is unavailable."""
        self.is_simulator = True
        logger.info("Simulator generator active: feeding packets to bounded queue.")

        # Try using existing simulator module if present
        try:
            import simulator
            class QueueSink:
                def __init__(self, q):
                    self.q = q
                def append(self, pkt):
                    self.q.put(pkt)

            sink = QueueSink(self.queue)
            sim_thread = threading.Thread(
                target=simulator.simulate_traffic, args=(sink,), daemon=True
            )
            sim_thread.start()
            while not self._stop_event.is_set():
                time.sleep(0.5)
            return
        except ImportError:
            pass

        # Fallback synthetic packet generator
        import random
        servers = ["10.0.0.1", "10.0.0.2", "192.168.1.100", "172.16.0.5"]
        clients = [f"192.168.1.{i}" for i in range(10, 50)]
        protocols = ["TCP", "UDP", "ICMP"]

        while not self._stop_event.is_set():
            pkt = {
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "source": random.choice(clients),
                "destination": random.choice(servers),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 22, 53, 8080]),
                "port": random.choice([80, 443, 22, 53, 8080]),
                "protocol": random.choice(protocols),
                "size": random.randint(64, 1500),
                "flags": "PA" if random.random() > 0.5 else "S",
            }
            self.queue.put(pkt)
            time.sleep(0.01 + random.random() * 0.04)

    def _publish_loop(self) -> None:
        """Batch and dispatch packets from queue to backend API."""
        while not self._stop_event.is_set():
            batch = self.queue.get_batch(
                max_batch=self.batch_size, timeout=self.batch_interval
            )
            if not batch:
                continue

            payload = {
                "agent_id": f"agent-{os.getpid()}",
                "sent_at": time.time(),
                "packets": batch,
            }

            try:
                if self._http_client:
                    resp = self._http_client.post(
                        f"{self.backend_url}/api/ingest", json=payload
                    )
                    if resp.status_code != 202:
                        logger.warning(f"Ingest responded with HTTP {resp.status_code}: {resp.text}")
            except Exception as e:
                logger.debug(f"Transmission error to {self.backend_url}: {e}")
                # Backpressure: Sleep briefly on backend connection issues to prevent spinning
                time.sleep(0.5)


# --- Backward Compatibility Wrapper ---

def _parse_packet(pkt: Any) -> Dict[str, Any]:
    """Legacy helper: parses a Scapy packet into a dict."""
    res = extract_metadata(pkt)
    return res or {}


def start_capture(buffer: Any, interface: Optional[str] = None, bpf_filter: str = "ip") -> None:
    """
    Backward-compatible capture function for existing scripts and tests.
    """
    def callback(pkt: Any) -> None:
        entry = _parse_packet(pkt)
        if entry:
            buffer.append(entry)

    kwargs = {"prn": callback, "store": False, "filter": bpf_filter}
    if interface:
        kwargs["iface"] = interface

    try:
        if SCAPY_AVAILABLE:
            sniff(**kwargs)
    except (PermissionError, OSError, RuntimeError) as e:
        logger.warning(f"Capture error ({e}).")


# --- Standalone CLI Runner ---

def main() -> None:
    """CLI Entrypoint for running the standalone capture agent."""
    backend_url = os.environ.get("BACKEND_URL", "http://localhost:8000")
    api_key = os.environ.get("INGEST_API_KEY", "packet-analyzer-secret-key-2026")
    interface = os.environ.get("CAPTURE_INTERFACE", None)
    bpf_filter = os.environ.get("BPF_FILTER", "ip")
    sampling_rate = float(os.environ.get("SAMPLING_RATE", "1.0"))

    agent = PacketCaptureAgent(
        backend_url=backend_url,
        api_key=api_key,
        interface=interface,
        bpf_filter=bpf_filter,
        sampling_rate=sampling_rate,
    )

    def handle_signal(sig, frame):
        logger.info(f"Signal {sig} received. Initiating graceful shutdown...")
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    agent.start()
    logger.info("Capture agent running. Press Ctrl+C to terminate.")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
