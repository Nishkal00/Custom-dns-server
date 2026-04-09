"""
benchmark.py — Performance evaluation for the DNS + SSL server.

Tests:
  1. UDP DNS  — concurrent queries, measures latency & throughput
  2. DNS-over-TLS — concurrent queries over TLS, measures latency & throughput
  3. SSL control channel — concurrent connections, measures connection time

Run:  python benchmark.py
"""

import socket
import ssl
import threading
import time
import statistics
from dnslib import DNSRecord

SERVER_IP    = " " # enter server's IP address.
DNS_PORT     = 5053
DNS_TLS_PORT = 8853
SSL_PORT     = 8443

TEST_DOMAINS = [
    "example.com",
    "amazon.com",
    "reddit.com",
    "google.com",
    "github.com",
]

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def color(text, code):
    return f"\033[{code}m{text}\033[0m"

def header(title):
    print("\n" + color("=" * 55, "1;36"))
    print(color(f"  {title}", "1;36"))
    print(color("=" * 55, "1;36"))

def print_stats(label, latencies, errors, total_time):
    success = len(latencies)
    total   = success + errors
    throughput = success / total_time if total_time > 0 else 0

    print(f"\n  {color(label, '1;33')}")
    print(f"    Requests sent   : {total}")
    print(f"    Successful      : {color(success, '1;32')}")
    print(f"    Errors          : {color(errors, '1;31')}")
    if latencies:
        print(f"    Min latency     : {min(latencies)*1000:.2f} ms")
        print(f"    Max latency     : {max(latencies)*1000:.2f} ms")
        print(f"    Avg latency     : {statistics.mean(latencies)*1000:.2f} ms")
        print(f"    Median latency  : {statistics.median(latencies)*1000:.2f} ms")
        if len(latencies) > 1:
            print(f"    Std deviation   : {statistics.stdev(latencies)*1000:.2f} ms")
    print(f"    Throughput      : {throughput:.2f} req/s")


# ------------------------------------------------------------------ #
# 1. UDP DNS Benchmark
# ------------------------------------------------------------------ #

def _udp_dns_worker(domain, results, lock):
    start = time.time()
    try:
        q = DNSRecord.question(domain)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(q.pack(), (SERVER_IP, DNS_PORT))
        data, _ = sock.recvfrom(512)
        sock.close()
        elapsed = time.time() - start
        with lock:
            results["latencies"].append(elapsed)
    except Exception:
        with lock:
            results["errors"] += 1


def bench_udp_dns(num_clients=50):
    header(f"UDP DNS Benchmark  ({num_clients} concurrent queries)")
    results = {"latencies": [], "errors": 0}
    lock = threading.Lock()
    threads = []

    start = time.time()
    for i in range(num_clients):
        domain = TEST_DOMAINS[i % len(TEST_DOMAINS)]
        t = threading.Thread(target=_udp_dns_worker, args=(domain, results, lock))
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total_time = time.time() - start
    print_stats("UDP DNS", results["latencies"], results["errors"], total_time)


# ------------------------------------------------------------------ #
# 2. DNS-over-TLS Benchmark
# ------------------------------------------------------------------ #

def _dot_worker(domain, results, lock):
    start = time.time()
    try:
        ctx = ssl._create_unverified_context()
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(5)
        conn = ctx.wrap_socket(raw, server_hostname=SERVER_IP)
        conn.connect((SERVER_IP, DNS_TLS_PORT))

        q    = DNSRecord.question(domain)
        data = q.pack()
        conn.sendall(len(data).to_bytes(2, "big") + data)

        # Read 2-byte length prefix
        raw_len = b""
        while len(raw_len) < 2:
            chunk = conn.recv(2 - len(raw_len))
            if not chunk:
                raise ConnectionError("Connection closed")
            raw_len += chunk

        msg_len = int.from_bytes(raw_len, "big")
        resp = b""
        while len(resp) < msg_len:
            chunk = conn.recv(msg_len - len(resp))
            if not chunk:
                raise ConnectionError("Connection closed")
            resp += chunk

        conn.close()
        elapsed = time.time() - start
        with lock:
            results["latencies"].append(elapsed)
    except Exception:
        with lock:
            results["errors"] += 1


def bench_dot(num_clients=50):
    header(f"DNS-over-TLS Benchmark  ({num_clients} concurrent queries)")
    results = {"latencies": [], "errors": 0}
    lock = threading.Lock()
    threads = []

    start = time.time()
    for i in range(num_clients):
        domain = TEST_DOMAINS[i % len(TEST_DOMAINS)]
        t = threading.Thread(target=_dot_worker, args=(domain, results, lock))
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total_time = time.time() - start
    print_stats("DNS-over-TLS", results["latencies"], results["errors"], total_time)


# ------------------------------------------------------------------ #
# 3. SSL Control Channel Benchmark
# ------------------------------------------------------------------ #

def _ssl_worker(results, lock):
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ctx  = ssl._create_unverified_context()
        conn = ctx.wrap_socket(sock, server_hostname=SERVER_IP)
        conn.connect((SERVER_IP, SSL_PORT))
        conn.send(b"benchmark ping")
        conn.recv(1024)
        conn.close()
        elapsed = time.time() - start
        with lock:
            results["latencies"].append(elapsed)
    except Exception:
        with lock:
            results["errors"] += 1


def bench_ssl(num_clients=30):
    header(f"SSL Control Channel Benchmark  ({num_clients} concurrent connections)")
    results = {"latencies": [], "errors": 0}
    lock = threading.Lock()
    threads = []

    start = time.time()
    for _ in range(num_clients):
        t = threading.Thread(target=_ssl_worker, args=(results, lock))
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total_time = time.time() - start
    print_stats("SSL Connections", results["latencies"], results["errors"], total_time)


# ------------------------------------------------------------------ #
# 4. Sustained Load Test (ramp up over time)
# ------------------------------------------------------------------ #

def bench_sustained(duration_sec=10, interval=0.1):
    header(f"Sustained UDP DNS Load Test  ({duration_sec}s, query every {interval}s)")
    latencies = []
    errors    = 0
    start     = time.time()

    while time.time() - start < duration_sec:
        domain = TEST_DOMAINS[int((time.time() - start) * 10) % len(TEST_DOMAINS)]
        t0 = time.time()
        try:
            q = DNSRecord.question(domain)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(q.pack(), (SERVER_IP, DNS_PORT))
            sock.recvfrom(512)
            sock.close()
            latencies.append(time.time() - t0)
        except Exception:
            errors += 1
        time.sleep(interval)

    total_time = time.time() - start
    print_stats("Sustained Load", latencies, errors, total_time)


# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    print(color("\n  DNS + SSL Server — Performance Benchmark", "1;37"))
    print(color(f"  Target: {SERVER_IP}", "0;37"))

    bench_udp_dns(num_clients=50)
    bench_dot(num_clients=50)
    bench_ssl(num_clients=30)
    bench_sustained(duration_sec=10, interval=0.1)

    print("\n" + color("  Benchmark complete.", "1;32") + "\n")
