import subprocess
import time
import os
from datetime import datetime

def log_action(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("log.txt", "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def timed_ping(ip):
    try:
        cmd = ["ping", "-n", "1", ip] if os.name == "nt" else ["ping", "-c", "1", ip]
        start = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        end = time.time()

        if result.returncode == 0:
            rtt = (end - start) * 1000  # ms
            return round(rtt, 2)
    except Exception:
        return None
    return None

def analyze_network(ip, count=5):
    results = []
    prev_latency = None

    for i in range(count):
        latency = timed_ping(ip)
        if latency is not None:
            jitter = round(abs(latency - prev_latency), 2) if prev_latency is not None else 0
            prev_latency = latency
            throughput = round(1500 * 8 / (latency / 1000), 2) if latency > 0 else 0
            results.append({
                "latency": latency,
                "jitter (ms)": jitter,
                "packet loss": 0,
                "throughput (bps)": throughput
            })
        else:
            results.append({
                "latency": 0,
                "jitter (ms)": 0,
                "packet loss": 1,
                "throughput (bps)": 0
            })
        time.sleep(0.2)

    log_action(f"Timed ping analysis on {ip} with {count} pings")
    return results
