#!/usr/bin/env python3
import sys
import ctypes as ct
from bcc import BPF
import time
from datetime import datetime
import json
import os

class AlertEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("container_id", ct.c_uint32),
        ("duration_us", ct.c_uint64),
        ("cpu_time_us", ct.c_uint64),
        ("comm", ct.c_char * 16),
        ("timestamp", ct.c_uint64),
    ]

class EBPFConnectionTracker:
    def __init__(self, ebpf_program_path, threshold_ms=100):
        self.threshold_ms = threshold_ms
        self.alerts = []
        
        try:
            self.bpf = BPF(src_file=ebpf_program_path)
            print("✅ eBPF program loaded successfully")
            
            # Map Key 0 is our global threshold
            self.bpf["threshold_map"][ct.c_uint32(0)] = ct.c_uint64(threshold_ms)
            print(f"⚙️  System Threshold: {threshold_ms}ms CPU per Connection")
            
            self.bpf["events"].open_perf_buffer(self.handle_event)
            
        except Exception as e:
            print(f"❌ Failed to load eBPF program: {e}")
            sys.exit(1)
    
    # ... (AlertEvent structure remains the same as before) ...
    def handle_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(AlertEvent)).contents
        
        cpu_ms = event.cpu_time_us / 1000.0
        dur_ms = event.duration_us / 1000.0
        
        # This will now show numbers like 0.45ms instead of 0.0ms
        print(f"🚨 ALERT: {event.comm.decode()} | CID: {event.container_id} | "
              f"CPU: {cpu_ms:.2f}ms | Duration: {dur_ms:.2f}ms")
        
        alert_data = {
            "timestamp": datetime.now().isoformat(),
            "pid": event.pid,
            "container_id": event.container_id,
            "command": event.comm.decode('utf-8', 'replace'),
            "duration_ms": round(dur_ms, 2),
            "cpu_time_ms": round(cpu_ms, 2),
            "severity": "CRITICAL" if cpu_ms > self.threshold_ms * 3 else "WARNING"
        }

    def start_monitoring(self):
        print(f"\n{'='*75}\n🔍 Monitoring Container Anomalies (Microsecond Precision)...\n{'='*75}\n")
        try:
            while True:
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n🛑 Shutting down...")
            self.save_alerts()

    def save_alerts(self):
        if not self.alerts: return
        os.makedirs("data/output", exist_ok=True)
        filename = f"data/output/alerts_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(self.alerts, f, indent=2)
        print(f"💾 {len(self.alerts)} alerts exported to {filename}")

if __name__ == "__main__":
    # 50ms is a good sensitive threshold for micro-services
    tracker = EBPFConnectionTracker("ebpf/programs/connection_tracker.c", threshold_ms=50)
    tracker.start_monitoring()
