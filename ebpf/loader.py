#!/usr/bin/env python3
import sys
import ctypes as ct
from bcc import BPF
import time
from datetime import datetime
import json
import os

# Ensure ML module is discoverable
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.threshold_calculator import DynamicThresholdCalculator

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
    def __init__(self, ebpf_program_path, use_dynamic=True):
        self.use_dynamic = use_dynamic
        self.alerts = []
        self.normal_traffic = []
        self.threshold_calc = DynamicThresholdCalculator() if use_dynamic else None
        
        try:
            self.bpf = BPF(src_file=ebpf_program_path)
            self.bpf["events"].open_perf_buffer(self.handle_event)
            print(f"✅ Tracker Started (Mode: {'Dynamic' if use_dynamic else 'Static'})")
        except Exception as e:
            print(f"❌ Loader Failed: {e}")
            sys.exit(1)

    def handle_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(AlertEvent)).contents
        cid = event.container_id
        cpu_us = event.cpu_time_us
        
        # Step 1: Update the "Brain"
        self.threshold_calc.update(cid, cpu_us)
        
        # Step 2: Get dynamic threshold or use hardcoded 50ms (50000us)
        current_threshold_us = self.threshold_calc.get_threshold(cid) or 50000
        is_anomaly = cpu_us > current_threshold_us
        
        alert_data = {
            "timestamp": datetime.now().isoformat(),
            "pid": event.pid,
            "container_id": cid,
            "command": event.comm.decode('utf-8', 'replace'),
            "cpu_time_ms": round(cpu_us / 1000.0, 2),
            "threshold_ms": round(current_threshold_us / 1000.0, 2),
            "severity": self._get_severity(cpu_us, current_threshold_us)
        }

        if is_anomaly and len(self.threshold_calc.container_windows.get(cid, [])) > 30:
            self.alerts.append(alert_data)
            self._print_alert(alert_data)
        else:
            self.normal_traffic.append(alert_data)

    def _get_severity(self, cpu, thresh):
        ratio = cpu / thresh if thresh > 0 else 0
        if ratio > 5: return "CRITICAL"
        if ratio > 2: return "HIGH"
        return "MEDIUM"

    def _print_alert(self, d):
        print(f"🚨 ANOMALY | {d['command']} | CPU: {d['cpu_time_ms']}ms | Thresh: {d['threshold_ms']}ms | {d['severity']}")

    def start_monitoring(self):
        try:
            while True:
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            self.save_data()

    def save_data(self):
        os.makedirs("data/output", exist_ok=True)
        os.makedirs("data/training", exist_ok=True)
        ts = int(time.time())
        with open(f"data/output/alerts_{ts}.json", 'w') as f: json.dump(self.alerts, f)
        with open(f"data/training/normal_{ts}.json", 'w') as f: json.dump(self.normal_traffic, f)
        print(f"💾 Data Saved: {len(self.alerts)} alerts, {len(self.normal_traffic)} normal samples.")

if __name__ == "__main__":
    tracker = EBPFConnectionTracker("ebpf/programs/connection_tracker.c")
    tracker.start_monitoring()
