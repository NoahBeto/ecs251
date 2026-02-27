#!/usr/bin/env python3
"""
Comprehensive visualization for epoll file server
Matches ECS 251 evaluation plan requirements
"""

import matplotlib.pyplot as plt
import numpy as np
import re
import os
from pathlib import Path

class ComprehensiveVisualizer:
    def __init__(self, results_dir='benchmark_results_epoll', output_dir='evaluation'):
        self.results_dir = results_dir
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Data storage
        self.throughput = {}  # concurrency -> req/s
        self.latency_filesize = {}  # file_size_kb -> latency_ms
        self.cpu_util = {}  # concurrency -> cpu%
        self.syscalls = {}  # syscall -> count
        self.range_perf = {}  # concurrency -> req/s
        self.upload_perf = {}  # concurrency -> uploads/s

    # --- Parsing methods ---
    def parse_ab(self, filepath):
        """Parse ab output"""
        if not os.path.exists(filepath):
            return {}
        with open(filepath, 'r') as f:
            content = f.read()
        result = {}

        # Requests per second
        match = re.search(r'Requests per second:\s+([\d.]+)', content)
        if match:
            result['rps'] = float(match.group(1))

        # Time per request (mean, standard)
        match = re.search(
            r'Time per request:\s*([\d.]+)\s*\[ms\]\s*\(mean(?:, across all concurrent requests)?\)',
            content
)
        if match:
            result['latency'] = float(match.group(1))
        # Transfer rate
        match = re.search(r'Transfer rate:\s+([\d.]+)', content)
        if match:
            result['transfer'] = float(match.group(1))

        # Peak CPU
        match = re.search(r'Peak CPU: ([\d.]+)%', content)
        if match:
            result['cpu'] = float(match.group(1))

        return result

    # --- Load benchmark data ---
    def load_all_data(self):
        print("Loading data...")
        # Throughput vs concurrency
        for c in [10, 50, 100, 500, 1000, 5000, 10000]:
            data = self.parse_ab(f"{self.results_dir}/epoll_c{c}_1kb.txt")
            if 'rps' in data:
                self.throughput[c] = data['rps']
            if 'cpu' in data:
                self.cpu_util[c] = data['cpu']

        # Latency vs file size
        files = {'1kb.txt': 1, '10kb.bin': 10, '100kb.bin': 100, '1mb.bin': 1024, '10mb.bin': 10240}
        for fname, size in files.items():
            data = self.parse_ab(f"{self.results_dir}/epoll_c100_{fname}")
            if 'latency' in data:
                self.latency_filesize[size] = data['latency']

        # CPU utilization from separate files (fallback)
        for c in [10, 50, 100, 500, 1000, 5000, 10000]:
            fpath = f"{self.results_dir}/cpu_c{c}.txt"
            if os.path.exists(fpath):
                with open(fpath, 'r') as f:
                    match = re.search(r'([\d.]+)%', f.read())
                    if match:
                        self.cpu_util[c] = float(match.group(1))

        # Range request performance
        for c in [10, 100, 1000]:
            data = self.parse_ab(f"{self.results_dir}/range_c{c}.txt")
            if 'rps' in data:
                self.range_perf[c] = data['rps']

        # Upload performance
        for c in [10, 50, 100]:
            fpath = f"{self.results_dir}/upload_c{c}.txt"
            if os.path.exists(fpath):
                with open(fpath, 'r') as f:
                    match = re.search(r'\(([\d.]+) uploads/s\)', f.read())
                    if match:
                        self.upload_perf[c] = float(match.group(1))

        # System calls
        self.load_syscalls()

        print(f"✓ Loaded {len(self.throughput)} throughput points")
        print(f"✓ Loaded {len(self.latency_filesize)} latency points")
        print(f"✓ Loaded {len(self.cpu_util)} CPU utilization points")

    def load_syscalls(self):
        """Load system call data"""
        fpath = f"{self.results_dir}/syscalls_detailed.txt"
        if not os.path.exists(fpath):
            return
        with open(fpath, 'r') as f:
            lines = f.readlines()
        for line in lines:
            parts = line.split()
            if len(parts) >= 5 and parts[-1] not in ['syscall', 'total']:
                try:
                    calls = int(parts[3])
                    syscall = parts[-1]
                    self.syscalls[syscall] = calls
                except:
                    continue

    # --- Plotting methods ---
    def plot_throughput_extended(self):
        if not self.throughput:
            return
        fig, ax = plt.subplots(figsize=(12, 7))
        conc = sorted(self.throughput.keys())
        thru = [self.throughput[c] for c in conc]
        ax.plot(conc, thru, 'o-', linewidth=2.5, markersize=10, color='#2E86AB', label='epoll')
        for x, y in zip(conc, thru): ax.text(x, y*1.02, f'{y:.0f}', ha='center', fontsize=9)
        ax.set_xlabel('Concurrent Connections', fontsize=13, fontweight='bold')
        ax.set_ylabel('Throughput (req/s)', fontsize=13, fontweight='bold')
        ax.set_title('Throughput vs Concurrency (10 to 10,000 clients)\n1KB File', fontsize=15, fontweight='bold', pad=20)
        ax.grid(True, alpha=0.3, linestyle='--')
        ax.set_xscale('log')
        ax.legend(fontsize=12)
        plt.tight_layout()
        plt.savefig(f'{self.output_dir}/epoll_throughput_extended.png', dpi=300)
        print(f"✓ Saved: epoll_throughput_extended.png")
        plt.close()

    def plot_latency_extended(self):
        if not self.latency_filesize:
            return
        fig, ax = plt.subplots(figsize=(12, 7))
        sizes = sorted(self.latency_filesize.keys())
        lats = [self.latency_filesize[s] for s in sizes]
        ax.plot(sizes, lats, 'o-', linewidth=2.5, markersize=10, color='#A23B72', label='epoll')
        for x, y in zip(sizes, lats): ax.text(x, y*1.05, f'{y:.2f}', ha='center', fontsize=9)
        ax.set_xlabel('File Size (KB)', fontsize=13, fontweight='bold')
        ax.set_ylabel('Average Latency (ms)', fontsize=13, fontweight='bold')
        ax.set_title('Latency vs File Size (1KB to 10MB)\n100 Concurrent Connections', fontsize=15, fontweight='bold', pad=20)
        ax.grid(True, alpha=0.3, linestyle='--')
        ax.set_xscale('log')
        ax.legend(fontsize=12)
        plt.tight_layout()
        plt.savefig(f'{self.output_dir}/epoll_latency_extended.png', dpi=300)
        print(f"✓ Saved: epoll_latency_extended.png")
        plt.close()

    def plot_cpu_utilization(self):
        if not self.cpu_util:
            return
        fig, ax = plt.subplots(figsize=(12, 7))
        conc = sorted(self.cpu_util.keys())
        cpu = [self.cpu_util[c] for c in conc]
        ax.plot(conc, cpu, 'o-', linewidth=2.5, markersize=10, color='#F18F01', label='CPU Usage')
        for x, y in zip(conc, cpu): ax.text(x, y*1.02, f'{y:.1f}%', ha='center', fontsize=9)
        ax.set_xlabel('Concurrent Connections', fontsize=13, fontweight='bold')
        ax.set_ylabel('CPU Utilization (%)', fontsize=13, fontweight='bold')
        ax.set_title('CPU Utilization vs Concurrency', fontsize=15, fontweight='bold', pad=20)
        ax.grid(True, alpha=0.3, linestyle='--')
        ax.set_xscale('log')
        ax.legend(fontsize=12)
        plt.tight_layout()
        plt.savefig(f'{self.output_dir}/epoll_cpu_utilization.png', dpi=300)
        print(f"✓ Saved: epoll_cpu_utilization.png")
        plt.close()

    def plot_syscalls(self):
        if not self.syscalls:
            return
        top = sorted(self.syscalls.items(), key=lambda x: x[1], reverse=True)[:10]
        fig, ax = plt.subplots(figsize=(12, 7))
        names = [s[0] for s in top]
        counts = [s[1] for s in top]
        bars = ax.barh(names, counts, color='#C73E1D', alpha=0.8)
        for bar, count in zip(bars, counts):
            width = bar.get_width()
            ax.text(width*1.02, bar.get_y()+bar.get_height()/2, f'{count}', ha='left', va='center', fontsize=10, fontweight='bold')
        total = sum(self.syscalls.values())
        ax.set_xlabel('Number of Calls', fontsize=13, fontweight='bold')
        ax.set_ylabel('System Call', fontsize=13, fontweight='bold')
        ax.set_title(f'System Call Distribution (Total: {total} calls)\n1000 Requests', fontsize=15, fontweight='bold', pad=20)
        ax.grid(True, alpha=0.3, axis='x', linestyle='--')
        plt.tight_layout()
        plt.savefig(f'{self.output_dir}/epoll_syscalls_distribution.png', dpi=300)
        print(f"✓ Saved: epoll_syscalls_distribution.png")
        plt.close()

    def plot_comparison_grid(self):
        fig = plt.figure(figsize=(16, 12))
        ax1 = plt.subplot(2,2,1)
        if self.throughput:
            conc = sorted(self.throughput.keys())
            thru = [self.throughput[c] for c in conc]
            ax1.plot(conc, thru, 'o-', linewidth=2, markersize=8, color='#2E86AB')
            ax1.set_xlabel('Concurrent Connections', fontweight='bold')
            ax1.set_ylabel('Throughput (req/s)', fontweight='bold')
            ax1.set_title('Throughput vs Concurrency', fontweight='bold')
            ax1.set_xscale('log')
            ax1.grid(True, alpha=0.3)
        ax2 = plt.subplot(2,2,2)
        if self.latency_filesize:
            sizes = sorted(self.latency_filesize.keys())
            lats = [self.latency_filesize[s] for s in sizes]
            ax2.plot(sizes, lats, 'o-', linewidth=2, markersize=8, color='#A23B72')
            ax2.set_xlabel('File Size (KB)', fontweight='bold')
            ax2.set_ylabel('Latency (ms)', fontweight='bold')
            ax2.set_title('Latency vs File Size', fontweight='bold')
            ax2.set_xscale('log')
            ax2.grid(True, alpha=0.3)
        ax3 = plt.subplot(2,2,3)
        if self.cpu_util:
            conc = sorted(self.cpu_util.keys())
            cpu = [self.cpu_util[c] for c in conc]
            ax3.plot(conc, cpu, 'o-', linewidth=2, markersize=8, color='#F18F01')
            ax3.set_xlabel('Concurrent Connections', fontweight='bold')
            ax3.set_ylabel('CPU Usage (%)', fontweight='bold')
            ax3.set_title('CPU Utilization vs Concurrency', fontweight='bold')
            ax3.set_xscale('log')
            ax3.grid(True, alpha=0.3)
        ax4 = plt.subplot(2,2,4)
        if self.syscalls:
            top = sorted(self.syscalls.items(), key=lambda x: x[1], reverse=True)[:6]
            names = [s[0] for s in top]
            counts = [s[1] for s in top]
            ax4.bar(names, counts, color='#C73E1D', alpha=0.8)
            total = sum(self.syscalls.values())
            ax4.set_xlabel('System Call', fontweight='bold')
            ax4.set_ylabel('Count', fontweight='bold')
            ax4.set_title(f'Top System Calls ({total} total)', fontweight='bold')
            ax4.tick_params(axis='x', rotation=45)
            ax4.grid(True, alpha=0.3, axis='y')
        fig.suptitle('epoll File Server Performance Analysis', fontsize=16, fontweight='bold', y=0.995)
        plt.tight_layout()
        plt.savefig(f'{self.output_dir}/epoll_evaluation_summary.png', dpi=300)
        print(f"✓ Saved: epoll_evaluation_summary.png")
        plt.close()

    # --- Report ---
    def generate_report(self):
        report_path = f'{self.output_dir}/epoll_evaluation_report.txt'
        with open(report_path, 'w') as f:
            f.write("="*80 + "\n")
            f.write("epoll File Server - Evaluation Report\n")
            f.write("="*80 + "\n\n")
            f.write("1. THROUGHPUT vs CONCURRENCY (1KB file)\n")
            f.write("-"*80 + "\n")
            for c in sorted(self.throughput.keys()):
                f.write(f"  {c:>6} connections: {self.throughput[c]:>10.2f} req/s\n")
            if self.throughput:
                max_c = max(self.throughput, key=self.throughput.get)
                f.write(f"\n  Peak throughput: {self.throughput[max_c]:.2f} req/s @ {max_c} connections\n\n")
            f.write("2. LATENCY vs FILE SIZE (100 concurrent)\n")
            f.write("-"*80 + "\n")
            for size in sorted(self.latency_filesize.keys()):
                size_str = f"{size}KB" if size<1024 else f"{size//1024}MB"
                f.write(f"  {size_str:>8}: {self.latency_filesize[size]:>8.2f} ms\n")
            f.write("\n3. CPU UTILIZATION\n")
            f.write("-"*80 + "\n")
            for c in sorted(self.cpu_util.keys()):
                f.write(f"  {c:>6} connections: {self.cpu_util[c]:>6.2f}%\n")
            f.write("\n4. SYSTEM CALLS (1000 requests)\n")
            f.write("-"*80 + "\n")
            if self.syscalls:
                total = sum(self.syscalls.values())
                f.write(f"  Total system calls: {total}\n")
                f.write(f"  Calls per request:  {total/1000:.2f}\n\n")
                f.write("  Top system calls:\n")
                for sc, count in sorted(self.syscalls.items(), key=lambda x:x[1], reverse=True)[:10]:
                    f.write(f"    {sc:20} {count:>6} calls\n")
            f.write("\n")
            if self.range_perf:
                f.write("5. RANGE REQUEST PERFORMANCE\n")
                f.write("-"*80 + "\n")
                for c in sorted(self.range_perf.keys()):
                    f.write(f"  {c:>6} connections: {self.range_perf[c]:>10.2f} req/s\n")
            if self.upload_perf:
                f.write("6. FILE UPLOAD PERFORMANCE (100KB files)\n")
                f.write("-"*80 + "\n")
                for c in sorted(self.upload_perf.keys()):
                    f.write(f"  {c:>6} concurrent: {self.upload_perf[c]:>8.2f} uploads/s\n")
            f.write("="*80 + "\n")
        print(f"✓ Saved: epoll_evaluation_report.txt")

    # --- Run all ---
    def run_all(self):
        print("\n=== Loading Benchmark Data ===")
        self.load_all_data()
        print("\n=== Generating Visualizations ===")
        self.plot_throughput_extended()
        self.plot_latency_extended()
        self.plot_cpu_utilization()
        self.plot_syscalls()
        self.plot_comparison_grid()
        print("\n=== Generating Report ===")
        self.generate_report()
        print(f"\n✓ Complete! All results in {self.output_dir}/")

# --- Main ---
def main():
    viz = ComprehensiveVisualizer()
    viz.run_all()

if __name__ == '__main__':
    main()