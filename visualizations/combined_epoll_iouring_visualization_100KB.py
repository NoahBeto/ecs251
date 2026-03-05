#!/usr/bin/env python3
"""
Compare io_uring and epoll file server benchmarks in a single figure.
Plots throughput, latency, CPU, and system calls together with legend.
"""

import matplotlib.pyplot as plt
import re
import os

class CompareVisuals:
    def __init__(self, iouring_dir='benchmark_results_iouring_100KB', epoll_dir='benchmark_results_epoll_100KB'):
        self.iouring_dir = iouring_dir
        self.epoll_dir = epoll_dir

        self.concurrency_levels = [10, 50, 100, 500, 1000, 5000, 10000]
        self.file_sizes = {'1kb.txt': 1, '10kb.txt': 10, '100kb.txt': 100, '1mb.txt': 1024, '10mb.txt': 10240}

        self.data = {
            'iouring': {'throughput': {}, 'latency': {}, 'cpu': {}, 'syscalls': {}},
            'epoll': {'throughput': {}, 'latency': {}, 'cpu': {}, 'syscalls': {}},
        }

    def parse_ab_file(self, filepath):
        if not os.path.exists(filepath):
            return {}
        with open(filepath, 'r') as f:
            content = f.read()
        result = {}
        m = re.search(r'Requests per second:\s+([\d.]+)', content)
        if m: result['rps'] = float(m.group(1))
        m = re.search(r'Time per request:\s+([\d.]+)', content)
        if m: result['latency'] = float(m.group(1))
        m = re.search(r'Peak CPU:\s*([\d.]+)%', content)
        if m: result['cpu'] = float(m.group(1))
        return result

    def load_syscalls(self, dir_):
        """Load top system calls from syscalls_detailed.txt"""
        path = os.path.join(dir_, 'syscalls_detailed.txt')
        if not os.path.exists(path):
            return {}
        syscalls = {}
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 5 and parts[-1] not in ['syscall', 'total']:
                    try:
                        calls = int(parts[3])
                        syscall = parts[-1]
                        syscalls[syscall] = calls
                    except:
                        continue
        return syscalls

    def load_data(self):
        # Load throughput, latency, CPU
        for label, dir_ in [('iouring', self.iouring_dir), ('epoll', self.epoll_dir)]:
            prefix = 'iouring' if label == 'iouring' else 'epoll'

            # Throughput
            for c in self.concurrency_levels:
                fpath = os.path.join(dir_, f'{prefix}_c{c}_100kb.txt')
                data = self.parse_ab_file(fpath)
                if 'rps' in data:
                    self.data[label]['throughput'][c] = data['rps']

                # CPU (separate file)
                cpu_file = os.path.join(dir_, f'cpu_c{c}.txt')
                if os.path.exists(cpu_file):
                    with open(cpu_file) as f:
                        m = re.search(r'([\d.]+)%', f.read())
                        if m:
                            self.data[label]['cpu'][c] = float(m.group(1))

            # Latency vs file size
            for fname, size in self.file_sizes.items():
                fpath = os.path.join(dir_, f'{prefix}_c500_{fname}')
                data = self.parse_ab_file(fpath)
                if 'latency' in data:
                    self.data[label]['latency'][size] = data['latency']

            # System calls
            self.data[label]['syscalls'] = self.load_syscalls(dir_)

    def plot_comparison(self):
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))

        # 1. Throughput vs Concurrency
        ax = axes[0,0]
        for label, color in [('iouring','#2E86AB'), ('epoll','#FF6F61')]:
            conc = sorted(self.data[label]['throughput'].keys())
            thru = [self.data[label]['throughput'][c] for c in conc]
            ax.plot(conc, thru, 'o-', linewidth=2, markersize=8, color=color, label=label)
        ax.set_xscale('log')
        ax.set_xlabel('Concurrent Connections', fontweight='bold')
        ax.set_ylabel('Throughput (req/s)', fontweight='bold')
        ax.set_title('Throughput vs Concurrency', fontweight='bold')
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=12)

        # 2. Latency vs File Size
        ax = axes[0,1]
        for label, color in [('iouring','#2E86AB'), ('epoll','#FF6F61')]:
            sizes = sorted(self.data[label]['latency'].keys())
            lats = [self.data[label]['latency'][s] for s in sizes]
            ax.plot(sizes, lats, 'o-', linewidth=2, markersize=8, color=color, label=label)
        ax.set_xscale('log')
        ax.set_xlabel('File Size (KB)', fontweight='bold')
        ax.set_ylabel('Latency (ms)', fontweight='bold')
        ax.set_title('Latency vs File Size', fontweight='bold')
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=12)

        # 3. CPU Utilization vs Concurrency
        ax = axes[1,0]
        for label, color in [('iouring','#2E86AB'), ('epoll','#FF6F61')]:
            conc = sorted(self.data[label]['cpu'].keys())
            cpu = [self.data[label]['cpu'][c] for c in conc]
            ax.plot(conc, cpu, 'o-', linewidth=2, markersize=8, color=color, label=label)
        ax.set_xscale('log')
        ax.set_xlabel('Concurrent Connections', fontweight='bold')
        ax.set_ylabel('CPU Usage (%)', fontweight='bold')
        ax.set_title('CPU Utilization vs Concurrency', fontweight='bold')
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=12)

        # 4. System Calls - epoll only
        ax = axes[1, 1]
        e_sys = self.data['epoll']['syscalls']

        top_n = 6
        top_calls = sorted(e_sys.items(), key=lambda x: x[1], reverse=True)[:top_n]
        names  = [k for k, _ in top_calls]
        counts = [v for _, v in top_calls]
        total  = sum(e_sys.values())

        labels = names

        bars = ax.bar(range(len(names)), counts, width=0.6, color='#FF6F61', alpha=0.9)

        for bar, count in zip(bars, counts):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                    f'{count}', ha='center', va='bottom', fontsize=11)

        ax.set_xticks(range(len(names)))
        ax.set_xticklabels(labels, rotation=0, ha='center', fontsize=12)
        ax.set_ylabel('Number of Calls', fontweight='bold')
        ax.set_title(f'Top System Calls - epoll (Total: {total})\n1000 Requests',
                     fontweight='bold')
        ax.grid(True, alpha=0.3, axis='y')

        plt.tight_layout()
        plt.suptitle('Comparison: io_uring vs epoll File Server', fontsize=16, fontweight='bold', y=1.02)
        plt.savefig('benchmark_comparison_100KB.png', dpi=300)
        print("✓ Saved: benchmark_comparison_100KB.png")
        plt.show()

def main():
    cmp_viz = CompareVisuals()
    cmp_viz.load_data()
    cmp_viz.plot_comparison()

if __name__ == '__main__':
    main()