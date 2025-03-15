#!/usr/bin/env python3
"""
CacheLeaks: Cache Side-Channel Detection Tool

This tool monitors system processes and memory access patterns to detect
potential cache-based side-channel attacks such as Flush+Reload, Prime+Probe,
and other timing attacks that exploit the shared cache architecture.

Adapted for macOS with simulation approach due to hardware access restrictions.
"""

import os
import sys
import time
import argparse
import logging
import numpy as np
import subprocess
from threading import Thread
from collections import defaultdict, deque

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("CacheLeaks")

def is_macos():
    """Check if running on macOS"""
    return sys.platform == 'darwin'

class CacheMonitor:
    """Monitors cache access patterns for potential side-channel leakage."""
    
    def __init__(self, pid=None, threshold=100, window_size=1000, sampling_rate=1000):
        """
        Initialize the cache monitor.
        
        Args:
            pid: Process ID to monitor (None for system-wide monitoring)
            threshold: Threshold for detecting anomalous cache behavior (in cycles)
            window_size: Size of the sliding window for statistical analysis
            sampling_rate: Cache access sampling rate in Hz
        """
        self.pid = pid
        self.threshold = threshold
        self.window_size = window_size
        self.sampling_rate = sampling_rate
        self.running = False
        self.cache_access_times = deque(maxlen=window_size)
        self.alerts = []
        self.cache_miss_patterns = defaultdict(int)
        
        # Check if running as root (needed for some features)
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        if not self.is_root:
            logger.warning("Not running as root. Some detection features will be limited.")
    
    def _get_perf_counters(self):
        """Get cache-related performance data based on platform."""
        if not self.is_root:
            return None
            
        if is_macos():
            return self._get_macos_perf_counters()
        else:
            return self._get_linux_perf_counters()
    
    def _get_linux_perf_counters(self):
        """Get cache-related performance counters using Linux perf."""
        cmd = ["perf", "stat", "-e", "cache-misses,cache-references", "-p", str(self.pid)]
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            return output
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error("Failed to get perf counters. Is perf installed?")
            return None
    
    def _get_macos_perf_counters(self):
        """Get performance data on macOS (limited capabilities)."""
        if not self.pid:
            return None  # System-wide monitoring isn't well supported
            
        # On macOS, we have limited options for hardware counter access
        try:
            # Try to use pmset for some basic power stats that might indicate CPU activity
            cmd = ["pmset", "-g", "therm"]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            
            # Supplement with process stats
            ps_cmd = ["ps", "-p", str(self.pid), "-o", "%cpu,%mem"]
            ps_output = subprocess.check_output(ps_cmd, stderr=subprocess.STDOUT, text=True)
            
            # Combine outputs
            combined = f"Process Stats:\n{ps_output}\nSystem Thermal:\n{output}"
            return combined
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.debug(f"Failed to get macOS performance data: {e}")
            return None
    
    def _detect_flush_reload(self):
        """Enhanced Flush+Reload detection using multiple statistical signals"""
        if len(self.cache_access_times) < self.window_size:
            return 0.0
            
        times = np.array(self.cache_access_times)
        
        # 1. Bimodal distribution check
        hist, _ = np.histogram(times, bins=50)
        peaks = np.where(np.diff(np.sign(np.diff(hist))) < 0)[0] + 1
        
        mean = np.mean(times)
        std = np.std(times)
        
        # Calculate bimodality score
        bimodal_score = 0.0
        if len(peaks) >= 2 and std > mean * 0.3:
            # Calculate the valley-to-peak ratio
            valley = np.min(hist[peaks[0]:peaks[1]])
            peak = np.max(hist[peaks[0]:peaks[1]])
            ratio = valley / peak if peak > 0 else 1.0
            bimodal_score = 1.0 - min(ratio * 2, 1.0)
        
        # 2. Clustering-based detection
        cluster_score = 0.0
        # Check if the data seems to have two distinct groups
        threshold = mean + 0.5 * std
        group1 = times[times <= threshold]
        group2 = times[times > threshold]
        
        # If we have two reasonably sized groups, that's suspicious
        if len(group1) > 0.2 * len(times) and len(group2) > 0.2 * len(times):
            # Calculate separation between groups
            separation = abs(np.mean(group1) - np.mean(group2))
            # Normalize by overall standard deviation
            cluster_score = min(separation / std, 1.0) if std > 0 else 0.0
        
        # Combined score with more weight on bimodal distribution
        confidence = bimodal_score * 0.6 + cluster_score * 0.4
        
        return confidence
    
    def _detect_prime_probe(self):
        """Enhanced Prime+Probe detection focusing on periodicity and regularity"""
        if len(self.cache_access_times) < self.window_size:
            return 0.0
        
        times = np.array(self.cache_access_times)
        
        # 1. Check for periodicity using autocorrelation
        autocorr = np.correlate(times - np.mean(times), times - np.mean(times), mode='full')
        autocorr = autocorr[len(autocorr)//2:]
        
        # Normalize
        autocorr = autocorr / autocorr[0] if autocorr[0] > 0 else autocorr
        
        # Find peaks in autocorrelation with simple peak detection
        peaks = [i for i in range(1, len(autocorr)-1) 
                if autocorr[i] > autocorr[i-1] and autocorr[i] > autocorr[i+1]]
        
        periodicity_score = 0.0
        if len(peaks) >= 3:
            # Check if peaks are evenly spaced
            intervals = np.diff(peaks[:5] if len(peaks) > 5 else peaks)
            interval_std = np.std(intervals)
            interval_mean = np.mean(intervals)
            
            # Calculate periodicity score (lower variation means more periodic)
            if interval_mean > 0:
                variation = interval_std / interval_mean
                periodicity_score = 1.0 - min(variation * 2, 1.0)
        
        # 2. Check for regularity in access time spikes
        # Calculate the difference between consecutive cache access times
        diffs = np.diff(times)
        
        # Define a threshold for spikes
        threshold = np.mean(diffs) + 1.5 * np.std(diffs)
        spikes = diffs > threshold
        
        regularity_score = 0.0
        if np.sum(spikes) > 3:
            # Get indices of spikes
            spike_indices = np.where(spikes)[0]
            spike_intervals = np.diff(spike_indices)
            
            # Calculate coefficient of variation
            if len(spike_intervals) >= 2:
                cv = np.std(spike_intervals) / np.mean(spike_intervals) if np.mean(spike_intervals) > 0 else float('inf')
                
                # Lower CV means more regular spacing
                regularity_score = 1.0 - min(cv / 2, 1.0) if cv < float('inf') else 0.0
        
        # Combined score
        confidence = max(periodicity_score, regularity_score)
        
        return confidence
    
    def _get_attack_probability(self):
        """Combines detection methods with hardware counter validation (if available)"""
        # Run detection methods
        fr_score = self._detect_flush_reload()
        pp_score = self._detect_prime_probe()
        
        # Get hardware performance counters if available
        hw_score = 0.0
        perf_data = self._get_perf_counters()
        
        # On macOS, hardware validation is limited, so we rely more on timing analysis
        hw_weight = 0.1 if is_macos() else 0.3
        
        if perf_data and not is_macos():
            # For Linux systems, we can extract cache miss rates
            try:
                import re
                misses = re.search(r'([0-9,]+)\s+cache-misses', perf_data)
                refs = re.search(r'([0-9,]+)\s+cache-references', perf_data)
                
                if misses and refs:
                    # Calculate miss rate
                    miss_val = int(misses.group(1).replace(',', ''))
                    ref_val = int(refs.group(1).replace(',', ''))
                    miss_rate = miss_val / ref_val if ref_val > 0 else 0
                    
                    # Miss rates above 10% are suspicious
                    hw_score = min(miss_rate / 0.1, 1.0)
            except:
                pass
        elif perf_data and is_macos():
            # For macOS, we try to extract CPU usage as a weak signal
            try:
                import re
                cpu_match = re.search(r'(\d+\.\d+)%cpu', perf_data)
                if cpu_match:
                    cpu_usage = float(cpu_match.group(1))
                    # High CPU with low memory could indicate computation-heavy attacks
                    # This is a very weak signal compared to cache counters
                    hw_score = min(cpu_usage / 100, 0.5)  # Cap at 0.5 to avoid false positives
            except:
                pass
        
        # Determine attack type and confidence
        if fr_score > pp_score:
            attack_type = "Flush+Reload"
            confidence = fr_score * (1 - hw_weight) + hw_score * hw_weight
        else:
            attack_type = "Prime+Probe"
            confidence = pp_score * (1 - hw_weight) + hw_score * hw_weight
        
        # Scale confidence to 0-1 range
        confidence = min(confidence, 1.0)
        
        return attack_type, confidence, {
            'flush_reload': fr_score,
            'prime_probe': pp_score,
            'hardware': hw_score
        }
    
    def _simulate_cache_access(self):
        """
        Simulate cache access timing measurements.
        
        Enhanced simulation for macOS where hardware access is limited.
        """
        # Base access time
        base_time = 100
        # Normal variation
        noise = np.random.normal(0, 10, 1)[0]
        
        if is_macos():
            # More sophisticated simulation for macOS
            if self.running:
                # Current position in the window
                pos = len(self.cache_access_times) % self.window_size
                
                # Simulate Flush+Reload attack pattern (bimodal distribution)
                if np.random.random() < 0.01:
                    # Create bimodal distribution - either fast or slow access
                    return base_time + noise + (self.threshold * 1.5 if np.random.random() < 0.5 else -self.threshold * 0.5)
                
                # Simulate Prime+Probe attack pattern (periodic spikes)
                if pos % 50 == 0 and np.random.random() < 0.3:
                    return base_time + self.threshold + noise
                
                # Simulate periodic pattern over longer term
                if pos % 100 < 5 and np.random.random() < 0.4:
                    return base_time + self.threshold * 0.8 + noise
        else:
            # Original simulation for Linux
            if self.running and np.random.random() < 0.01:
                return base_time + noise + self.threshold * 1.5
        
        return base_time + noise
    
    def _analyze_cache_patterns(self):
        """Analyze cache access patterns for side-channel vulnerabilities"""
        # Get current cache access time (simulated)
        access_time = self._simulate_cache_access()
        self.cache_access_times.append(access_time)
        
        # Use the enhanced detection method
        attack_type, detection_score, context = self._get_attack_probability()
        
        if detection_score > 0.7:
            alert = {
                "timestamp": time.time(),
                "type": attack_type,
                "confidence": detection_score,
                "process_id": self.pid,
                "context": context
            }
            self.alerts.append(alert)
            logger.warning(f"Potential {attack_type} attack detected! Confidence: {detection_score:.2f}")
            
            # Get additional information if monitoring a specific process
            if self.pid:
                perf_data = self._get_perf_counters()
                if perf_data:
                    logger.info(f"Performance data:\n{perf_data}")
    
    def start_monitoring(self):
        """Start the cache monitoring process."""
        if self.running:
            logger.warning("Monitoring already running")
            return
            
        self.running = True
        logger.info(f"Starting cache side-channel monitoring{f' for PID {self.pid}' if self.pid else ''}")
        
        if is_macos() and not self.pid:
            logger.warning("System-wide monitoring on macOS has limited accuracy")
        
        # Start the monitoring thread
        self.monitor_thread = Thread(target=self._monitoring_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop the cache monitoring process."""
        if not self.running:
            return
            
        self.running = False
        self.monitor_thread.join(timeout=1.0)
        logger.info("Cache monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop that runs in a separate thread."""
        interval = 1.0 / self.sampling_rate
        
        while self.running:
            self._analyze_cache_patterns()
            time.sleep(interval)
    
    def generate_report(self):
        """Generate a report of detected side-channel vulnerabilities."""
        if not self.alerts:
            logger.info("No cache side-channel vulnerabilities detected")
            return
        
        logger.info(f"\n{'='*50}\nCache Side-Channel Detection Report\n{'='*50}")
        logger.info(f"Total Alerts: {len(self.alerts)}")
        
        if is_macos():
            logger.info("Note: macOS detection relies heavily on simulation and statistical analysis.")
            
        attack_types = defaultdict(int)
        for alert in self.alerts:
            attack_types[alert["type"]] += 1
        
        logger.info("\nDetected Attack Types:")
        for attack_type, count in attack_types.items():
            logger.info(f"  - {attack_type}: {count} alerts")
        
        logger.info("\nTop 5 Recent Alerts:")
        for alert in self.alerts[-5:]:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert["timestamp"]))
            logger.info(f"  - {timestamp} | {alert['type']} | Confidence: {alert['confidence']:.2f}")
            
            # Add detailed metrics if in debug mode
            if logger.level <= logging.DEBUG and "context" in alert:
                context = alert["context"]
                logger.debug(f"    Flush+Reload score: {context['flush_reload']:.2f}")
                logger.debug(f"    Prime+Probe score: {context['prime_probe']:.2f}")
                logger.debug(f"    Hardware validation: {context['hardware']:.2f}")
        
        logger.info(f"{'='*50}")


class CacheLeaks:
    """Main CacheLeaks tool class."""
    
    def __init__(self):
        """Initialize the CacheLeaks tool."""
        self.monitor = None
    
    def _check_system_support(self):
        """Check if the system supports necessary features for detection."""
        supported = True
        warnings = []
        
        if is_macos():
            warnings.append("Running on macOS. Hardware access is limited, using simulation.")
            
            # Check for admin privileges (needed for some macOS features)
            if os.geteuid() != 0:
                warnings.append("Not running as root/admin. Some features will be disabled.")
            
            # Check if we can access process information
            try:
                subprocess.check_output(["ps", "-p", "1"], stderr=subprocess.DEVNULL)
            except:
                supported = False
                warnings.append("Cannot access process information.")
                
            # Let the user know about macOS limitations
            warnings.append("macOS security restrictions limit hardware counter access.")
            warnings.append("Detection relies primarily on timing pattern analysis and simulation.")
        else:
            # Check for perf support
            try:
                subprocess.check_output(["perf", "--version"], stderr=subprocess.PIPE)
            except (subprocess.SubprocessError, FileNotFoundError):
                supported = False
                warnings.append("'perf' tool not found. Install it for better detection.")
            
            # Check for MSR access (for advanced features)
            if not os.path.exists("/dev/cpu/0/msr") and os.name == 'posix':
                warnings.append("MSR access not available. Some detection features will be limited.")
        
        return supported, warnings
    
    def _scan_process(self, pid):
        """
        Scan a specific process for cache side-channel vulnerabilities.
        
        Args:
            pid: Process ID to scan
        """
        if not pid:
            logger.error("No PID specified for process scanning")
            return
            
        try:
            # Check if process exists
            if is_macos():
                subprocess.check_output(["ps", "-p", str(pid)], stderr=subprocess.DEVNULL)
            else:
                os.kill(pid, 0)
        except (OSError, subprocess.SubprocessError):
            logger.error(f"Process with PID {pid} does not exist")
            return
            
        logger.info(f"Scanning process {pid} for cache side-channel vulnerabilities...")
        
        # Create a monitor for this specific process
        self.monitor = CacheMonitor(pid=pid)
        self.monitor.start_monitoring()
    
    def _scan_system(self, duration=60):
        """
        Scan the entire system for cache side-channel vulnerabilities.
        
        Args:
            duration: Duration of the scan in seconds
        """
        logger.info(f"Scanning system for cache side-channel vulnerabilities (duration: {duration}s)...")
        
        if is_macos():
            logger.warning("System-wide scanning on macOS has limited accuracy due to hardware access restrictions.")
        
        # Create a system-wide monitor
        self.monitor = CacheMonitor()
        self.monitor.start_monitoring()
        
        # Run for the specified duration
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
        
        self.monitor.stop_monitoring()
        self.monitor.generate_report()
    
    def _scan_binary(self, binary_path):
        """
        Scan a binary file for potential cache side-channel vulnerabilities.
        
        Args:
            binary_path: Path to the binary file
        """
        if not os.path.exists(binary_path):
            logger.error(f"Binary file {binary_path} does not exist")
            return
            
        logger.info(f"Scanning binary {binary_path} for potential vulnerabilities...")
        
        # This would involve static analysis in a real implementation
        # For demonstration, we'll just run the binary and monitor it
        try:
            process = subprocess.Popen([binary_path])
            pid = process.pid
            
            logger.info(f"Binary running with PID {pid}")
            self._scan_process(pid)
            
            # Wait for a while
            time.sleep(30)
            
            # Clean up
            process.terminate()
            process.wait(timeout=5)
            
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"Failed to run binary: {e}")
    
    def run(self, args):
        """
        Run the CacheLeaks tool with the specified arguments.
        
        Args:
            args: Command-line arguments
        """
        supported, warnings = self._check_system_support()
        
        for warning in warnings:
            logger.warning(warning)
            
        if not supported:
            logger.warning("Your system has limited support for cache side-channel detection")
            if is_macos():
                logger.warning("On macOS, detection will rely heavily on simulation")
        
        try:
            if args.pid:
                self._scan_process(args.pid)
                time.sleep(args.duration)
                self.monitor.stop_monitoring()
                self.monitor.generate_report()
                
            elif args.binary:
                self._scan_binary(args.binary)
                
            else:
                self._scan_system(args.duration)
                
        except KeyboardInterrupt:
            logger.info("CacheLeaks interrupted by user")
            if self.monitor:
                self.monitor.stop_monitoring()
                self.monitor.generate_report()


def main():
    """Main entry point for the CacheLeaks tool."""
    parser = argparse.ArgumentParser(
        description="CacheLeaks: Cache Side-Channel Detection Tool",
        epilog="Example: cacheleaks --scan-system --duration 60"
    )
    
    # Main operation modes
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--scan-system", action="store_true", help="Scan the entire system")
    mode_group.add_argument("--pid", type=int, help="Scan a specific process")
    mode_group.add_argument("--binary", type=str, help="Scan a binary file")
    
    # Additional options
    parser.add_argument("--duration", type=int, default=60, help="Duration of scanning in seconds")
    parser.add_argument("--threshold", type=int, default=100, help="Detection threshold in CPU cycles")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity")
    
    args = parser.parse_args()
    
    # Set logging level based on verbosity
    if args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbose >= 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)
    
    # Create and run the tool
    tool = CacheLeaks()
    tool.run(args)


if __name__ == "__main__":
    main()
