"""
CacheLeaks: Cache Side-Channel Detection Tool
Enhanced for accuracy with improved classification algorithms
"""

import os
import sys
import time
import argparse
import logging
import numpy as np
import csv
from threading import Thread
from collections import defaultdict, deque

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("CacheLeaks")

class CacheMonitor:
    def __init__(self, csv_file=None, window_size=50):
        self.window_size = window_size
        self.running = False
        self.cache_access_times = deque(maxlen=window_size)
        self.cache_hit_status = deque(maxlen=window_size)
        self.alerts = []
        
        # Store attack patterns
        self.patterns = {
            'flush_reload': [], 
            'prime_probe': [],
            'evict_reload': [],
            'normal': []
        }
        
        # Store all samples for analysis
        self.all_samples = []
        self.current_index = 0
        
        # Calibration thresholds
        self.flush_reload_threshold = None
        self.prime_probe_threshold = None
        
        # Load and calibrate with CSV data
        if csv_file and os.path.exists(csv_file):
            success = self.load_csv_data(csv_file)
            if success:
                self.calibrate_detection()
                
        # Set detection mode
        self.has_reference_data = len(self.all_samples) > 0
    
    def load_csv_data(self, csv_file):
        """Load timing data from CSV file with attack type information"""
        try:
            with open(csv_file, 'r') as f:
                reader = csv.reader(f)
                headers = next(reader)  # Skip header row
                
                # Check column format
                if len(headers) < 4:
                    logger.error(f"CSV file needs at least 4 columns, found {len(headers)}")
                    return False
                
                # Reset data structures
                self.all_samples = []
                for k in self.patterns:
                    self.patterns[k] = []
                
                # Process data rows
                for row in reader:
                    if len(row) >= 4:
                        try:
                            # Extract core information
                            access_time = float(row[1])
                            cache_hit = int(row[2]) if len(row) > 2 else None
                            attack_type = row[3].lower() if len(row) > 3 else "unknown"
                            
                            # Create sample dictionary
                            sample = {
                                'timestamp': float(row[0]) if len(row) > 0 else time.time(),
                                'access_time': access_time,
                                'cache_hit': cache_hit,
                                'attack_type': attack_type
                            }
                            
                            # Add CPU usage and memory pattern if available
                            if len(row) >= 5:
                                sample['cpu_usage'] = float(row[4])
                            if len(row) >= 6:
                                sample['memory_pattern'] = row[5]
                            
                            # Add to our dataset
                            self.all_samples.append(sample)
                            
                            # Categorize into pattern groups
                            if 'flush' in attack_type or 'fr' == attack_type:
                                self.patterns['flush_reload'].append(sample)
                            elif 'prime' in attack_type or 'pp' == attack_type:
                                self.patterns['prime_probe'].append(sample)
                            elif 'evict' in attack_type or 'er' == attack_type:
                                self.patterns['evict_reload'].append(sample)
                            elif 'normal' in attack_type:
                                self.patterns['normal'].append(sample)
                                    
                        except (ValueError, IndexError) as e:
                            logger.debug(f"Error parsing row: {e}")
                            continue
            
            # Log statistics about the loaded data
            logger.info(f"Loaded {len(self.all_samples)} samples from CSV")
            for attack_type, samples in self.patterns.items():
                if samples:
                    times = [s['access_time'] for s in samples]
                    logger.info(f"  - {attack_type}: {len(samples)} samples")
                    if times:
                        logger.info(f"    Mean: {np.mean(times):.2f}, Min: {np.min(times):.2f}, Max: {np.max(times):.2f}")
            
            return len(self.all_samples) > 0
            
        except Exception as e:
            logger.error(f"Error loading CSV data: {e}")
            return False
    
    def calibrate_detection(self):
        """Analyze the loaded data to calibrate detection thresholds"""
        if not self.all_samples:
            logger.warning("No data to calibrate with")
            return False
            
        logger.info("Calibrating detection algorithms...")
        
        # 1. Find optimal threshold for Flush+Reload
        try:
            # Extract all timing samples
            all_times = np.array([s['access_time'] for s in self.all_samples])
            
            # Use simple K-means-like approach to find 2 clusters (cache hit vs miss)
            sorted_times = np.sort(all_times)
            diffs = np.diff(sorted_times)
            # Find largest gap between consecutive times
            max_diff_idx = np.argmax(diffs)
            # Threshold is at the middle of the largest gap
            self.flush_reload_threshold = (sorted_times[max_diff_idx] + sorted_times[max_diff_idx+1]) / 2
            logger.info(f"Flush+Reload threshold calibrated to: {self.flush_reload_threshold:.2f}")
            
            # Get typical patterns for each attack
            fr_times = [s['access_time'] for s in self.patterns['flush_reload']] if self.patterns['flush_reload'] else []
            pp_times = [s['access_time'] for s in self.patterns['prime_probe']] if self.patterns['prime_probe'] else []
            normal_times = [s['access_time'] for s in self.patterns['normal']] if self.patterns['normal'] else []
            
            # Calculate bimodality statistics for Flush+Reload
            if fr_times:
                # Create histogram
                hist, bin_edges = np.histogram(fr_times, bins=50)
                # Find peaks as local maxima
                peaks = []
                for i in range(1, len(hist)-1):
                    if hist[i] > hist[i-1] and hist[i] > hist[i+1]:
                        peaks.append(i)
                
                self.fr_peak_count = len(peaks)
                self.fr_std = np.std(fr_times)
                self.fr_mean = np.mean(fr_times)
                logger.info(f"Flush+Reload pattern: peaks={self.fr_peak_count}, std={self.fr_std:.2f}")
            
            # Calculate periodicity statistics for Prime+Probe
            if pp_times:
                pp_times = np.array(pp_times)
                pp_diffs = np.diff(pp_times)
                self.pp_mean_diff = np.mean(pp_diffs)
                self.pp_std_diff = np.std(pp_diffs)
                self.pp_threshold = np.mean(pp_diffs) + 1.5 * np.std(pp_diffs)
                logger.info(f"Prime+Probe pattern: mean_diff={self.pp_mean_diff:.2f}, threshold={self.pp_threshold:.2f}")
            
            # Calculate normal behavior statistics
            if normal_times:
                self.normal_mean = np.mean(normal_times)
                self.normal_std = np.std(normal_times)
                logger.info(f"Normal pattern: mean={self.normal_mean:.2f}, std={self.normal_std:.2f}")

            # Calculate cache hit/miss ratios
            if fr_times and hasattr(self, 'flush_reload_threshold'):
                fr_hits = sum(1 for t in fr_times if t < self.flush_reload_threshold)
                fr_total = len(fr_times)
                self.fr_hit_ratio = fr_hits / fr_total if fr_total > 0 else 0
                logger.info(f"Flush+Reload hit ratio: {self.fr_hit_ratio:.2f}")
                
            if pp_times and hasattr(self, 'flush_reload_threshold'):
                pp_hits = sum(1 for t in pp_times if t < self.flush_reload_threshold)
                pp_total = len(pp_times)
                self.pp_hit_ratio = pp_hits / pp_total if pp_total > 0 else 0
                logger.info(f"Prime+Probe hit ratio: {self.pp_hit_ratio:.2f}")
            
            # Set default classification weights
            self.classification_weights = {
                'bimodality_weight': 0.6,
                'periodicity_weight': 0.3,
                'hit_ratio_weight': 0.1
            }
                
            return True
            
        except Exception as e:
            logger.error(f"Error during calibration: {e}")
            return False
    
    def _get_interval_pattern(self, times):
        """Extract the pattern of intervals between significant timing changes"""
        if not times or len(times) < 10:
            return []
            
        times = np.array(times)
        diffs = np.diff(times)
        threshold = np.mean(diffs) + 1.5 * np.std(diffs)
        spikes = diffs > threshold
        
        if np.sum(spikes) < 2:
            return []
            
        spike_indices = np.where(spikes)[0]
        intervals = np.diff(spike_indices)
        
        return intervals
    
    def _detect_flush_reload(self, window=None):
        """Enhanced Flush+Reload detection using patterns learned from data"""
        if window is None:
            window = list(self.cache_access_times)
            
        if not window or len(window) < 10:
            return 0.0
        
        times = np.array(window)
        
        # 1. Check for bimodal distribution (characteristic of Flush+Reload)
        hist, bin_edges = np.histogram(times, bins=50)
        
        # Find peaks as local maxima
        peaks = []
        for i in range(1, len(hist)-1):
            if hist[i] > hist[i-1] and hist[i] > hist[i+1]:
                peaks.append(i)
        
        # Calculate statistics
        mean = np.mean(times)
        std = np.std(times)
        
        # Basic bimodal score
        bimodal_score = 0.0
        if len(peaks) >= 2 and std > mean * 0.2:
            # Measure valley-to-peak ratio
            valleys = []
            for i in range(len(peaks)-1):
                valley_region = hist[peaks[i]:peaks[i+1]]
                if len(valley_region) > 0:
                    valleys.append(np.min(valley_region))
            
            if valleys:
                avg_valley = np.mean(valleys)
                avg_peak = np.mean([hist[p] for p in peaks])
                ratio = avg_valley / avg_peak if avg_peak > 0 else 1.0
                bimodal_score = 1.0 - min(ratio * 2, 1.0)
        
        # 2. Check for cache hit/miss distribution if threshold available
        threshold_score = 0.0
        if hasattr(self, 'flush_reload_threshold'):
            # Count samples on each side of threshold
            below = np.sum(times < self.flush_reload_threshold)
            above = len(times) - below
            
            # Calculate ratio (should be split for Flush+Reload)
            if len(times) > 0:
                split_ratio = min(below, above) / len(times)
                threshold_score = split_ratio * 2  # Scale to [0,1]
        
        # 3. Hit ratio score if available
        hit_ratio_score = 0.0
        if hasattr(self, 'fr_hit_ratio') and len(self.cache_hit_status) > 0:
            hits = np.array(list(self.cache_hit_status))
            current_hit_ratio = np.mean(hits)
            hit_ratio_score = 1.0 - min(abs(current_hit_ratio - self.fr_hit_ratio) / 0.5, 1.0)
        
        # Combine scores with weights from calibration if available
        if hasattr(self, 'classification_weights'):
            weights = self.classification_weights
            return (
                weights.get('bimodality_weight', 0.6) * bimodal_score +
                weights.get('periodicity_weight', 0.3) * threshold_score +
                weights.get('hit_ratio_weight', 0.1) * hit_ratio_score
            )
        
        # Default weights
        return 0.6 * bimodal_score + 0.3 * threshold_score + 0.1 * hit_ratio_score
    
    def _detect_prime_probe(self, window=None):
        """Enhanced Prime+Probe detection using learned patterns"""
        if window is None:
            window = list(self.cache_access_times)
            
        if not window or len(window) < 10:
            return 0.0
        
        times = np.array(window)
        
        # 1. Check for periodicity in access times
        diffs = np.diff(times)
        
        # Use calibrated threshold if available
        threshold = self.pp_threshold if hasattr(self, 'pp_threshold') else (np.mean(diffs) + 1.5 * np.std(diffs))
        spikes = diffs > threshold
        
        periodicity_score = 0.0
        if np.sum(spikes) >= 3:
            # Get spike intervals
            spike_indices = np.where(spikes)[0]
            intervals = np.diff(spike_indices)
            
            if len(intervals) >= 2:
                # Calculate coefficient of variation (lower means more regular)
                mean_interval = np.mean(intervals)
                std_interval = np.std(intervals)
                cv = std_interval / mean_interval if mean_interval > 0 else float('inf')
                
                # Higher score for lower variation (more periodic)
                periodicity_score = 1.0 - min(cv / 2, 1.0) if cv < float('inf') else 0.0
        
        # 2. Check for uniform distribution (vs bimodal for Flush+Reload)
        hist, bin_edges = np.histogram(times, bins=50)
        
        # Calculate variance of histogram (lower variance = more uniform = Prime+Probe)
        hist_normalized = hist / np.sum(hist) if np.sum(hist) > 0 else hist
        hist_var = np.var(hist_normalized)
        uniformity_score = 1.0 - min(hist_var * 20, 1.0)  # Scale appropriately
        
        # 3. Check hit ratio pattern if available
        hit_ratio_score = 0.0
        if hasattr(self, 'pp_hit_ratio') and len(self.cache_hit_status) > 0:
            hits = np.array(list(self.cache_hit_status))
            current_hit_ratio = np.mean(hits)
            hit_ratio_score = 1.0 - min(abs(current_hit_ratio - self.pp_hit_ratio) / 0.5, 1.0)
        
        # Combine scores with weights from calibration if available
        if hasattr(self, 'classification_weights'):
            weights = self.classification_weights
            return (
                weights.get('bimodality_weight', 0.6) * uniformity_score +
                weights.get('periodicity_weight', 0.3) * periodicity_score +
                weights.get('hit_ratio_weight', 0.1) * hit_ratio_score
            )
        
        # Default weights
        return 0.5 * uniformity_score + 0.4 * periodicity_score + 0.1 * hit_ratio_score
    
    def _get_attack_probability(self):
        """Determine most likely attack type and confidence"""
        if len(self.cache_access_times) < 10:
            return "Unknown", 0.0, {}
        
        window = list(self.cache_access_times)
        
        # Get detection scores
        fr_score = self._detect_flush_reload(window)
        pp_score = self._detect_prime_probe(window)
        
        # Add classification bias based on training data proportions
        if hasattr(self, 'fr_count') and hasattr(self, 'pp_count'):
            total = self.fr_count + self.pp_count
            if total > 0:
                # Adjust scores based on prior probabilities
                fr_prior = self.fr_count / total
                pp_prior = self.pp_count / total
                fr_score = fr_score * (0.7 + 0.3 * fr_prior)
                pp_score = pp_score * (0.7 + 0.3 * pp_prior)
        
        scores = {
            "Flush+Reload": fr_score,
            "Prime+Probe": pp_score
        }
        
        # Get attack type with highest score
        attack_type = max(scores, key=scores.get)
        confidence = scores[attack_type]
        
        # Normalize confidence
        confidence = min(confidence, 1.0)
        
        return attack_type, confidence, scores
    
    def _get_next_sample(self):
        """Get next sample from the dataset"""
        if not self.all_samples:
            # Fallback to simulation
            return self._simulate_timing()
        
        # Get sample from the loaded data
        sample = self.all_samples[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.all_samples)
        
        return sample
    
    def _simulate_timing(self):
        """Generate simulated timing data when no CSV is available"""
        base_time = 100
        noise = np.random.normal(0, 10)
        
        return {
            'timestamp': time.time(),
            'access_time': base_time + noise,
            'cache_hit': 1 if np.random.random() < 0.8 else 0,
            'attack_type': 'normal',
            'cpu_usage': 5.0 + np.random.random() * 10,
            'memory_pattern': 'sequential'
        }
    
    def _analyze_cache_patterns(self):
        """Process next timing sample and check for attack patterns"""
        sample = self._get_next_sample()
        
        # Add to our sliding windows
        self.cache_access_times.append(sample['access_time'])
        if 'cache_hit' in sample and sample['cache_hit'] is not None:
            self.cache_hit_status.append(sample['cache_hit'])
        
        # Detect attacks
        attack_type, confidence, scores = self._get_attack_probability()
        
        # Log alerts for high-confidence detections
        if confidence > 0.6:  # Lower threshold for better recall
            # Convert attack type format
            detected_type = attack_type.lower().replace('+', '_')
            actual_type = sample['attack_type'].lower()
            
            alert = {
                "timestamp": time.time(),
                "type": attack_type,
                "real_type": sample['attack_type'],
                "confidence": confidence,
                "scores": scores,
                "access_time": sample['access_time']
            }
            self.alerts.append(alert)
            
            # Colorize output based on correct detection
            is_correct = detected_type in actual_type or actual_type in detected_type
            color = "\033[92m" if is_correct else "\033[91m"  # Green for correct, red for incorrect
            
            # Only log at debug level to avoid too much output
            logger.debug(f"{color}Detected: {attack_type} (conf: {confidence:.2f}, actual: {sample['attack_type']})\033[0m")
    
    def start_monitoring(self):
        """Start the monitoring process"""
        if self.running:
            return
            
        # Store counts for prior probability calculation
        self.fr_count = len(self.patterns['flush_reload'])
        self.pp_count = len(self.patterns['prime_probe'])
        
        self.running = True
        logger.info(f"Starting monitoring with {len(self.all_samples)} samples...")
        
        self.monitor_thread = Thread(target=self._monitoring_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop the monitoring process"""
        if not self.running:
            return
            
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=1.0)
        logger.info("Monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop with improved report generation"""
        samples_processed = 0
        max_samples = len(self.all_samples) if self.all_samples else 10000
        
        while self.running and samples_processed < max_samples:
            self._analyze_cache_patterns()
            samples_processed += 1
            
            # Process faster for large datasets
            if len(self.all_samples) > 1000:
                if samples_processed % 1000 == 0:
                    logger.info(f"Processed {samples_processed}/{max_samples} samples")
                time.sleep(0.0001)  # Very fast processing
            else:
                time.sleep(0.001)  # Normal speed
        
        # When finished, stop monitoring and generate report immediately
        self.running = False
        logger.info(f"Processed {samples_processed}/{max_samples} samples")
        
        # Generate report directly from here to ensure it's displayed
        self.generate_report()
    
    def generate_report(self):
        """Generate detection report with accuracy metrics matching the desired format"""
        if not self.alerts:
            logger.info("No cache side-channel attacks detected")
            return
        
        # Count detections by type
        attack_types = defaultdict(int)
        for alert in self.alerts:
            attack_type = alert["type"]
            attack_types[attack_type] += 1
        
        # Calculate detection accuracy
        correct_detections = 0
        if self.all_samples:
            for alert in self.alerts:
                detected = alert["type"].lower().replace("+", "_")
                actual = alert["real_type"].lower()
                if detected in actual or actual in detected:
                    correct_detections += 1
        
        # Calculate confusion matrix
        confusion = defaultdict(lambda: defaultdict(int))
        for alert in self.alerts:
            detected = alert["type"].lower().replace("+", "_")
            actual = alert["real_type"].lower()
            confusion[actual][detected] += 1
        
        # Start printing report in desired format
        logger.info("="*50)
        logger.info("Detection Report")
        logger.info("="*50)
        logger.info(f"Total Alerts: {len(self.alerts)}")
        logger.info("")
        logger.info("Detected Attack Types:")
        for attack_type, count in attack_types.items():
            logger.info(f"  - {attack_type}: {count} alerts")
        
        # Accuracy
        accuracy = correct_detections / len(self.alerts) if len(self.alerts) > 0 else 0
        logger.info(f"Detection Accuracy: {accuracy:.2f} ({correct_detections}/{len(self.alerts)})")
        
        # Confusion Matrix
        logger.info("")
        logger.info("Confusion Matrix:")
        logger.info("  Actual vs Detected:")
        for actual, detections in confusion.items():
            for detected, count in detections.items():
                logger.info(f"  - {actual} detected as {detected}: {count} times")
        
        # Recent Alerts - exactly matching the format in the example
        logger.info("")
        logger.info("Recent Alerts:")
        for alert in self.alerts[-5:]:
            timestamp = time.strftime('%H:%M:%S', time.localtime(alert["timestamp"]))
            logger.info(f"  - {timestamp} | {alert['type']} | Confidence: {alert['confidence']:.2f}")
        
        logger.info("="*50)


def main():
    parser = argparse.ArgumentParser(description='CacheLeaks: Cache Side-Channel Detection')
    parser.add_argument('--csv-file', type=str, help='Path to CSV data file with timing samples')
    parser.add_argument('--window-size', type=int, default=50, help='Analysis window size')
    parser.add_argument('--threshold', type=float, default=0.6, help='Detection confidence threshold')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Check if CSV file exists
    if args.csv_file and not os.path.exists(args.csv_file):
        logger.error(f"CSV file not found: {args.csv_file}")
        return
    
    # Create and run monitor
    monitor = CacheMonitor(csv_file=args.csv_file, window_size=args.window_size)
    
    if not monitor.has_reference_data:
        logger.warning("No reference data loaded. Will use simulation only.")
    
    try:
        monitor.start_monitoring()
        logger.info("Processing samples...")
        
        # Wait for monitoring to complete with a timeout
        max_wait_time = 60  # Maximum wait time in seconds
        wait_start = time.time()
        while monitor.running and (time.time() - wait_start < max_wait_time):
            time.sleep(0.1)
        
        # Report is generated in the monitoring loop, but add a check in case of timeout
        if monitor.running:
            logger.warning("Monitoring took too long and timed out")
            monitor.stop_monitoring()
            # Generate report if it wasn't generated in the monitoring loop
            monitor.generate_report()
            
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        if monitor.running:
            monitor.stop_monitoring()
            monitor.generate_report()
        sys.exit(0)


if __name__ == "__main__":
    main()
