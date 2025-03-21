# CacheLeaks - Cache Side-Channel Attack Detection Tool
## Overview
CacheLeaks is a tool for detecting cache side-channel attacks, specifically designed to identify Flush+Reload and Prime+Probe attack patterns. The system monitors cache access timing patterns and uses statistical analysis to differentiate between normal system behavior and malicious side-channel activity.

## Files in this Repository
cacheleaks.py: The main detection tool for identifying cache side-channel attacks

cacheleaks_mac_sim.py: A macOS-optimized version with simulation capabilities

flush_reload.csv: Sample data containing Flush+Reload attack patterns

prime_probe.csv: Sample data containing Prime+Probe attack patterns

Flush_Flush.ipynb: Jupyter notebook simulating Flush+Flush attack technique

Prime_Probe.ipynb: Jupyter notebook simulating Prime+Probe attack techniques


# Running the Detection Tool

## Run the generated data simulation
python cacheleaks_mac_sim.py --scan-system --duration 10

## Running Flush+Reload with Mastik integration
python cacheleaks.py --csv-file flush_reload.csv --verbose

## Run Prime+Probe data with Mastik integration
python cacheleaks.py --csv-file prime_probe.csv --verbose


--csv-file: Path to CSV file with timing samples
--window-size: Analysis window size (default: 50)
--threshold: Detection confidence threshold (default: 0.6)
--verbose: Enable detailed logging

Detection Accuracy
Based on our testing with the provided datasets:

Flush+Reload detection: 73% accuracy
Prime+Probe detection: 55% accuracy

Example Output

==================================================

Total Alerts: 220

Detected Attack Types:
  - Flush+Reload: 220 alerts
Detection Accuracy: 0.73 (160/220)

Confusion Matrix:
  Actual vs Detected:
  - normal detected as flush_reload: 60 times
  - flush_reload detected as flush_reload: 160 times

Recent Alerts:
  - 16:05:09 | Flush+Reload | Confidence: 0.60
  - 16:05:09 | Flush+Reload | Confidence: 0.60
  - 16:05:09 | Flush+Reload | Confidence: 0.60
  - 16:05:09 | Flush+Reload | Confidence: 0.60
  - 16:05:09 | Flush+Reload | Confidence: 0.60

==================================================

# CacheLeaks Implementation Details
## Data Processing
The system processes CSV timing data with 6 columns including timestamps, access times, cache hits, and attack type labels. It maintains a sliding window of recent cache accesses using memory-efficient data structures.
## Detection Algorithms
### Flush+Reload Detection:
This algorithm identifies bimodal distributions in cache access times. It creates histograms of timing data, finds peaks, and calculates valley-to-peak ratios. Lower ratios between timing clusters produce higher confidence scores, as deeper valleys between peaks are characteristic of Flush+Reload attacks.
### Prime+Probe Detection:
This detector focuses on periodicity in cache access patterns. It calculates differences between consecutive timing samples, identifies spikes above a dynamic threshold, and analyzes the regularity of intervals between spikes. More consistent intervals suggest coordinated Prime+Probe operations.
## Calibration System
The system auto-calibrates by analyzing provided data samples to determine optimal thresholds between cache hits and misses for the specific hardware. It extracts timing signatures for different attack types and adjusts classification weights based on observed characteristics.
## Mastik Integration
CacheLeaks integrates with Mastik data by extracting attack signatures from CSV outputs and using them as reference patterns for comparison with live measurements. This improves detection accuracy by matching against known attack patterns.

## Technical Design Choices

Fixed-size sliding windows maintain recent timing history without increasing memory usage

Dynamically adjusted statistical thresholds adapt to different hardware characteristics

Multiple detection signals are combined for greater accuracy and resilience against evasion

Background thread processing enables continuous monitoring without blocking

Weighted confidence scoring provides nuanced attack probability estimation
