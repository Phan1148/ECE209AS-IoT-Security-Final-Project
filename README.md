# CacheLeaks - Cache Side-Channel Attack Detection Tool
## Overview
CacheLeaks is a sophisticated tool for detecting cache side-channel attacks, specifically designed to identify Flush+Reload and Prime+Probe attack patterns. The system monitors cache access timing patterns and uses statistical analysis to differentiate between normal system behavior and malicious side-channel activity.
Files in this Repository

cacheleaks.py: The main detection tool for identifying cache side-channel attacks
cacheleaks_mac_sim.py: A macOS-optimized version with simulation capabilities
flush_reload.csv: Sample data containing Flush+Reload attack patterns
prime_probe.csv: Sample data containing Prime+Probe attack patterns
Flush_Flush.ipynb: Jupyter notebook simulating Flush+Flush attack technique
Prime_Probe.ipynb: Jupyter notebook simulating Prime+Probe attack technique

Attack Simulations
Flush+Reload Simulation (Flush_Flush.ipynb)
This notebook demonstrates the Flush+Reload attack technique, a powerful cache side-channel attack that can extract cryptographic keys and other sensitive information. The simulation:

Creates controlled cache access patterns
Demonstrates how an attacker can determine if data is in cache
Shows resulting timing distributions that CacheLeaks detects
Includes visualization of the bimodal timing distribution characteristic of this attack

Prime+Probe Simulation (Prime_Probe.ipynb)
This notebook simulates the Prime+Probe attack technique, which doesn't require shared memory between attacker and victim. The simulation:

Demonstrates priming cache sets with attacker-controlled data
Shows the probing phase to detect victim accesses
Illustrates the periodic patterns in cache timing that occur during the attack
Includes visualizations of cache set conflicts

# Running the Detection Tool

## Run the generated data simulation
python cacheleaks_mac_sim.py

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

## System Requirements
Python Dependencies

numpy
matplotlib (for visualization if running the notebooks)
pandas (for data processing)

## Optional Dependencies

scipy (for enhanced statistical analysis)
sklearn (for clustering algorithms)

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

## Implementation Details
CacheLeaks uses a sliding window approach to analyze cache timing patterns. For Flush+Reload, it looks for bimodal distributions, while for Prime+Probe, it detects periodic patterns using autocorrelation analysis.
The tool adapts to your system's specific timing characteristics through an automatic calibration phase that analyzes the provided datasets.
