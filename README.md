# Web Log Brute-Force Analyzer

A robust, Python-based security script designed to parse web server access logs and detect HTTP brute-force authentication attacks using a sliding-window algorithm.

## Features
* **Sliding Window Detection:** Tracks failed authentication attempts within a configurable time window (default: 4 failures in 5 minutes).
* **Compromise Correlation:** Automatically flags an IP address as `[COMPROMISED]` if a successful login (HTTP 200/302) immediately follows a brute-force sequence.
* **Memory Safe:** Implements a strict `MAX_TRACKED_IPS` cap (10,000) to prevent memory exhaustion during massive volumetric attacks.
* **Chronological Sorting:** Safely handles out-of-order log entries by sorting events by timestamp prior to analysis.
* **JSON Export:** Automatically generates a `threat_report.json` file for integration with SIEMs or dashboarding tools.

## Prerequisites
* Python 3.6+
* Standard web server logs (Apache/Nginx format) containing timestamps and HTTP status codes.

## Installation
Clone the repository to your local machine:
```bash
git clone [https://github.com/sajid-sec/log-analyzer.git](https://github.com/sajid-sec/log-analyzer.git)
cd log-analyzer
