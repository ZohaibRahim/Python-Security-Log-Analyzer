"""
alert_summary.py

Parse a log file, counts FAILED entries grouped by source IP,
and classifies each IP using a two-tier severity model:
- WARNING:   crosses the warn threshold (possible pattern, worth watching)
- CONFIRMED: crosses the confirm threshold (high-confidence pattern)
"""

import argparse
import re
from collections import Counter

IP_PATTERN = re.compile (r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def classify(count, warn_threshold, confirm_threshold):
  if count >= confirm_threshold:
    return "CONFIRMED"
  elif count >= warn_threshold:
    return "WARNING"
  return None

def parse_log(path, keyword="FAILED"):
  ip_counts = Counter()
  unmatched = 0
  total_flagged = 0
  
  with open(path, "r") as f:
    for line in f:
      if keyword not in line:
        continue
      total_flagged += 1
      match = IP_PATTERN.search(line)
      if match:
        ip_counts[match.group()] += 1
      else:
        unmatched += 1
  
  return ip_counts, unmatched, total_flagged

def main():
  parser = argparse.ArgumentParser(description="Summarize failure patterns in a log file.")
  parser.add_argument("path", help="Path to the log file.")
  parser.add_argument("--keyword", default="FAILED", help="Keyword to flag (default: FAILED)")
  parser.add_argument("--warn-threshold", type=int, default=2, help="Repeat count to flag as a warning (default: 2)")
  parser.add_argument("--confirm-threshold", type=int, default=3, help="Repeat count to flag as confirmed (default: 3)")
  args = parser.parse_args()
  
  ip_counts, unmatched, total_flagged = parse_log(args.path, args.keyword)
  
  print(f"Total '{args.keyword}' entries: {total_flagged}")
  print(f"Entries with no IP address: {unmatched}\n")
  
  print("Failures by source IP: ")
  warning_count = 0
  confirmed_count = 0
  for ip, count in ip_counts.most_common():
    status = classify(count, args.warn_threshold, args.confirm_threshold)
    if status == "CONFIRMED":
        confirmed_count += 1
        print(f"  {ip}: {count}  <-- CONFIRMED pattern")
    elif status == "WARNING":
        warning_count += 1
        print(f"  {ip}: {count}  <-- WARNING, monitor")
    else:
        print(f"  {ip}: {count}")
  
  print(f"\n{confirmed_count} IP(s) CONFIRMED, {warning_count} IP(s) at WARNING level.")

if __name__ == "__main__":
  main()
