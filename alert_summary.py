"""
alert_summary.py

Parse a log file, counts FAILED entries grouped by source IP,
and flags IPs that cross a repeat-failure threshold as a possible
brute-force pattern.
"""

import argparse
import re
from collections import Counter

IP_PATTERN = re.compile (r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def parse_log(path, keyword="FAILED", threshold=2):
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
  parser.add_argument("--threshold", type=int, default=2, help="Repeat count to flag as suspicious (default: 2)")
  
  ip_counts, unmatched, total flagged = parse_log(args.path, args.keyword, args.threshold)
  
  print(f"Total '{args.keyword}' entries: {total_flagged}")
  print(f"Entries with no IP address: {unmatched}\n")
  
  print("Failures by source IP: ")
  for ip, count in ip_counts.most_common():
    flag = " <-- repeated failure pattern" if count >= args.threshold]
    print(f" {ip}: {count}{flag}")
  
  repeat_offenders = [ip for ip, c in ip_counts.items() if c >= args.threshold]
  print(f"\n{len(repeat_offenders)} IP(s) crossed the threshold of {args.threshold} failures.")

if __name__ == "__main__":
  main()
