#!/usr/bin/env python3
"""Count classifications - handling numeric labels properly"""

import csv
from collections import Counter

# Map numeric labels to proper categories
digit_map = {
    '0': 'No Action',
    '1': 'Warning', 
    '2': 'Spam',
    '3': 'Malicious',
    '4': 'Warning',
    '5': 'Malicious'
}

def normalize_classification(cls):
    """Normalize classification label"""
    if cls.strip().isdigit():
        return digit_map.get(cls.strip(), 'No Action')
    return cls.strip()

# Count original classifications
print("=== ORIGINAL CLASSIFICATION COUNTS (Normalized) ===")
original_counts = Counter()

with open('/home/u3/email_data/1-6332/1-6332final.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        cls = normalize_classification(row['Classification'])
        original_counts[cls] += 1

total = sum(original_counts.values())
for cls, count in original_counts.most_common():
    pct = (count / total) * 100
    print(f"{cls:12s}: {count:5d} ({pct:5.1f}%)")

print(f"\nTotal: {total:,} records")

# Count new classifications
print("\n=== NEW CLASSIFICATION COUNTS ===")
new_counts = Counter()

with open('/home/u3/email_data/1-6332/1-6332final_analyzed.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        cls = row['New_Classification'].strip()
        new_counts[cls] += 1

total = sum(new_counts.values())
for cls, count in new_counts.most_common():
    pct = (count / total) * 100
    print(f"{cls:12s}: {count:5d} ({pct:5.1f}%)")

print(f"\nTotal: {total:,} records")

# Show differences
print("\n=== CLASSIFICATION CHANGES ===")
print(f"{'Category':12s} | {'Original':>8s} | {'New':>8s} | {'Change':>8s}")
print("-" * 45)

all_categories = set(original_counts.keys()) | set(new_counts.keys())
for cat in sorted(all_categories):
    orig = original_counts.get(cat, 0)
    new = new_counts.get(cat, 0)
    diff = new - orig
    sign = '+' if diff > 0 else ''
    print(f"{cat:12s} | {orig:8d} | {new:8d} | {sign}{diff:7d}")