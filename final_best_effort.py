import csv
import json

def final_classification(row):
    """Best effort classification based on all analyses"""
    
    def safe_float(val):
        try:
            return float(val) if val else 0.0
        except:
            return 0.0
    
    def safe_int(val):
        try:
            return int(float(val)) if val else 0
        except:
            return 0
    
    # Key insight from analysis: total_components_detected_malicious seems to be 
    # the primary driver, but not in the expected way
    
    components = safe_float(row.get('total_components_detected_malicious', 0))
    behavioral = safe_float(row.get('max_behavioral_sandbox_score', 0))
    spam_score = safe_float(row.get('content_spam_score', 0))
    exfiltration = safe_float(row.get('max_exfiltration_behavior_score', 0))
    
    # Check for any confirmed malicious indicators
    has_known_mal = (
        safe_int(row.get('sender_known_malicios', 0)) > 0 or
        safe_int(row.get('any_file_hash_malicious', 0)) > 0 or
        safe_int(row.get('malicious_attachment_Count', 0)) > 0 or
        safe_int(row.get('domain_known_malicious', 0)) > 0 or
        safe_int(row.get('smtp_ip_known_malicious', 0)) > 0 or
        safe_int(row.get('return_path_known_malicious', 0)) > 0 or
        safe_int(row.get('reply_path_known_malicious', 0)) > 0 or
        safe_int(row.get('final_url_known_malicious', 0)) > 0
    )
    
    # New insight: The original classifier seems to use complex combinations
    # Let's try to match the observed patterns more closely
    
    # Pattern 1: High components doesn't always mean Malicious
    # No Action had avg 0.601 components, Malicious had 0.515
    
    # Pattern 2: Spam has high spam_score (avg 0.230) but also components (0.515)
    if spam_score > 0.4:
        if has_known_mal and behavioral > 0.1:
            return 'Malicious'
        elif components > 2:
            return 'Malicious'
        else:
            return 'Spam'
    
    # Pattern 3: Known malicious doesn't guarantee Malicious classification
    if has_known_mal:
        if behavioral > 0.3 or exfiltration > 0.7:
            return 'Malicious'
        elif components > 1.5 and behavioral > 0.05:
            return 'Malicious'
        elif spam_score > 0.2:
            return 'Spam'
        else:
            return 'Warning'
    
    # Pattern 4: High behavioral score
    if behavioral > 0.5:
        if components > 0 or has_known_mal:
            return 'Malicious'
        else:
            return 'Warning'
    elif behavioral > 0.2:
        if components > 1:
            return 'Malicious'
        else:
            return 'Warning'
    elif behavioral > 0.05:
        if components > 2:
            return 'Malicious'
        else:
            return 'Warning'
    
    # Pattern 5: Components-based logic (counterintuitive)
    if components > 2:
        if behavioral > 0.01 or exfiltration > 0.5:
            return 'Malicious'
        elif spam_score > 0.1:
            return 'Spam'
        else:
            return 'No Action'  # Surprisingly common pattern
    elif components > 1:
        if behavioral > 0.02:
            return 'Malicious'
        elif spam_score > 0.15:
            return 'Spam'
        else:
            return 'Warning'
    elif components > 0:
        if behavioral > 0.05 or exfiltration > 0.6:
            return 'Malicious'
        elif spam_score > 0.2:
            return 'Spam'
        else:
            return 'Warning'
    
    # Pattern 6: No components but other risks
    if exfiltration > 0.8:
        return 'Malicious'
    elif exfiltration > 0.5:
        return 'Warning'
    
    # Pattern 7: Spam detection
    if spam_score > 0.2:
        return 'Spam'
    elif spam_score > 0.1:
        if behavioral > 0.01:
            return 'Warning'
        else:
            return 'Spam'
    
    # Pattern 8: Minor risks
    if behavioral > 0.01 or exfiltration > 0.1:
        return 'Warning'
    
    if spam_score > 0.05:
        return 'Spam'
    
    # Default: No Action
    return 'No Action'

def main():
    with open('1-6332final.csv', 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        headers = reader.fieldnames
    
    if 'New_Classification' not in headers:
        headers.append('New_Classification')
    
    # Process
    correct = 0
    for row in rows:
        original = row['Classification']
        predicted = final_classification(row)
        row['New_Classification'] = predicted
        if original == predicted:
            correct += 1
    
    # Write
    with open('1-6332final_analyzed.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    
    # Results
    accuracy = correct / len(rows) * 100
    print(f"Final Best Effort Classification")
    print(f"Accuracy: {accuracy:.1f}% ({correct}/{len(rows)})")
    
    # Show distribution
    from collections import Counter
    original = Counter(row['Classification'] for row in rows)
    new = Counter(row['New_Classification'] for row in rows)
    
    print("\nDistribution Comparison:")
    for cls in ['Malicious', 'Warning', 'Spam', 'No Action']:
        print(f"{cls}: {original[cls]} -> {new[cls]}")

if __name__ == "__main__":
    main()