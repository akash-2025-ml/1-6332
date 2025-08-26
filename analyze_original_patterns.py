import csv
from collections import defaultdict

def analyze_patterns():
    with open('1-6332final.csv', 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    # Analyze key indicators by classification
    patterns = {
        'Malicious': defaultdict(list),
        'Warning': defaultdict(list), 
        'Spam': defaultdict(list),
        'No Action': defaultdict(list)
    }
    
    def safe_float(val):
        try:
            return float(val) if val else 0.0
        except:
            return 0.0
    
    # Key signals to analyze
    key_signals = [
        'sender_known_malicios',
        'any_file_hash_malicious',
        'malicious_attachment_Count',
        'total_components_detected_malicious',
        'max_behavioral_sandbox_score',
        'content_spam_score',
        'sender_domain_reputation_score',
        'any_exploit_pattern_detected',
        'packer_detected',
        'has_executable_attachment',
        'sender_spoof_detected',
        'user_marked_as_spam_before',
        'bulk_message_indicator',
        'marketing-keywords_detected',
        'urgency_keywords_present',
        'spf_result',
        'dmarc_result'
    ]
    
    # Collect values for each signal by classification
    for row in rows:
        cls = row['Classification']
        if cls in patterns:
            for signal in key_signals:
                if signal in row:
                    patterns[cls][signal].append(safe_float(row[signal]))
    
    # Print analysis
    print("Signal Pattern Analysis by Original Classification")
    print("="*60)
    
    for cls in ['Malicious', 'Warning', 'Spam', 'No Action']:
        print(f"\n{cls} Class ({len([r for r in rows if r['Classification'] == cls])} records):")
        print("-"*40)
        
        for signal in key_signals:
            if signal in patterns[cls] and patterns[cls][signal]:
                values = patterns[cls][signal]
                avg = sum(values) / len(values)
                max_val = max(values)
                min_val = min(values)
                
                # For binary signals, show percentage of 1s
                if signal in ['sender_known_malicios', 'any_file_hash_malicious', 
                             'any_exploit_pattern_detected', 'packer_detected',
                             'has_executable_attachment', 'sender_spoof_detected',
                             'user_marked_as_spam_before', 'bulk_message_indicator',
                             'urgency_keywords_present']:
                    pct_true = sum(1 for v in values if v == 1) / len(values) * 100
                    print(f"  {signal}: {pct_true:.1f}% true")
                else:
                    print(f"  {signal}: avg={avg:.3f}, range=[{min_val:.3f}, {max_val:.3f}]")
    
    # Check for clear differentiators
    print("\n\nKey Differentiators:")
    print("-"*40)
    
    # Check malicious indicators in each class
    mal_indicators = ['sender_known_malicios', 'any_file_hash_malicious', 
                     'malicious_attachment_Count', 'total_components_detected_malicious']
    
    for cls in ['Malicious', 'Warning', 'Spam', 'No Action']:
        mal_count = 0
        for row in rows:
            if row['Classification'] == cls:
                for ind in mal_indicators:
                    if safe_float(row.get(ind, 0)) > 0:
                        mal_count += 1
                        break
        total = len([r for r in rows if r['Classification'] == cls])
        if total > 0:
            print(f"{cls}: {mal_count}/{total} ({mal_count/total*100:.1f}%) have malicious indicators")

if __name__ == "__main__":
    analyze_patterns()