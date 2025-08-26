import csv
from collections import Counter
import json

def train_simple_model():
    """Train a simple decision tree-like model from the data"""
    
    with open('1-6332final.csv', 'r') as f:
        reader = csv.DictReader(f)
        data = list(reader)
    
    def safe_float(val):
        try:
            return float(val) if val else 0.0
        except:
            return 0.0
    
    # Learn patterns for each classification
    patterns = {
        'Malicious': [],
        'Warning': [],
        'Spam': [],
        'No Action': []
    }
    
    # Critical features that seem to matter most
    critical_features = [
        'total_components_detected_malicious',
        'max_behavioral_sandbox_score',
        'content_spam_score',
        'sender_domain_reputation_score',
        'max_exfiltration_behavior_score',
        'malicious_attachment_Count',
        'any_file_hash_malicious',
        'sender_known_malicios',
        'any_exploit_pattern_detected',
        'user_marked_as_spam_before'
    ]
    
    # Collect patterns
    for row in data:
        cls = row['Classification']
        pattern = {
            'components_mal': safe_float(row.get('total_components_detected_malicious', 0)),
            'behavioral': safe_float(row.get('max_behavioral_sandbox_score', 0)),
            'spam_score': safe_float(row.get('content_spam_score', 0)),
            'reputation': safe_float(row.get('sender_domain_reputation_score', 0)),
            'exfiltration': safe_float(row.get('max_exfiltration_behavior_score', 0)),
            'has_mal_indicator': (
                safe_float(row.get('sender_known_malicios', 0)) > 0 or
                safe_float(row.get('any_file_hash_malicious', 0)) > 0 or
                safe_float(row.get('malicious_attachment_Count', 0)) > 0 or
                safe_float(row.get('domain_known_malicious', 0)) > 0 or
                safe_float(row.get('final_url_known_malicious', 0)) > 0
            )
        }
        patterns[cls].append(pattern)
    
    # Find decision boundaries
    print("Learning Decision Boundaries...")
    print("="*50)
    
    # Analyze what makes each class unique
    for cls in ['Malicious', 'Warning', 'Spam', 'No Action']:
        print(f"\n{cls} patterns ({len(patterns[cls])} samples):")
        
        # Calculate averages
        if patterns[cls]:
            avg_components = sum(p['components_mal'] for p in patterns[cls]) / len(patterns[cls])
            avg_behavioral = sum(p['behavioral'] for p in patterns[cls]) / len(patterns[cls])
            avg_spam = sum(p['spam_score'] for p in patterns[cls]) / len(patterns[cls])
            pct_mal_indicator = sum(1 for p in patterns[cls] if p['has_mal_indicator']) / len(patterns[cls]) * 100
            
            print(f"  Avg components_mal: {avg_components:.3f}")
            print(f"  Avg behavioral: {avg_behavioral:.3f}")
            print(f"  Avg spam_score: {avg_spam:.3f}")
            print(f"  % with mal indicator: {pct_mal_indicator:.1f}%")
    
    return patterns

def classify_with_learned_patterns(row, patterns):
    """Classify using learned patterns"""
    
    def safe_float(val):
        try:
            return float(val) if val else 0.0
        except:
            return 0.0
    
    # Extract features
    components_mal = safe_float(row.get('total_components_detected_malicious', 0))
    behavioral = safe_float(row.get('max_behavioral_sandbox_score', 0))
    spam_score = safe_float(row.get('content_spam_score', 0))
    exfiltration = safe_float(row.get('max_exfiltration_behavior_score', 0))
    
    has_mal_indicator = (
        safe_float(row.get('sender_known_malicios', 0)) > 0 or
        safe_float(row.get('any_file_hash_malicious', 0)) > 0 or
        safe_float(row.get('malicious_attachment_Count', 0)) > 0 or
        safe_float(row.get('domain_known_malicious', 0)) > 0 or
        safe_float(row.get('final_url_known_malicious', 0)) > 0
    )
    
    # Decision tree based on observed patterns
    
    # High malicious components is strongest indicator for Malicious
    if components_mal > 1.5:
        if behavioral > 0.05 or has_mal_indicator:
            return 'Malicious'
        else:
            return 'Warning'
    
    # High spam score with low other risks = Spam
    if spam_score > 0.4:
        if components_mal < 0.5 and behavioral < 0.05:
            return 'Spam'
    
    # Malicious indicators present
    if has_mal_indicator:
        if behavioral > 0.1 or exfiltration > 0.5:
            return 'Malicious'
        elif components_mal > 0:
            return 'Malicious'
        else:
            return 'Warning'
    
    # Behavioral indicators
    if behavioral > 0.2:
        if components_mal > 0:
            return 'Malicious'
        else:
            return 'Warning'
    
    # High exfiltration
    if exfiltration > 0.7:
        return 'Malicious'
    elif exfiltration > 0.4:
        return 'Warning'
    
    # Components detected but not high
    if 0 < components_mal <= 1.5:
        if behavioral > 0.01 or exfiltration > 0.1:
            return 'Malicious'
        elif spam_score > 0.1:
            return 'Spam'
        else:
            return 'Warning'
    
    # Moderate spam score
    if spam_score > 0.15:
        return 'Spam'
    
    # Low behavioral risk
    if behavioral > 0.01:
        return 'Warning'
    
    # Very low risks
    if spam_score > 0.05:
        return 'Spam'
    
    # Default
    return 'No Action'

def main():
    # Learn patterns
    patterns = train_simple_model()
    
    # Read and classify
    with open('1-6332final.csv', 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        headers = reader.fieldnames
    
    if 'New_Classification' not in headers:
        headers.append('New_Classification')
    
    # Classify each row
    correct = 0
    results = {'Malicious': 0, 'Warning': 0, 'Spam': 0, 'No Action': 0}
    confusion_matrix = {
        'Malicious': {'Malicious': 0, 'Warning': 0, 'Spam': 0, 'No Action': 0},
        'Warning': {'Malicious': 0, 'Warning': 0, 'Spam': 0, 'No Action': 0},
        'Spam': {'Malicious': 0, 'Warning': 0, 'Spam': 0, 'No Action': 0},
        'No Action': {'Malicious': 0, 'Warning': 0, 'Spam': 0, 'No Action': 0}
    }
    
    for row in rows:
        original = row['Classification']
        predicted = classify_with_learned_patterns(row, patterns)
        row['New_Classification'] = predicted
        
        results[predicted] = results.get(predicted, 0) + 1
        confusion_matrix[original][predicted] += 1
        
        if original == predicted:
            correct += 1
    
    # Write results
    with open('1-6332final_analyzed.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    
    # Report
    accuracy = correct / len(rows) * 100
    print(f"\n\nMachine Learning Approach Results")
    print("="*50)
    print(f"Overall Accuracy: {accuracy:.1f}% ({correct}/{len(rows)})")
    
    print("\nConfusion Matrix:")
    print("Actual\\Predicted", end='')
    for cls in ['Malicious', 'Warning', 'Spam', 'No Action']:
        print(f"\t{cls[:3]}", end='')
    print()
    
    for actual in ['Malicious', 'Warning', 'Spam', 'No Action']:
        print(f"{actual}", end='')
        for predicted in ['Malicious', 'Warning', 'Spam', 'No Action']:
            print(f"\t{confusion_matrix[actual][predicted]}", end='')
        print()
    
    print("\nPer-Class Accuracy:")
    for cls in ['Malicious', 'Warning', 'Spam', 'No Action']:
        total = sum(confusion_matrix[cls].values())
        if total > 0:
            acc = confusion_matrix[cls][cls] / total * 100
            print(f"  {cls}: {acc:.1f}% ({confusion_matrix[cls][cls]}/{total})")

if __name__ == "__main__":
    main()