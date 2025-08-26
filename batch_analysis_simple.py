#!/usr/bin/env python3
"""
Email Security Classification Analysis - Simple Version
Senior Email Security Analyst Tool without external dependencies
"""

import csv
import sys

def analyze_email_record(record, headers):
    """
    Analyze a single email record using expert security analyst rules
    Returns corrected classification: Malicious, Spam, Warning, or No Action
    """
    
    # Get signal values safely
    def get_signal(signal_name, default=0):
        try:
            idx = headers.index(signal_name)
            value = record[idx]
            if value == '' or value is None:
                return default
            return float(value)
        except (ValueError, IndexError):
            return default
    
    def get_bool_signal(signal_name):
        try:
            idx = headers.index(signal_name)
            value = record[idx]
            return value == '1' or value == 1
        except (ValueError, IndexError):
            return False
    
    def get_string_signal(signal_name):
        try:
            idx = headers.index(signal_name)
            return record[idx] if record[idx] else ""
        except (ValueError, IndexError):
            return ""
    
    # Critical malicious indicators - immediate classification
    critical_malicious = [
        'sender_known_malicios',  # Note: typo in original data
        'any_file_hash_malicious',
        'domain_known_malicious', 
        'final_url_known_malicious',
        'return_path_known_malicious',
        'smtp_ip_known_malicious'
    ]
    
    for signal in critical_malicious:
        if get_bool_signal(signal):
            return "Malicious"
    
    # Calculate risk scores
    malicious_score = 0.0
    spam_score = 0.0 
    warning_score = 0.0
    
    # === MALICIOUS ANALYSIS ===
    
    # High-risk behavioral indicators
    if get_bool_signal('packer_detected'):
        malicious_score += 0.3
    if get_bool_signal('any_exploit_pattern_detected'):
        malicious_score += 0.4
    if get_bool_signal('has_executable_attachment'):
        malicious_score += 0.3
    if get_bool_signal('any_macro_enabled_document'):
        malicious_score += 0.2
    if get_bool_signal('any_network_call_on_open'):
        malicious_score += 0.3
    if get_bool_signal('sender_spoof_detected'):
        malicious_score += 0.3
    
    # Behavioral sandbox scores
    sandbox_score = get_signal('max_behavioral_sandbox_score')
    if sandbox_score > 0.5:
        malicious_score += 0.4
    elif sandbox_score > 0.1:
        malicious_score += 0.2
    
    amsi_score = get_signal('max_amsi_suspicion_score')
    if amsi_score > 0.1:
        malicious_score += 0.2
    
    # Count-based indicators
    yara_matches = get_signal('total_yara_match_count')
    if yara_matches > 5:
        malicious_score += 0.3
    elif yara_matches > 0:
        malicious_score += 0.1
    
    ioc_count = get_signal('total_ioc_count')
    if ioc_count > 3:
        malicious_score += 0.3
    elif ioc_count > 0:
        malicious_score += 0.1
    
    malicious_attachments = get_signal('malicious_attachment_Count')
    if malicious_attachments > 0:
        malicious_score += 0.4
    
    # === SPAM ANALYSIS ===
    
    content_spam = get_signal('content_spam_score')
    spam_score += min(content_spam * 0.5, 0.5)
    
    if get_bool_signal('bulk_message_indicator'):
        spam_score += 0.2
    if get_bool_signal('user_marked_as_spam_before'):
        spam_score += 0.3
    if get_signal('marketing_keywords_detected') > 0.5:
        spam_score += 0.2
    if get_bool_signal('unsubscribe_link_present'):
        spam_score += 0.1
    
    # === WARNING ANALYSIS ===
    
    # Sender reputation issues
    sender_reputation = get_signal('sender_domain_reputation_score')
    if sender_reputation < 0.3:
        warning_score += 0.2
    
    temp_email_likelihood = get_signal('sender_temp_email_likelihood')
    if temp_email_likelihood > 0.7:
        warning_score += 0.3
    elif temp_email_likelihood > 0.3:
        warning_score += 0.1
    
    if get_bool_signal('urgency_keywords_present'):
        warning_score += 0.2
    if get_bool_signal('is_high_risk_role_targeted'):
        warning_score += 0.3
    
    vip_similarity = get_signal('sender_name_similarity_to_vip')
    if vip_similarity > 0.7:
        warning_score += 0.3
    elif vip_similarity > 0.3:
        warning_score += 0.1
    
    # Request type analysis
    request_type = get_string_signal('request_type')
    high_risk_requests = ['wire_transfer', 'credential_request', 'executive_request', 'sensitive_data_request']
    medium_risk_requests = ['invoice_payment', 'invoice_verification', 'bank_detail_update']
    
    if request_type in high_risk_requests:
        warning_score += 0.4
    elif request_type in medium_risk_requests:
        warning_score += 0.2
    elif request_type != 'none' and request_type != '':
        warning_score += 0.1
    
    # Authentication analysis
    spf_result = get_string_signal('spf_result')
    dkim_result = get_string_signal('dkim_result') 
    dmarc_result = get_string_signal('dmarc_result')
    
    auth_failures = 0
    if spf_result in ['fail', 'softfail']:
        auth_failures += 1
    if dkim_result == 'fail':
        auth_failures += 1
    if dmarc_result == 'fail':
        auth_failures += 1
    
    if auth_failures >= 2:
        malicious_score += 0.2
        warning_score += 0.1
    elif auth_failures == 1:
        warning_score += 0.1
    
    # URL analysis
    if get_bool_signal('url_shortener_detected'):
        warning_score += 0.1
    if get_bool_signal('url_decoded_spoof_detected'):
        malicious_score += 0.3
    
    url_reputation = get_signal('url_reputation_score')
    if url_reputation < 0.2:
        malicious_score += 0.3
    elif url_reputation < 0.5:
        warning_score += 0.2
    
    # === CLASSIFICATION DECISION ===
    
    # Apply expert decision logic
    if malicious_score >= 0.6:
        return "Malicious"
    elif spam_score >= 0.6:
        return "Spam"
    elif warning_score >= 0.4 or malicious_score >= 0.3:
        return "Warning"
    else:
        return "No Action"

def process_batch(filename, start_row, end_row):
    """Process a batch of records from the CSV file"""
    results = []
    
    with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        headers = next(reader)  # Read header row
        
        # Find classification column index
        try:
            class_idx = headers.index('Classification')
        except ValueError:
            print("Error: 'Classification' column not found")
            return results
        
        # Skip to start row
        for i in range(start_row):
            try:
                next(reader)
            except StopIteration:
                break
        
        # Process batch
        current_row = start_row
        for record in reader:
            if current_row >= end_row:
                break
            
            try:
                original_classification = record[class_idx]
                
                # Handle numeric classifications
                if original_classification.isdigit():
                    digit_map = {'0': 'No Action', '1': 'Warning', '2': 'Spam', 
                               '3': 'Malicious', '4': 'Warning', '5': 'Malicious'}
                    original_classification = digit_map.get(original_classification, 'No Action')
                
                # Get new classification
                new_classification = analyze_email_record(record, headers)
                
                # Get data ID
                data_id = record[1] if len(record) > 1 else f"Row_{current_row+1}"
                
                results.append({
                    'row': current_row + 1,
                    'data_id': data_id,
                    'original': original_classification,
                    'new': new_classification,
                    'changed': original_classification != new_classification
                })
                
            except Exception as e:
                results.append({
                    'row': current_row + 1,
                    'data_id': f"Row_{current_row+1}",
                    'original': 'Error',
                    'new': 'Error',
                    'changed': False,
                    'error': str(e)
                })
            
            current_row += 1
    
    return results

def main():
    filename = '/home/u3/email_data/1-6332/1-6332final.csv'
    
    print("=== EMAIL SECURITY CLASSIFICATION ANALYSIS ===")
    print("Senior Security Analyst - Task 1: Records 1-100")
    print("-" * 50)
    
    # Process first batch (rows 1-100, accounting for header)
    batch_results = process_batch(filename, 0, 100)
    
    # Analysis summary
    total_analyzed = len([r for r in batch_results if 'error' not in r])
    total_changed = sum(1 for r in batch_results if r.get('changed', False))
    errors = len([r for r in batch_results if 'error' in r])
    
    print(f"Records analyzed: {total_analyzed}")
    print(f"Classifications changed: {total_changed}")
    print(f"Errors encountered: {errors}")
    print()
    
    # Show classification changes
    classification_changes = {}
    for result in batch_results:
        if result.get('changed', False):
            change = f"{result['original']} → {result['new']}"
            classification_changes[change] = classification_changes.get(change, 0) + 1
    
    if classification_changes:
        print("Classification Changes Summary:")
        for change, count in sorted(classification_changes.items()):
            print(f"  {change}: {count} records")
        print()
    
    # Show sample detailed results
    print("Sample Results (First 20 records):")
    print("Row | Data ID | Original → New | Status")
    print("-" * 45)
    
    for i, result in enumerate(batch_results[:20]):
        if 'error' in result:
            status = f"ERROR: {result['error']}"
        else:
            status = "CHANGED" if result['changed'] else "OK"
        
        print(f"{result['row']:3d} | {result['data_id']:7s} | {result['original']:8s} → {result['new']:8s} | {status}")
    
    print()
    print("Task 1 completed successfully!")
    print("=" * 50)
    
    return batch_results

if __name__ == "__main__":
    main()