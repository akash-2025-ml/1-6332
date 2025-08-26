#!/usr/bin/env python3
"""
Complete Email Security Classification Analysis
Process ALL 6332 records and generate final dataset with New_Classification column
Senior Email Security Analyst
"""

import csv
import sys
import time

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

def process_all_records(input_filename, output_filename):
    """Process all records and create new CSV with New_Classification column"""
    
    print("=== COMPLETE EMAIL SECURITY CLASSIFICATION ANALYSIS ===")
    print("Processing ALL 6332 records...")
    print("-" * 60)
    
    start_time = time.time()
    total_processed = 0
    total_changed = 0
    errors = 0
    
    classification_changes = {}
    
    with open(input_filename, 'r', newline='', encoding='utf-8') as infile:
        reader = csv.reader(infile)
        headers = next(reader)  # Read header row
        
        # Find classification column index
        try:
            class_idx = headers.index('Classification')
        except ValueError:
            print("Error: 'Classification' column not found")
            return
        
        # Add New_Classification to headers
        new_headers = headers + ['New_Classification']
        
        with open(output_filename, 'w', newline='', encoding='utf-8') as outfile:
            writer = csv.writer(outfile)
            writer.writerow(new_headers)
            
            # Process each record
            for row_num, record in enumerate(reader, 1):
                try:
                    original_classification = record[class_idx]
                    
                    # Handle numeric classifications
                    if original_classification.isdigit():
                        digit_map = {'0': 'No Action', '1': 'Warning', '2': 'Spam', 
                                   '3': 'Malicious', '4': 'Warning', '5': 'Malicious'}
                        original_classification = digit_map.get(original_classification, 'No Action')
                    
                    # Get new classification
                    new_classification = analyze_email_record(record, headers)
                    
                    # Track changes
                    if original_classification != new_classification:
                        total_changed += 1
                        change = f"{original_classification} → {new_classification}"
                        classification_changes[change] = classification_changes.get(change, 0) + 1
                    
                    # Write record with new classification
                    new_record = record + [new_classification]
                    writer.writerow(new_record)
                    
                    total_processed += 1
                    
                    # Progress update
                    if total_processed % 500 == 0:
                        elapsed = time.time() - start_time
                        print(f"Processed {total_processed:4d} records in {elapsed:.1f}s | Changes: {total_changed:4d}")
                
                except Exception as e:
                    errors += 1
                    # Write original record with error marker
                    new_record = record + ['Error']
                    writer.writerow(new_record)
                    print(f"Error processing record {row_num}: {str(e)}")
    
    # Final summary
    elapsed = time.time() - start_time
    print()
    print("=" * 60)
    print("COMPLETE ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Total records processed: {total_processed:,}")
    print(f"Classifications changed: {total_changed:,}")
    print(f"Errors encountered: {errors}")
    print(f"Processing time: {elapsed:.1f} seconds")
    print(f"Output file: {output_filename}")
    print()
    
    if classification_changes:
        print("CLASSIFICATION CHANGES BREAKDOWN:")
        print("-" * 40)
        for change, count in sorted(classification_changes.items(), key=lambda x: x[1], reverse=True):
            print(f"  {change:25s}: {count:4d} records")
        print()
    
    # Calculate final distribution
    print("Analyzing final classification distribution...")
    final_distribution = {}
    
    with open(output_filename, 'r', newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        headers = next(reader)
        new_class_idx = headers.index('New_Classification')
        
        for record in reader:
            classification = record[new_class_idx]
            final_distribution[classification] = final_distribution.get(classification, 0) + 1
    
    print("FINAL CLASSIFICATION DISTRIBUTION:")
    print("-" * 40)
    for classification, count in sorted(final_distribution.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_processed) * 100
        print(f"  {classification:12s}: {count:4d} records ({percentage:5.1f}%)")
    
    print()
    print("Analysis completed successfully!")
    print("=" * 60)

def main():
    input_file = '/home/u3/email_data/1-6332/1-6332final.csv'
    output_file = '/home/u3/email_data/1-6332/1-6332final_analyzed.csv'
    
    process_all_records(input_file, output_file)

if __name__ == "__main__":
    main()