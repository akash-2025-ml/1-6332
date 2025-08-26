import csv

# Function to analyze signals and determine correct classification
def analyze_email_signals(row):
    # Convert string values to appropriate types
    def safe_float(value, default=0.0):
        try:
            return float(value)
        except:
            return default
    
    def safe_int(value, default=0):
        try:
            return int(value)
        except:
            return default
    
    # Direct malicious indicators - ANY of these = Malicious
    if safe_int(row['sender_known_malicios']) == 1:
        return 'Malicious'
    if safe_int(row['any_file_hash_malicious']) == 1:
        return 'Malicious'
    if safe_int(row['malicious_attachment_Count']) > 0:
        return 'Malicious'
    if safe_int(row['total_components_detected_malicious']) > 0:
        return 'Malicious'
    if safe_int(row['final_url_known_malicious']) == 1:
        return 'Malicious'
    if safe_int(row['domain_known_malicious']) == 1:
        return 'Malicious'
    if safe_int(row['return_path_known_malicious']) == 1:
        return 'Malicious'
    if safe_int(row['reply_path_known_malicious']) == 1:
        return 'Malicious'
    if safe_int(row['smtp_ip_known_malicious']) == 1:
        return 'Malicious'
    
    # High behavioral scores indicating malicious activity
    if safe_float(row['max_behavioral_sandbox_score']) > 0.8:
        return 'Malicious'
    if safe_float(row['max_exfiltration_behavior_score']) > 0.9:
        return 'Malicious'
    
    # Active exploitation
    if safe_int(row['any_exploit_pattern_detected']) == 1 and safe_int(row['packer_detected']) == 1:
        return 'Malicious'
    
    # Multiple high-risk indicators combined
    risk_count = 0
    if safe_int(row['packer_detected']) == 1:
        risk_count += 1
    if safe_int(row['has_executable_attachment']) == 1:
        risk_count += 1
    if safe_int(row['any_network_call_on_open']) == 1:
        risk_count += 1
    if safe_int(row['any_exploit_pattern_detected']) == 1:
        risk_count += 1
    if safe_float(row['max_behavioral_sandbox_score']) > 0.5:
        risk_count += 1
    if safe_float(row['max_exfiltration_behavior_score']) > 0.7:
        risk_count += 1
    
    if risk_count >= 3:
        return 'Malicious'
    
    # Check for Spam indicators
    spam_score = 0
    
    # Strong spam indicators
    if safe_float(row['content_spam_score']) > 0.8:
        spam_score += 3
    elif safe_float(row['content_spam_score']) > 0.5:
        spam_score += 2
    
    if safe_int(row['user_marked_as_spam_before']) == 1:
        spam_score += 3
    if safe_int(row['bulk_message_indicator']) == 1:
        spam_score += 2
    if safe_float(row['marketing-keywords_detected']) > 0.7:
        spam_score += 2
    elif safe_float(row['marketing-keywords_detected']) > 0.4:
        spam_score += 1
    
    if safe_float(row['sender_temp_email_likelihood']) > 0.8:
        spam_score += 2
    elif safe_float(row['sender_temp_email_likelihood']) > 0.5:
        spam_score += 1
    
    # If strong spam indicators and no security risks
    if spam_score >= 5 and risk_count == 0:
        return 'Spam'
    
    # Check for Warning indicators
    warning_score = 0
    
    # Spoofing and deception
    if safe_int(row['sender_spoof_detected']) == 1:
        warning_score += 2
    if safe_int(row['url_decoded_spoof_detected']) == 1:
        warning_score += 2
    if safe_int(row['dna_morphing_detected']) == 1:
        warning_score += 2
    if safe_float(row['site_visual_similarity_to_known_brand']) > 0.8:
        warning_score += 2
    
    # Authentication failures
    if row['spf_result'] == 'fail':
        warning_score += 1
    if row['dkim_result'] == 'fail':
        warning_score += 1
    if row['dmarc_result'] == 'fail':
        warning_score += 1
    
    # Reputation issues
    if safe_float(row['sender_domain_reputation_score']) < 0.3:
        warning_score += 2
    elif safe_float(row['sender_domain_reputation_score']) < 0.5:
        warning_score += 1
    
    if safe_float(row['url_reputation_score']) < 0.2:
        warning_score += 2
    elif safe_float(row['url_reputation_score']) < 0.4:
        warning_score += 1
    
    # SSL issues
    if row['ssl_validity_status'] in ['expired', 'self signed', 'mismatch', 'revoked', 'no_ssl']:
        warning_score += 1
    
    # Risky content
    if safe_int(row['any_macro_enabled_document']) == 1:
        warning_score += 1
    if safe_int(row['any_vbscript_javascript_detected']) == 1:
        warning_score += 1
    if safe_int(row['any_active_x_objects_detected']) == 1:
        warning_score += 1
    
    # High-risk requests
    high_risk_requests = ['wire_transfer', 'credential_request', 'bank_detail_update', 
                         'vpn_or_mfa_reset', 'legal_threat', 'executive_request']
    medium_risk_requests = ['invoice_payment', 'gift_card_request', 'sensitive_data_request',
                           'document_download', 'link_click', 'urgent_callback', 
                           'invoice_verification']
    
    if row['request_type'] in high_risk_requests:
        if safe_int(row['urgency_keywords_present']) == 1:
            warning_score += 3
        else:
            warning_score += 2
    elif row['request_type'] in medium_risk_requests:
        warning_score += 1
    
    # Behavioral indicators
    if safe_float(row['max_behavioral_sandbox_score']) > 0.3:
        warning_score += 1
    if safe_float(row['max_exfiltration_behavior_score']) > 0.5:
        warning_score += 1
    
    # Return path mismatches
    if safe_int(row['return_path_mismatch_with_from']) == 1:
        warning_score += 1
    if safe_int(row['reply_path_diff_from_sender']) == 1:
        warning_score += 1
    
    # Decision logic
    if warning_score >= 4 or (warning_score >= 2 and risk_count >= 1):
        return 'Warning'
    elif spam_score >= 3:
        return 'Spam'
    elif warning_score >= 2:
        return 'Warning'
    else:
        return 'No Action'

# Read the CSV file
with open('1-6332final.csv', 'r') as infile:
    reader = csv.DictReader(infile)
    rows = list(reader)
    headers = reader.fieldnames

# Add New_Classification column
headers.append('New_Classification')

# Process each row
changes = 0
classification_counts = {'Malicious': 0, 'Spam': 0, 'Warning': 0, 'No Action': 0}
new_classification_counts = {'Malicious': 0, 'Spam': 0, 'Warning': 0, 'No Action': 0}
change_matrix = {}

for row in rows:
    original = row['Classification']
    new_class = analyze_email_signals(row)
    row['New_Classification'] = new_class
    
    # Count classifications
    if original in classification_counts:
        classification_counts[original] += 1
    if new_class in new_classification_counts:
        new_classification_counts[new_class] += 1
    
    # Track changes
    if original != new_class:
        changes += 1
        change_key = f"{original} -> {new_class}"
        change_matrix[change_key] = change_matrix.get(change_key, 0) + 1

# Write the updated CSV
with open('1-6332final_analyzed.csv', 'w', newline='') as outfile:
    writer = csv.DictWriter(outfile, fieldnames=headers)
    writer.writeheader()
    writer.writerows(rows)

# Print analysis report
print("Classification Analysis Complete (Refined Version)")
print("="*50)
print(f"\nTotal records analyzed: {len(rows)}")
print(f"Classifications changed: {changes} ({changes/len(rows)*100:.2f}%)")

print("\nOriginal Classification Distribution:")
for class_name, count in sorted(classification_counts.items()):
    print(f"  {class_name}: {count}")

print("\nNew Classification Distribution:")
for class_name, count in sorted(new_classification_counts.items()):
    print(f"  {class_name}: {count}")

if changes > 0:
    print("\nChanges Summary:")
    for change, count in sorted(change_matrix.items()):
        print(f"  {change}: {count}")

# Sample some specific cases to verify logic
print("\n\nSample Analysis of First 5 Changes:")
sample_count = 0
for i, row in enumerate(rows):
    if row['Classification'] != row['New_Classification'] and sample_count < 5:
        print(f"\nRecord {i+1} (Data: {row['Data ']})")
        print(f"  Original: {row['Classification']} -> New: {row['New_Classification']}")
        print(f"  Key indicators:")
        if int(float(row['sender_known_malicios']) if row['sender_known_malicios'] else 0) == 1:
            print(f"    - sender_known_malicious: 1")
        if int(float(row['any_file_hash_malicious']) if row['any_file_hash_malicious'] else 0) == 1:
            print(f"    - any_file_hash_malicious: 1")
        if float(row['max_behavioral_sandbox_score'] if row['max_behavioral_sandbox_score'] else 0) > 0.5:
            print(f"    - max_behavioral_sandbox_score: {row['max_behavioral_sandbox_score']}")
        if float(row['content_spam_score'] if row['content_spam_score'] else 0) > 0.5:
            print(f"    - content_spam_score: {row['content_spam_score']}")
        if row['request_type'] != 'none':
            print(f"    - request_type: {row['request_type']}")
        sample_count += 1

print(f"\nUpdated dataset saved to '1-6332final_analyzed.csv'")