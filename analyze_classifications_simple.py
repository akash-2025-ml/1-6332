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
    
    # Initialize risk scores
    malicious_score = 0
    spam_score = 0
    warning_score = 0
    
    # Critical malicious indicators
    if safe_int(row['sender_known_malicios']) == 1:
        malicious_score += 10
    if safe_int(row['any_file_hash_malicious']) == 1:
        malicious_score += 10
    if safe_int(row['malicious_attachment_Count']) > 0:
        malicious_score += 10
    if safe_int(row['total_components_detected_malicious']) > 0:
        malicious_score += 8
    if safe_int(row['final_url_known_malicious']) == 1:
        malicious_score += 8
    if safe_int(row['domain_known_malicious']) == 1:
        malicious_score += 8
    if safe_int(row['smtp_ip_known_malicious']) == 1:
        malicious_score += 6
    if safe_int(row['return_path_known_malicious']) == 1:
        malicious_score += 6
    if safe_int(row['reply_path_known_malicious']) == 1:
        malicious_score += 6
    
    # High-risk behavioral indicators
    behavioral_score = safe_float(row['max_behavioral_sandbox_score'])
    if behavioral_score > 0.7:
        malicious_score += 8
    elif behavioral_score > 0.4:
        warning_score += 5
    
    exfiltration_score = safe_float(row['max_exfiltration_behavior_score'])
    if exfiltration_score > 0.8:
        malicious_score += 7
    elif exfiltration_score > 0.5:
        warning_score += 4
    
    if safe_int(row['packer_detected']) == 1:
        malicious_score += 5
    if safe_int(row['has_executable_attachment']) == 1:
        malicious_score += 4
    if safe_int(row['any_exploit_pattern_detected']) == 1:
        malicious_score += 6
    if safe_int(row['any_network_call_on_open']) == 1:
        malicious_score += 5
    if safe_int(row['any_active_x_objects_detected']) == 1:
        malicious_score += 4
    
    # Macro and script indicators
    if safe_int(row['any_macro_enabled_document']) == 1:
        warning_score += 4
    if safe_int(row['any_vbscript_javascript_detected']) == 1:
        warning_score += 4
    
    # Spoofing and reputation indicators
    if safe_int(row['sender_spoof_detected']) == 1:
        warning_score += 5
    
    sender_rep = safe_float(row['sender_domain_reputation_score'])
    if sender_rep < 0.2:
        warning_score += 4
    elif sender_rep < 0.5:
        warning_score += 2
    
    # URL and domain indicators
    if safe_int(row['url_decoded_spoof_detected']) == 1:
        warning_score += 5
    if safe_int(row['dna_morphing_detected']) == 1:
        warning_score += 4
    
    url_rep = safe_float(row['url_reputation_score'])
    if url_rep < 0.2:
        warning_score += 3
    
    visual_sim = safe_float(row['site_visual_similarity_to_known_brand'])
    if visual_sim > 0.7:
        warning_score += 5
    
    # Email authentication
    if row['spf_result'] == 'fail':
        warning_score += 3
    if row['dkim_result'] == 'fail':
        warning_score += 2
    if row['dmarc_result'] == 'fail':
        warning_score += 3
    
    # Spam indicators
    content_spam = safe_float(row['content_spam_score'])
    if content_spam > 0.7:
        spam_score += 8
    elif content_spam > 0.4:
        spam_score += 4
    
    if safe_int(row['user_marked_as_spam_before']) == 1:
        spam_score += 6
    if safe_int(row['bulk_message_indicator']) == 1:
        spam_score += 5
    
    marketing_score = safe_float(row['marketing-keywords_detected'])
    if marketing_score > 0.5:
        spam_score += 4
    
    # Temporary email likelihood
    temp_email = safe_float(row['sender_temp_email_likelihood'])
    if temp_email > 0.7:
        spam_score += 5
    elif temp_email > 0.4:
        spam_score += 3
    
    # Request type analysis
    high_risk_requests = ['wire_transfer', 'credential_request', 'bank_detail_update', 
                         'vpn_or_mfa_reset', 'legal_threat']
    medium_risk_requests = ['invoice_payment', 'gift_card_request', 'sensitive_data_request',
                           'document_download', 'link_click', 'urgent_callback', 
                           'invoice_verification', 'executive_request']
    
    request_type = row['request_type']
    if request_type in high_risk_requests:
        if safe_int(row['urgency_keywords_present']) == 1:
            malicious_score += 6
        else:
            warning_score += 5
    elif request_type in medium_risk_requests:
        warning_score += 3
    
    # SSL and security indicators
    ssl_status = row['ssl_validity_status']
    if ssl_status in ['expired', 'self signed', 'mismatch', 'revoked']:
        warning_score += 3
    elif ssl_status == 'no_ssl':
        warning_score += 4
    
    # Calculate final classification
    # Priority: Malicious > Warning > Spam > No Action
    if malicious_score >= 15:
        return 'Malicious'
    elif warning_score >= 12 or (warning_score >= 8 and malicious_score >= 5):
        return 'Warning'
    elif spam_score >= 10 or (spam_score >= 6 and content_spam > 0.5):
        return 'Spam'
    elif malicious_score >= 8 and warning_score >= 5:
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
print("Classification Analysis Complete")
print("="*50)
print(f"\nTotal records analyzed: {len(rows)}")
print(f"Classifications changed: {changes} ({changes/len(rows)*100:.2f}%)")

print("\nOriginal Classification Distribution:")
for class_name, count in classification_counts.items():
    print(f"  {class_name}: {count}")

print("\nNew Classification Distribution:")
for class_name, count in new_classification_counts.items():
    print(f"  {class_name}: {count}")

if changes > 0:
    print("\nChanges Summary:")
    for change, count in sorted(change_matrix.items()):
        print(f"  {change}: {count}")

print(f"\nUpdated dataset saved to '1-6332final_analyzed.csv'")