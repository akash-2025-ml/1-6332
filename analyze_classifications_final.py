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
            return int(float(value))
        except:
            return default
    
    # === MALICIOUS CLASSIFICATION ===
    # Any confirmed malicious indicator = immediate Malicious classification
    
    # Known malicious senders/domains/IPs (binary indicators)
    if safe_int(row['sender_known_malicios']) == 1:
        return 'Malicious'
    if safe_int(row['domain_known_malicious']) == 1:
        return 'Malicious'
    if safe_int(row['smtp_ip_known_malicious']) == 1:
        return 'Malicious'
    if safe_int(row['return_path_known_malicious']) == 1:
        return 'Malicious'
    if safe_int(row['reply_path_known_malicious']) == 1:
        return 'Malicious'
    
    # Malicious attachments/files
    if safe_int(row['any_file_hash_malicious']) == 1:
        return 'Malicious'
    if safe_int(row['malicious_attachment_Count']) > 0:
        return 'Malicious'
    if safe_int(row['total_components_detected_malicious']) > 0:
        return 'Malicious'
    
    # Malicious URLs
    if safe_int(row['final_url_known_malicious']) == 1:
        return 'Malicious'
    
    # Very high behavioral scores (>0.8 indicates actual malicious behavior observed)
    if safe_float(row['max_behavioral_sandbox_score']) > 0.8:
        return 'Malicious'
    if safe_float(row['max_exfiltration_behavior_score']) > 0.9:
        return 'Malicious'
    
    # Active exploitation detected
    if safe_int(row['any_exploit_pattern_detected']) == 1:
        # Exploit pattern alone is strong enough for malicious
        return 'Malicious'
    
    # === SPAM CLASSIFICATION ===
    # Check spam indicators BEFORE warning (spam is less severe than warning)
    
    spam_indicators = 0
    
    # Content spam score is primary spam indicator
    content_spam = safe_float(row['content_spam_score'])
    if content_spam > 0.8:
        spam_indicators += 3
    elif content_spam > 0.6:
        spam_indicators += 2
    elif content_spam > 0.4:
        spam_indicators += 1
    
    # User feedback
    if safe_int(row['user_marked_as_spam_before']) == 1:
        spam_indicators += 2
    
    # Bulk message indicators
    if safe_int(row['bulk_message_indicator']) == 1:
        spam_indicators += 2
    
    # Marketing content
    marketing = safe_float(row['marketing-keywords_detected'])
    if marketing > 0.7:
        spam_indicators += 2
    elif marketing > 0.4:
        spam_indicators += 1
    
    # Temporary email likelihood
    temp_email = safe_float(row['sender_temp_email_likelihood'])
    if temp_email > 0.8:
        spam_indicators += 2
    elif temp_email > 0.5:
        spam_indicators += 1
    
    # Image-only emails often used for spam
    if safe_int(row['image_only_email']) == 1:
        spam_indicators += 1
    
    # Unsubscribe link (common in marketing/spam)
    if safe_int(row['unsubscribe_link_present']) == 1:
        spam_indicators += 1
    
    # === WARNING CLASSIFICATION ===
    # Security concerns that aren't confirmed malicious
    
    warning_indicators = 0
    
    # Spoofing attempts
    if safe_int(row['sender_spoof_detected']) == 1:
        warning_indicators += 3
    if safe_int(row['url_decoded_spoof_detected']) == 1:
        warning_indicators += 3
    if safe_int(row['dna_morphing_detected']) == 1:
        warning_indicators += 2
    
    # Visual similarity to known brands (phishing indicator)
    visual_sim = safe_float(row['site_visual_similarity_to_known_brand'])
    if visual_sim > 0.8:
        warning_indicators += 3
    elif visual_sim > 0.5:
        warning_indicators += 2
    
    # Suspicious behavioral scores (not high enough for malicious)
    behavioral = safe_float(row['max_behavioral_sandbox_score'])
    if 0.5 < behavioral <= 0.8:
        warning_indicators += 2
    elif 0.3 < behavioral <= 0.5:
        warning_indicators += 1
    
    exfiltration = safe_float(row['max_exfiltration_behavior_score'])
    if 0.7 < exfiltration <= 0.9:
        warning_indicators += 2
    elif 0.5 < exfiltration <= 0.7:
        warning_indicators += 1
    
    # Authentication failures
    auth_failures = 0
    if row['spf_result'] == 'fail':
        auth_failures += 1
    if row['dkim_result'] == 'fail':
        auth_failures += 1
    if row['dmarc_result'] == 'fail':
        auth_failures += 1
    if auth_failures >= 2:
        warning_indicators += 2
    elif auth_failures == 1:
        warning_indicators += 1
    
    # Poor reputation scores
    sender_rep = safe_float(row['sender_domain_reputation_score'])
    if sender_rep < 0.2:
        warning_indicators += 2
    elif sender_rep < 0.4:
        warning_indicators += 1
    
    url_rep = safe_float(row['url_reputation_score'])
    if url_rep > 0 and url_rep < 0.2:  # Only if URLs present
        warning_indicators += 2
    elif url_rep > 0 and url_rep < 0.4:
        warning_indicators += 1
    
    # SSL certificate issues
    ssl_status = row['ssl_validity_status']
    if ssl_status in ['expired', 'self signed', 'mismatch', 'revoked']:
        warning_indicators += 2
    elif ssl_status == 'no_ssl':
        warning_indicators += 1
    
    # Risky attachment types
    if safe_int(row['has_executable_attachment']) == 1:
        warning_indicators += 2
    if safe_int(row['packer_detected']) == 1:
        warning_indicators += 2
    if safe_int(row['any_macro_enabled_document']) == 1:
        warning_indicators += 2
    if safe_int(row['any_vbscript_javascript_detected']) == 1:
        warning_indicators += 2
    if safe_int(row['any_active_x_objects_detected']) == 1:
        warning_indicators += 1
    if safe_int(row['any_network_call_on_open']) == 1:
        warning_indicators += 2
    
    # Suspicious file characteristics
    if safe_float(row['max_metadata_suspicious_score']) > 0.7:
        warning_indicators += 2
    elif safe_float(row['max_metadata_suspicious_score']) > 0.4:
        warning_indicators += 1
    
    # High entropy (obfuscation)
    if safe_float(row['max_suspicious_string_entropy_score']) > 0.8:
        warning_indicators += 1
    
    # Request type analysis
    high_risk_requests = ['wire_transfer', 'credential_request', 'bank_detail_update', 
                         'vpn_or_mfa_reset', 'legal_threat', 'executive_request']
    medium_risk_requests = ['invoice_payment', 'gift_card_request', 'sensitive_data_request',
                           'document_download', 'link_click', 'urgent_callback', 
                           'invoice_verification']
    
    request_type = row['request_type']
    if request_type in high_risk_requests:
        if safe_int(row['urgency_keywords_present']) == 1:
            warning_indicators += 3
        else:
            warning_indicators += 2
    elif request_type in medium_risk_requests:
        warning_indicators += 1
    
    # High-risk role targeted
    if safe_int(row['is_high_risk_role_targeted']) == 1:
        warning_indicators += 1
    
    # VIP impersonation
    vip_sim = safe_float(row['sender_name_similarity_to_vip'])
    if vip_sim > 0.8:
        warning_indicators += 2
    elif vip_sim > 0.5:
        warning_indicators += 1
    
    # Path mismatches
    if safe_int(row['return_path_mismatch_with_from']) == 1:
        warning_indicators += 1
    if safe_int(row['reply_path_diff_from_sender']) == 1:
        warning_indicators += 1
    
    # URL shorteners and redirects
    if safe_int(row['url_shortener_detected']) == 1:
        warning_indicators += 1
    if safe_int(row['url_redirect_chain_length']) > 2:
        warning_indicators += 1
    
    # === CLASSIFICATION DECISION ===
    
    # If high spam score and low warning indicators, classify as Spam
    if spam_indicators >= 5 and warning_indicators <= 2:
        return 'Spam'
    
    # If significant warning indicators, classify as Warning
    if warning_indicators >= 5:
        return 'Warning'
    
    # If moderate warning indicators with some risk
    if warning_indicators >= 3:
        return 'Warning'
    
    # If moderate spam indicators
    if spam_indicators >= 4:
        return 'Spam'
    
    # If any warning indicators at all (being conservative)
    if warning_indicators >= 2:
        return 'Warning'
    
    # If mild spam indicators
    if spam_indicators >= 3:
        return 'Spam'
    
    # Otherwise, no action needed
    return 'No Action'

# Read the CSV file
with open('1-6332final.csv', 'r') as infile:
    reader = csv.DictReader(infile)
    rows = list(reader)
    headers = reader.fieldnames

# Add New_Classification column
if 'New_Classification' not in headers:
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
print("Classification Analysis Complete (Final Version)")
print("="*50)
print(f"\nTotal records analyzed: {len(rows)}")
print(f"Classifications changed: {changes} ({changes/len(rows)*100:.2f}%)")

print("\nOriginal Classification Distribution:")
for class_name in ['Malicious', 'Warning', 'No Action', 'Spam']:
    if class_name in classification_counts:
        print(f"  {class_name}: {classification_counts[class_name]:,}")

print("\nNew Classification Distribution:")
for class_name in ['Malicious', 'Warning', 'No Action', 'Spam']:
    if class_name in new_classification_counts:
        print(f"  {class_name}: {new_classification_counts[class_name]:,}")

print("\nNet Changes by Category:")
for class_name in ['Malicious', 'Warning', 'No Action', 'Spam']:
    original = classification_counts.get(class_name, 0)
    new = new_classification_counts.get(class_name, 0)
    change = new - original
    print(f"  {class_name}: {original:,} → {new:,} ({change:+,})")

if changes > 0:
    print("\nDetailed Changes:")
    for change, count in sorted(change_matrix.items()):
        print(f"  {change}: {count:,}")

print(f"\nUpdated dataset saved to '1-6332final_analyzed.csv'")