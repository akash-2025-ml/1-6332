import csv
import json

# Comprehensive signal categorization based on Detection_Signals_Essentials_1.0.csv
SIGNAL_CATEGORIES = {
    # CRITICAL MALICIOUS INDICATORS (Binary 0/1 - any 1 = Malicious)
    'confirmed_malicious': [
        'sender_known_malicios',  # Known malicious sender
        'any_file_hash_malicious',  # File hash matches known malware
        'malicious_attachment_Count',  # Count of malicious attachments (>0 = malicious)
        'total_components_detected_malicious',  # Malicious components found (>0 = malicious)
        'domain_known_malicious',  # Domain in threat intelligence
        'return_path_known_malicious',  # Return path is malicious
        'reply_path_known_malicious',  # Reply path is malicious
        'smtp_ip_known_malicious',  # Sending IP is malicious
        'final_url_known_malicious',  # Final URL after redirects is malicious
    ],
    
    # HIGH-RISK BEHAVIORAL INDICATORS (Float scores)
    'high_risk_behavior': {
        'max_behavioral_sandbox_score': 0.7,  # >0.7 = high risk execution behavior
        'max_exfiltration_behavior_score': 0.8,  # >0.8 = data theft attempt
        'max_amsi_suspicion_score': 0.7,  # >0.7 = suspicious script behavior
        'url_rendering_behavior_score': 0.8,  # >0.8 = malicious JavaScript
    },
    
    # EXPLOIT AND ATTACK INDICATORS
    'exploit_indicators': [
        'any_exploit_pattern_detected',  # Known exploit patterns
        'any_network_call_on_open',  # Calls home when opened
        'packer_detected',  # Obfuscated executable
    ],
    
    # SPOOFING AND DECEPTION
    'spoofing_indicators': [
        'sender_spoof_detected',  # Domain impersonation
        'url_decoded_spoof_detected',  # URL spoofing
        'dna_morphing_detected',  # DNS morphing/homograph
        'return_path_mismatch_with_from',  # Envelope/header mismatch
        'reply_path_diff_from_sender',  # Reply-to mismatch
    ],
    
    # REPUTATION SCORES (Lower = worse)
    'reputation_thresholds': {
        'sender_domain_reputation_score': {'critical': 0.2, 'warning': 0.5},
        'return_path_reputation_score': {'critical': 0.2, 'warning': 0.5},
        'reply_path_reputation_Score': {'critical': 0.2, 'warning': 0.5},
        'smtp_ip_reputation_score': {'critical': 0.2, 'warning': 0.5},
        'url_reputation_score': {'critical': 0.1, 'warning': 0.3},
    },
    
    # AUTHENTICATION FAILURES
    'auth_failures': {
        'spf_result': ['fail', 'softfail'],
        'dkim_result': ['fail'],
        'dmarc_result': ['fail'],
    },
    
    # ATTACHMENT RISKS
    'attachment_risks': [
        'has_executable_attachment',
        'any_macro_enabled_document',
        'any_vbscript_javascript_detected',
        'any_active_x_objects_detected',
        'unscannable_attachment_present',
    ],
    
    # SPAM INDICATORS
    'spam_primary': {
        'content_spam_score': {'high': 0.7, 'medium': 0.4},
        'user_marked_as_spam_before': 1,
        'bulk_message_indicator': 1,
    },
    
    'spam_secondary': {
        'marketing-keywords_detected': 0.5,
        'sender_temp_email_likelihood': 0.6,
        'unsubscribe_link_present': 1,
        'image_only_email': 1,
    },
    
    # HIGH-RISK REQUESTS
    'critical_requests': [
        'wire_transfer', 'credential_request', 'bank_detail_update',
        'vpn_or_mfa_reset', 'legal_threat'
    ],
    
    'risky_requests': [
        'invoice_payment', 'gift_card_request', 'sensitive_data_request',
        'document_download', 'link_click', 'urgent_callback',
        'invoice_verification', 'executive_request'
    ],
    
    # SSL/SECURITY ISSUES
    'ssl_critical': ['expired', 'self_signed', 'mismatch', 'revoked', 'invalid_chain'],
    'ssl_warning': ['no_ssl'],
    
    # ADDITIONAL RISK FACTORS
    'risk_multipliers': {
        'urgency_keywords_present': 1,
        'is_high_risk_role_targeted': 1,
        'sender_name_similarity_to_vip': 0.7,  # >0.7 = impersonation attempt
        'site_visual_similarity_to_known_brand': 0.7,  # >0.7 = phishing
        'url_shortener_detected': 1,
        'url_redirect_chain_length': 2,  # >2 = suspicious
    }
}

def analyze_email_comprehensive(row):
    """Analyze email with comprehensive signal understanding"""
    
    def safe_float(value, default=0.0):
        try:
            return float(value) if value and value != '' else default
        except:
            return default
    
    def safe_int(value, default=0):
        try:
            return int(float(value)) if value and value != '' else default
        except:
            return default
    
    # Initialize detailed scoring
    malicious_evidence = []
    warning_evidence = []
    spam_evidence = []
    
    # 1. CHECK CONFIRMED MALICIOUS INDICATORS (Immediate Malicious)
    for signal in SIGNAL_CATEGORIES['confirmed_malicious']:
        if signal in row:
            value = safe_int(row[signal])
            if (signal == 'malicious_attachment_Count' and value > 0) or \
               (signal == 'total_components_detected_malicious' and value > 0) or \
               (signal != 'malicious_attachment_Count' and signal != 'total_components_detected_malicious' and value == 1):
                malicious_evidence.append(f"{signal}={value}")
    
    # If ANY confirmed malicious indicator, classify as Malicious
    if malicious_evidence:
        return 'Malicious'
    
    # 2. CHECK HIGH-RISK BEHAVIORAL SCORES
    for signal, threshold in SIGNAL_CATEGORIES['high_risk_behavior'].items():
        if signal in row:
            value = safe_float(row[signal])
            if value > threshold:
                malicious_evidence.append(f"{signal}={value:.3f}>{threshold}")
    
    # High behavioral scores = Malicious
    if malicious_evidence:
        return 'Malicious'
    
    # 3. CHECK EXPLOIT PATTERNS WITH OTHER RISKS
    exploit_count = 0
    for signal in SIGNAL_CATEGORIES['exploit_indicators']:
        if signal in row and safe_int(row[signal]) == 1:
            exploit_count += 1
    
    # Multiple exploit indicators or exploit + executable = Malicious
    if exploit_count >= 2 or (exploit_count >= 1 and safe_int(row.get('has_executable_attachment', 0)) == 1):
        return 'Malicious'
    
    # 4. ACCUMULATE WARNING INDICATORS
    warning_score = 0
    
    # Spoofing attempts
    spoof_count = 0
    for signal in SIGNAL_CATEGORIES['spoofing_indicators']:
        if signal in row and safe_int(row[signal]) == 1:
            spoof_count += 1
            warning_score += 2
    
    # Reputation issues
    for signal, thresholds in SIGNAL_CATEGORIES['reputation_thresholds'].items():
        if signal in row:
            value = safe_float(row[signal])
            if value > 0:  # Only check if value exists
                if value < thresholds['critical']:
                    warning_score += 3
                elif value < thresholds['warning']:
                    warning_score += 1
    
    # Authentication failures
    auth_fail_count = 0
    for signal, fail_values in SIGNAL_CATEGORIES['auth_failures'].items():
        if signal in row and row[signal] in fail_values:
            auth_fail_count += 1
    warning_score += auth_fail_count * 2
    
    # Attachment risks
    attachment_risk_count = 0
    for signal in SIGNAL_CATEGORIES['attachment_risks']:
        if signal in row and safe_int(row[signal]) == 1:
            attachment_risk_count += 1
    warning_score += attachment_risk_count * 2
    
    # SSL issues
    if 'ssl_validity_status' in row:
        ssl_status = row['ssl_validity_status']
        if ssl_status in SIGNAL_CATEGORIES['ssl_critical']:
            warning_score += 3
        elif ssl_status in SIGNAL_CATEGORIES['ssl_warning']:
            warning_score += 1
    
    # Request type analysis
    request_type = row.get('request_type', 'none')
    urgency = safe_int(row.get('urgency_keywords_present', 0))
    
    if request_type in SIGNAL_CATEGORIES['critical_requests']:
        warning_score += 5 if urgency else 4
    elif request_type in SIGNAL_CATEGORIES['risky_requests']:
        warning_score += 3 if urgency else 2
    
    # Risk multipliers
    if safe_int(row.get('is_high_risk_role_targeted', 0)) == 1:
        warning_score += 2
    
    vip_similarity = safe_float(row.get('sender_name_similarity_to_vip', 0))
    if vip_similarity > 0.7:
        warning_score += 3
    elif vip_similarity > 0.5:
        warning_score += 1
    
    brand_similarity = safe_float(row.get('site_visual_similarity_to_known_brand', 0))
    if brand_similarity > 0.7:
        warning_score += 4
    elif brand_similarity > 0.5:
        warning_score += 2
    
    # URL suspicious indicators
    if safe_int(row.get('url_shortener_detected', 0)) == 1:
        warning_score += 1
    
    redirect_length = safe_int(row.get('url_redirect_chain_length', 0))
    if redirect_length > 2:
        warning_score += 2
    
    # 5. CHECK SPAM INDICATORS
    spam_score = 0
    
    # Primary spam indicators
    content_spam = safe_float(row.get('content_spam_score', 0))
    if content_spam > SIGNAL_CATEGORIES['spam_primary']['content_spam_score']['high']:
        spam_score += 4
    elif content_spam > SIGNAL_CATEGORIES['spam_primary']['content_spam_score']['medium']:
        spam_score += 2
    
    if safe_int(row.get('user_marked_as_spam_before', 0)) == 1:
        spam_score += 3
    
    if safe_int(row.get('bulk_message_indicator', 0)) == 1:
        spam_score += 3
    
    # Secondary spam indicators
    if safe_float(row.get('marketing-keywords_detected', 0)) > 0.5:
        spam_score += 2
    
    if safe_float(row.get('sender_temp_email_likelihood', 0)) > 0.6:
        spam_score += 2
    
    if safe_int(row.get('unsubscribe_link_present', 0)) == 1:
        spam_score += 1
    
    if safe_int(row.get('image_only_email', 0)) == 1:
        spam_score += 1
    
    # 6. FINAL CLASSIFICATION DECISION
    
    # High warning score = Warning (security concern)
    if warning_score >= 8:
        return 'Warning'
    
    # High spam score with low warning = Spam
    if spam_score >= 6 and warning_score < 4:
        return 'Spam'
    
    # Moderate warning score = Warning
    if warning_score >= 4:
        return 'Warning'
    
    # Moderate spam score = Spam
    if spam_score >= 4 and warning_score < 2:
        return 'Spam'
    
    # Low scores with some concerns = Warning (conservative)
    if warning_score >= 2 or (warning_score >= 1 and spam_score >= 2):
        return 'Warning'
    
    # Only spam indicators = Spam
    if spam_score >= 3:
        return 'Spam'
    
    # No significant indicators = No Action
    return 'No Action'

# Main processing
def process_dataset():
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
    
    for i, row in enumerate(rows):
        original = row['Classification']
        new_class = analyze_email_comprehensive(row)
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
    
    # Print comprehensive analysis report
    print("Comprehensive Signal-Based Classification Analysis")
    print("="*60)
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
        print("\nMost Common Changes:")
        sorted_changes = sorted(change_matrix.items(), key=lambda x: x[1], reverse=True)
        for change, count in sorted_changes[:10]:
            print(f"  {change}: {count:,}")
    
    print(f"\nUpdated dataset saved to '1-6332final_analyzed.csv'")
    
    # Analyze agreement rate by original classification
    print("\nAgreement Analysis:")
    for orig_class in ['Malicious', 'Warning', 'No Action', 'Spam']:
        total = classification_counts.get(orig_class, 0)
        if total > 0:
            unchanged = sum(1 for r in rows if r['Classification'] == orig_class and r['New_Classification'] == orig_class)
            print(f"  {orig_class}: {unchanged}/{total} ({unchanged/total*100:.1f}% agreement)")

if __name__ == "__main__":
    process_dataset()