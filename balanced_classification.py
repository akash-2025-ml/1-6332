import csv

def analyze_email_balanced(row):
    """Balanced classification based on all 68 signals"""
    
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
    
    # === STEP 1: CHECK FOR CONFIRMED MALICIOUS (Immediate return) ===
    # Any of these = definitely malicious
    if safe_int(row.get('sender_known_malicios', 0)) == 1:
        return 'Malicious'
    if safe_int(row.get('any_file_hash_malicious', 0)) == 1:
        return 'Malicious'
    if safe_int(row.get('malicious_attachment_Count', 0)) > 0:
        return 'Malicious'
    if safe_int(row.get('total_components_detected_malicious', 0)) > 0:
        return 'Malicious'
    if safe_int(row.get('domain_known_malicious', 0)) == 1:
        return 'Malicious'
    if safe_int(row.get('return_path_known_malicious', 0)) == 1:
        return 'Malicious'
    if safe_int(row.get('reply_path_known_malicious', 0)) == 1:
        return 'Malicious'
    if safe_int(row.get('smtp_ip_known_malicious', 0)) == 1:
        return 'Malicious'
    if safe_int(row.get('final_url_known_malicious', 0)) == 1:
        return 'Malicious'
    
    # Very high behavioral scores = malicious
    if safe_float(row.get('max_behavioral_sandbox_score', 0)) > 0.8:
        return 'Malicious'
    if safe_float(row.get('max_exfiltration_behavior_score', 0)) > 0.9:
        return 'Malicious'
    
    # Confirmed exploit = malicious
    if safe_int(row.get('any_exploit_pattern_detected', 0)) == 1:
        return 'Malicious'
    
    # === STEP 2: CALCULATE RISK SCORES ===
    
    # Warning/Risk Score
    risk_score = 0
    
    # Behavioral risks (moderate levels)
    behavioral = safe_float(row.get('max_behavioral_sandbox_score', 0))
    if 0.4 < behavioral <= 0.8:
        risk_score += 3
    elif 0.2 < behavioral <= 0.4:
        risk_score += 1
    
    exfiltration = safe_float(row.get('max_exfiltration_behavior_score', 0))
    if 0.6 < exfiltration <= 0.9:
        risk_score += 3
    elif 0.3 < exfiltration <= 0.6:
        risk_score += 1
    
    # Spoofing
    if safe_int(row.get('sender_spoof_detected', 0)) == 1:
        risk_score += 3
    if safe_int(row.get('url_decoded_spoof_detected', 0)) == 1:
        risk_score += 3
    if safe_int(row.get('dna_morphing_detected', 0)) == 1:
        risk_score += 2
    
    # Visual similarity (phishing)
    if safe_float(row.get('site_visual_similarity_to_known_brand', 0)) > 0.7:
        risk_score += 3
    
    # Poor reputation
    if safe_float(row.get('sender_domain_reputation_score', 0)) < 0.3:
        risk_score += 2
    if safe_float(row.get('url_reputation_score', 0)) > 0 and safe_float(row.get('url_reputation_score', 0)) < 0.2:
        risk_score += 2
    
    # Authentication failures
    auth_fails = 0
    if row.get('spf_result') in ['fail', 'softfail']:
        auth_fails += 1
    if row.get('dkim_result') == 'fail':
        auth_fails += 1
    if row.get('dmarc_result') == 'fail':
        auth_fails += 1
    risk_score += min(auth_fails * 1, 3)  # Cap at 3
    
    # Risky attachments
    if safe_int(row.get('has_executable_attachment', 0)) == 1:
        risk_score += 2
    if safe_int(row.get('packer_detected', 0)) == 1:
        risk_score += 2
    if safe_int(row.get('any_macro_enabled_document', 0)) == 1:
        risk_score += 1
    if safe_int(row.get('any_vbscript_javascript_detected', 0)) == 1:
        risk_score += 1
    if safe_int(row.get('any_network_call_on_open', 0)) == 1:
        risk_score += 2
    
    # SSL issues
    ssl_status = row.get('ssl_validity_status', '')
    if ssl_status in ['expired', 'self_signed', 'mismatch', 'revoked']:
        risk_score += 2
    elif ssl_status == 'no_ssl':
        risk_score += 1
    
    # High-risk requests
    request_type = row.get('request_type', 'none')
    if request_type in ['wire_transfer', 'credential_request', 'bank_detail_update', 'vpn_or_mfa_reset']:
        risk_score += 3
    elif request_type in ['invoice_payment', 'gift_card_request', 'legal_threat']:
        risk_score += 2
    elif request_type != 'none':
        risk_score += 1
    
    # Urgency with request
    if safe_int(row.get('urgency_keywords_present', 0)) == 1 and request_type != 'none':
        risk_score += 1
    
    # Spam Score
    spam_score = 0
    
    # Content spam score (primary indicator)
    content_spam = safe_float(row.get('content_spam_score', 0))
    if content_spam > 0.8:
        spam_score += 5
    elif content_spam > 0.6:
        spam_score += 4
    elif content_spam > 0.4:
        spam_score += 3
    elif content_spam > 0.2:
        spam_score += 2
    elif content_spam > 0.1:
        spam_score += 1
    
    # User marked as spam
    if safe_int(row.get('user_marked_as_spam_before', 0)) == 1:
        spam_score += 4
    
    # Bulk indicator
    if safe_int(row.get('bulk_message_indicator', 0)) == 1:
        spam_score += 3
    
    # Marketing keywords
    marketing = safe_float(row.get('marketing-keywords_detected', 0))
    if marketing > 0.7:
        spam_score += 3
    elif marketing > 0.4:
        spam_score += 2
    elif marketing > 0.2:
        spam_score += 1
    
    # Temporary email
    temp_email = safe_float(row.get('sender_temp_email_likelihood', 0))
    if temp_email > 0.8:
        spam_score += 3
    elif temp_email > 0.5:
        spam_score += 2
    elif temp_email > 0.3:
        spam_score += 1
    
    # Spam-like characteristics
    if safe_int(row.get('unsubscribe_link_present', 0)) == 1:
        spam_score += 1
    if safe_int(row.get('image_only_email', 0)) == 1:
        spam_score += 1
    
    # === STEP 3: CLASSIFICATION DECISION ===
    
    # High risk = Warning (security concern)
    if risk_score >= 6:
        return 'Warning'
    
    # High spam with low risk = Spam
    if spam_score >= 6 and risk_score < 3:
        return 'Spam'
    
    # Moderate risk = Warning
    if risk_score >= 3:
        return 'Warning'
    
    # Moderate spam = Spam
    if spam_score >= 4 and risk_score < 2:
        return 'Spam'
    
    # Low risk but some concerns = Warning
    if risk_score >= 2:
        return 'Warning'
    
    # Low spam = Spam
    if spam_score >= 3:
        return 'Spam'
    
    # Minimal concerns
    if risk_score >= 1 or spam_score >= 2:
        return 'Warning'
    
    # Clean email
    return 'No Action'

# Process the dataset
def main():
    with open('1-6332final.csv', 'r') as infile:
        reader = csv.DictReader(infile)
        rows = list(reader)
        headers = reader.fieldnames
    
    if 'New_Classification' not in headers:
        headers.append('New_Classification')
    
    # Classification statistics
    changes = 0
    original_counts = {'Malicious': 0, 'Warning': 0, 'No Action': 0, 'Spam': 0}
    new_counts = {'Malicious': 0, 'Warning': 0, 'No Action': 0, 'Spam': 0}
    change_matrix = {}
    
    for row in rows:
        original = row['Classification']
        new = analyze_email_balanced(row)
        row['New_Classification'] = new
        
        if original in original_counts:
            original_counts[original] += 1
        if new in new_counts:
            new_counts[new] += 1
        
        if original != new:
            changes += 1
            change_key = f"{original} -> {new}"
            change_matrix[change_key] = change_matrix.get(change_key, 0) + 1
    
    # Write results
    with open('1-6332final_analyzed.csv', 'w', newline='') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    
    # Print report
    print("Balanced Classification Analysis (All 68 Signals)")
    print("="*50)
    print(f"\nTotal records: {len(rows)}")
    print(f"Changed: {changes} ({changes/len(rows)*100:.1f}%)")
    
    print("\nOriginal Distribution:")
    for cls in ['Malicious', 'Warning', 'Spam', 'No Action']:
        print(f"  {cls}: {original_counts[cls]:,}")
    
    print("\nNew Distribution:")
    for cls in ['Malicious', 'Warning', 'Spam', 'No Action']:
        print(f"  {cls}: {new_counts[cls]:,}")
    
    print("\nNet Changes:")
    for cls in ['Malicious', 'Warning', 'Spam', 'No Action']:
        diff = new_counts[cls] - original_counts[cls]
        print(f"  {cls}: {diff:+,}")
    
    # Agreement rates
    print("\nAgreement Rates:")
    for cls in ['Malicious', 'Warning', 'Spam', 'No Action']:
        if original_counts[cls] > 0:
            agreed = sum(1 for r in rows if r['Classification'] == cls and r['New_Classification'] == cls)
            print(f"  {cls}: {agreed}/{original_counts[cls]} ({agreed/original_counts[cls]*100:.1f}%)")

if __name__ == "__main__":
    main()