import csv

def classify_based_on_patterns(row):
    """Classification based on patterns observed in original data"""
    
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
    
    # Based on pattern analysis, the original classification seems to use a combination approach
    # rather than strict "any malicious = Malicious" logic
    
    # Initialize scores
    malicious_score = 0
    warning_score = 0
    spam_score = 0
    
    # === MALICIOUS SCORING ===
    # Known malicious indicators (but not automatic classification)
    if safe_int(row.get('sender_known_malicios', 0)) == 1:
        malicious_score += 5
    if safe_int(row.get('any_file_hash_malicious', 0)) == 1:
        malicious_score += 5
    if safe_int(row.get('domain_known_malicious', 0)) == 1:
        malicious_score += 4
    if safe_int(row.get('return_path_known_malicious', 0)) == 1:
        malicious_score += 3
    if safe_int(row.get('reply_path_known_malicious', 0)) == 1:
        malicious_score += 3
    if safe_int(row.get('smtp_ip_known_malicious', 0)) == 1:
        malicious_score += 3
    if safe_int(row.get('final_url_known_malicious', 0)) == 1:
        malicious_score += 4
    
    # Malicious attachment count
    mal_attach = safe_int(row.get('malicious_attachment_Count', 0))
    if mal_attach > 0:
        malicious_score += min(mal_attach * 2, 6)
    
    # Malicious components
    mal_components = safe_int(row.get('total_components_detected_malicious', 0))
    if mal_components > 0:
        malicious_score += min(mal_components, 4)
    
    # Behavioral scores
    behavioral = safe_float(row.get('max_behavioral_sandbox_score', 0))
    if behavioral > 0.8:
        malicious_score += 4
    elif behavioral > 0.5:
        malicious_score += 2
        warning_score += 1
    elif behavioral > 0.3:
        warning_score += 2
    elif behavioral > 0.1:
        warning_score += 1
    
    # Exfiltration behavior
    exfiltration = safe_float(row.get('max_exfiltration_behavior_score', 0))
    if exfiltration > 0.8:
        malicious_score += 3
    elif exfiltration > 0.5:
        malicious_score += 1
        warning_score += 1
    elif exfiltration > 0.3:
        warning_score += 2
    
    # Exploit patterns
    if safe_int(row.get('any_exploit_pattern_detected', 0)) == 1:
        malicious_score += 3
    
    # Packer + executable combo
    if safe_int(row.get('packer_detected', 0)) == 1:
        malicious_score += 2
        if safe_int(row.get('has_executable_attachment', 0)) == 1:
            malicious_score += 2
    elif safe_int(row.get('has_executable_attachment', 0)) == 1:
        warning_score += 2
    
    # Network calls
    if safe_int(row.get('any_network_call_on_open', 0)) == 1:
        malicious_score += 2
    
    # === SPAM SCORING ===
    # Content spam score is key differentiator for spam
    content_spam = safe_float(row.get('content_spam_score', 0))
    if content_spam > 0.8:
        spam_score += 6
    elif content_spam > 0.6:
        spam_score += 5
    elif content_spam > 0.4:
        spam_score += 4
    elif content_spam > 0.2:
        spam_score += 3
    elif content_spam > 0.1:
        spam_score += 2
    elif content_spam > 0.05:
        spam_score += 1
    
    # User marked as spam
    if safe_int(row.get('user_marked_as_spam_before', 0)) == 1:
        spam_score += 3
    
    # Bulk indicator
    if safe_int(row.get('bulk_message_indicator', 0)) == 1:
        spam_score += 2
    
    # Marketing keywords
    marketing = safe_float(row.get('marketing-keywords_detected', 0))
    if marketing > 0.5:
        spam_score += 2
    elif marketing > 0.1:
        spam_score += 1
    
    # Temporary email
    temp_email = safe_float(row.get('sender_temp_email_likelihood', 0))
    if temp_email > 0.7:
        spam_score += 2
    elif temp_email > 0.4:
        spam_score += 1
    
    # === WARNING SCORING ===
    # Spoofing
    if safe_int(row.get('sender_spoof_detected', 0)) == 1:
        warning_score += 3
    if safe_int(row.get('url_decoded_spoof_detected', 0)) == 1:
        warning_score += 3
    if safe_int(row.get('dna_morphing_detected', 0)) == 1:
        warning_score += 2
    
    # Poor reputation
    sender_rep = safe_float(row.get('sender_domain_reputation_score', 0))
    if 0 < sender_rep < 0.2:
        warning_score += 2
    elif 0 < sender_rep < 0.4:
        warning_score += 1
    
    # Authentication issues
    if row.get('spf_result') in ['fail', 'softfail']:
        warning_score += 1
    if row.get('dkim_result') == 'fail':
        warning_score += 1
    if row.get('dmarc_result') == 'fail':
        warning_score += 1
    
    # Risky content
    if safe_int(row.get('any_macro_enabled_document', 0)) == 1:
        warning_score += 2
    if safe_int(row.get('any_vbscript_javascript_detected', 0)) == 1:
        warning_score += 2
    if safe_int(row.get('any_active_x_objects_detected', 0)) == 1:
        warning_score += 1
    
    # Request types
    request_type = row.get('request_type', 'none')
    if request_type in ['wire_transfer', 'credential_request', 'bank_detail_update']:
        warning_score += 3
    elif request_type in ['invoice_payment', 'gift_card_request', 'legal_threat']:
        warning_score += 2
    elif request_type != 'none':
        warning_score += 1
    
    # SSL issues
    ssl_status = row.get('ssl_validity_status', '')
    if ssl_status in ['expired', 'self_signed', 'mismatch', 'revoked']:
        warning_score += 1
    
    # Visual similarity
    if safe_float(row.get('site_visual_similarity_to_known_brand', 0)) > 0.7:
        warning_score += 2
    
    # === CLASSIFICATION DECISION ===
    # Pattern-based thresholds derived from analysis
    
    # Strong malicious indicators
    if malicious_score >= 8:
        return 'Malicious'
    
    # High spam score with low security risk
    if spam_score >= 6 and malicious_score < 4 and warning_score < 4:
        return 'Spam'
    
    # Moderate malicious with some warning signs
    if malicious_score >= 5 and (warning_score >= 2 or spam_score >= 2):
        return 'Malicious'
    
    # High warning score
    if warning_score >= 6:
        return 'Warning'
    
    # Moderate spam
    if spam_score >= 4 and malicious_score < 3:
        return 'Spam'
    
    # Moderate malicious
    if malicious_score >= 4:
        return 'Malicious'
    
    # Moderate warning
    if warning_score >= 3:
        return 'Warning'
    
    # Low spam
    if spam_score >= 3:
        return 'Spam'
    
    # Any malicious components with other risks
    if mal_components > 0 and (warning_score >= 2 or behavioral > 0.1):
        return 'Malicious'
    
    # Low warning
    if warning_score >= 2:
        return 'Warning'
    
    # Minimal spam
    if spam_score >= 2:
        return 'Spam'
    
    # Very low scores
    if malicious_score >= 1 or warning_score >= 1:
        return 'Warning'
    
    # Clean
    return 'No Action'

def main():
    with open('1-6332final.csv', 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        headers = reader.fieldnames
    
    if 'New_Classification' not in headers:
        headers.append('New_Classification')
    
    # Process and count
    changes = 0
    original_counts = {'Malicious': 0, 'Warning': 0, 'No Action': 0, 'Spam': 0}
    new_counts = {'Malicious': 0, 'Warning': 0, 'No Action': 0, 'Spam': 0}
    
    for row in rows:
        original = row['Classification']
        new = classify_based_on_patterns(row)
        row['New_Classification'] = new
        
        if original in original_counts:
            original_counts[original] += 1
        if new in new_counts:
            new_counts[new] += 1
        
        if original != new:
            changes += 1
    
    # Write results
    with open('1-6332final_analyzed.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    
    # Report
    print("Pattern-Based Classification Results")
    print("="*50)
    print(f"\nTotal records: {len(rows)}")
    print(f"Changed: {changes} ({changes/len(rows)*100:.1f}%)")
    
    print("\nOriginal Distribution:")
    for cls in ['Malicious', 'Warning', 'Spam', 'No Action']:
        print(f"  {cls}: {original_counts[cls]:,}")
    
    print("\nNew Distribution:")
    for cls in ['Malicious', 'Warning', 'Spam', 'No Action']:
        print(f"  {cls}: {new_counts[cls]:,}")
    
    print("\nAgreement Rates:")
    for cls in ['Malicious', 'Warning', 'Spam', 'No Action']:
        if original_counts[cls] > 0:
            agreed = sum(1 for r in rows if r['Classification'] == cls and r['New_Classification'] == cls)
            rate = agreed/original_counts[cls]*100
            print(f"  {cls}: {agreed}/{original_counts[cls]} ({rate:.1f}%)")
    
    # Overall accuracy
    correct = sum(1 for r in rows if r['Classification'] == r['New_Classification'])
    print(f"\nOverall Agreement: {correct}/{len(rows)} ({correct/len(rows)*100:.1f}%)")

if __name__ == "__main__":
    main()