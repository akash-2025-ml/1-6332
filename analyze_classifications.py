import pandas as pd
import numpy as np

# Read the dataset
df = pd.read_csv('1-6332final.csv')

# Function to analyze signals and determine correct classification
def analyze_email_signals(row):
    # Initialize risk scores
    malicious_score = 0
    spam_score = 0
    warning_score = 0
    
    # Critical malicious indicators
    if row['sender_known_malicios'] == 1:
        malicious_score += 10
    if row['any_file_hash_malicious'] == 1:
        malicious_score += 10
    if row['malicious_attachment_Count'] > 0:
        malicious_score += 10
    if row['total_components_detected_malicious'] > 0:
        malicious_score += 8
    if row['final_url_known_malicious'] == 1:
        malicious_score += 8
    if row['domain_known_malicious'] == 1:
        malicious_score += 8
    if row['smtp_ip_known_malicious'] == 1:
        malicious_score += 6
    if row['return_path_known_malicious'] == 1:
        malicious_score += 6
    if row['reply_path_known_malicious'] == 1:
        malicious_score += 6
    
    # High-risk behavioral indicators
    if row['max_behavioral_sandbox_score'] > 0.7:
        malicious_score += 8
    elif row['max_behavioral_sandbox_score'] > 0.4:
        warning_score += 5
    
    if row['max_exfiltration_behavior_score'] > 0.8:
        malicious_score += 7
    elif row['max_exfiltration_behavior_score'] > 0.5:
        warning_score += 4
    
    if row['packer_detected'] == 1:
        malicious_score += 5
    if row['has_executable_attachment'] == 1:
        malicious_score += 4
    if row['any_exploit_pattern_detected'] == 1:
        malicious_score += 6
    if row['any_network_call_on_open'] == 1:
        malicious_score += 5
    if row['any_active_x_objects_detected'] == 1:
        malicious_score += 4
    
    # Macro and script indicators
    if row['any_macro_enabled_document'] == 1:
        warning_score += 4
    if row['any_vbscript_javascript_detected'] == 1:
        warning_score += 4
    
    # Spoofing and reputation indicators
    if row['sender_spoof_detected'] == 1:
        warning_score += 5
    if row['sender_domain_reputation_score'] < 0.2:
        warning_score += 4
    elif row['sender_domain_reputation_score'] < 0.5:
        warning_score += 2
    
    # URL and domain indicators
    if row['url_decoded_spoof_detected'] == 1:
        warning_score += 5
    if row['dna_morphing_detected'] == 1:
        warning_score += 4
    if row['url_reputation_score'] < 0.2:
        warning_score += 3
    if row['site_visual_similarity_to_known_brand'] > 0.7:
        warning_score += 5
    
    # Email authentication
    if row['spf_result'] == 'fail':
        warning_score += 3
    if row['dkim_result'] == 'fail':
        warning_score += 2
    if row['dmarc_result'] == 'fail':
        warning_score += 3
    
    # Spam indicators
    if row['content_spam_score'] > 0.7:
        spam_score += 8
    elif row['content_spam_score'] > 0.4:
        spam_score += 4
    
    if row['user_marked_as_spam_before'] == 1:
        spam_score += 6
    if row['bulk_message_indicator'] == 1:
        spam_score += 5
    if row['marketing-keywords_detected'] > 0.5:
        spam_score += 4
    
    # Temporary email likelihood
    if row['sender_temp_email_likelihood'] > 0.7:
        spam_score += 5
    elif row['sender_temp_email_likelihood'] > 0.4:
        spam_score += 3
    
    # Request type analysis
    high_risk_requests = ['wire_transfer', 'credential_request', 'bank_detail_update', 
                         'vpn_or_mfa_reset', 'legal_threat']
    medium_risk_requests = ['invoice_payment', 'gift_card_request', 'sensitive_data_request',
                           'document_download', 'link_click', 'urgent_callback', 
                           'invoice_verification', 'executive_request']
    
    if row['request_type'] in high_risk_requests:
        if row['urgency_keywords_present'] == 1:
            malicious_score += 6
        else:
            warning_score += 5
    elif row['request_type'] in medium_risk_requests:
        warning_score += 3
    
    # SSL and security indicators
    if row['ssl_validity_status'] in ['expired', 'self signed', 'mismatch', 'revoked']:
        warning_score += 3
    elif row['ssl_validity_status'] == 'no_ssl':
        warning_score += 4
    
    # Calculate final classification
    # Priority: Malicious > Warning > Spam > No Action
    if malicious_score >= 15:
        return 'Malicious'
    elif warning_score >= 12 or (warning_score >= 8 and malicious_score >= 5):
        return 'Warning'
    elif spam_score >= 10 or (spam_score >= 6 and content_spam_score > 0.5):
        return 'Spam'
    elif malicious_score >= 8 and warning_score >= 5:
        return 'Warning'
    else:
        return 'No Action'

# Apply the analysis to each row
df['New_Classification'] = df.apply(analyze_email_signals, axis=1)

# Save the updated dataset
df.to_csv('1-6332final_analyzed.csv', index=False)

# Generate analysis report
print("Classification Analysis Complete")
print("="*50)

# Compare original vs new classifications
comparison = pd.crosstab(df['Classification'], df['New_Classification'])
print("\nClassification Comparison Matrix:")
print(comparison)

# Count differences
differences = df[df['Classification'] != df['New_Classification']]
print(f"\nTotal records analyzed: {len(df)}")
print(f"Classifications changed: {len(differences)} ({len(differences)/len(df)*100:.2f}%)")

# Show distribution of changes
if len(differences) > 0:
    print("\nChanges Summary:")
    change_summary = differences.groupby(['Classification', 'New_Classification']).size()
    print(change_summary)

# Save a detailed differences report
if len(differences) > 0:
    differences[['File?', 'Data ', 'Classification', 'New_Classification']].to_csv(
        'classification_differences.csv', index=False
    )
    print("\nDetailed differences saved to 'classification_differences.csv'")