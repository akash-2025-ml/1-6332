#!/usr/bin/env python3
"""
Email Security Classification Analysis Tool
Senior Email Security Analyst - Batch Processing System

This tool analyzes email security classifications based on 68 detection signals
and validates/corrects classifications for Malicious, Spam, Warning, or No Action.
"""

import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings('ignore')

class EmailSecurityAnalyzer:
    def __init__(self):
        self.signals_info = {}
        self.classification_rules = self._define_classification_rules()
        
    def _define_classification_rules(self):
        """Define expert rules for email classification based on signal analysis"""
        return {
            'malicious_indicators': {
                'critical': [
                    'sender_known_malicious', 'any_file_hash_malicious', 'domain_known_malicious',
                    'final_url_known_malicious', 'return_path_known_malicious', 'smtp_ip_known_malicious'
                ],
                'high_risk': [
                    'packer_detected', 'any_exploit_pattern_detected', 'has_executable_attachment',
                    'any_macro_enabled_document', 'any_network_call_on_open', 'sender_spoof_detected'
                ],
                'behavioral': [
                    'max_behavioral_sandbox_score', 'max_amsi_suspicion_score', 'max_exfiltration_behavior_score',
                    'total_yara_match_count', 'total_ioc_count', 'malicious_attachment_Count'
                ]
            },
            'spam_indicators': [
                'content_spam_score', 'bulk_message_indicator', 'marketing_keywords_detected',
                'user_marked_as_spam_before', 'unsubscribe_link_present'
            ],
            'warning_indicators': [
                'sender_temp_email_likelihood', 'urgency_keywords_present', 'is_high_risk_role_targeted',
                'sender_name_similarity_to_vip', 'url_shortener_detected', 'image_only_email'
            ],
            'authentication_issues': [
                'spf_result', 'dkim_result', 'dmarc_result', 'dmarc_enforced'
            ]
        }
    
    def analyze_record(self, record):
        """Analyze a single email record and determine correct classification"""
        malicious_score = self._calculate_malicious_score(record)
        spam_score = self._calculate_spam_score(record)
        warning_score = self._calculate_warning_score(record)
        
        # Decision logic based on expert analysis
        if malicious_score >= 0.7:
            return "Malicious"
        elif spam_score >= 0.6:
            return "Spam"  
        elif warning_score >= 0.4 or malicious_score >= 0.3:
            return "Warning"
        else:
            return "No Action"
    
    def _calculate_malicious_score(self, record):
        """Calculate malicious likelihood score (0-1)"""
        score = 0.0
        
        # Critical indicators - immediate malicious classification
        critical_signals = self.classification_rules['malicious_indicators']['critical']
        for signal in critical_signals:
            if signal in record and record[signal] == 1:
                return 1.0
        
        # High-risk behavioral indicators
        high_risk_signals = self.classification_rules['malicious_indicators']['high_risk']
        high_risk_count = sum(1 for signal in high_risk_signals if signal in record and record[signal] == 1)
        score += min(high_risk_count * 0.25, 0.8)
        
        # Behavioral analysis scores
        behavioral_signals = self.classification_rules['malicious_indicators']['behavioral']
        for signal in behavioral_signals:
            if signal in record and pd.notna(record[signal]):
                if signal.endswith('_score'):
                    score += min(float(record[signal]) * 0.3, 0.3)
                elif signal.endswith('_count') and float(record[signal]) > 0:
                    score += min(float(record[signal]) * 0.1, 0.4)
        
        # Authentication failures
        auth_failures = 0
        if record.get('spf_result') in ['fail', 'softfail']:
            auth_failures += 1
        if record.get('dkim_result') == 'fail':
            auth_failures += 1
        if record.get('dmarc_result') == 'fail':
            auth_failures += 1
        
        if auth_failures >= 2:
            score += 0.2
        
        return min(score, 1.0)
    
    def _calculate_spam_score(self, record):
        """Calculate spam likelihood score (0-1)"""
        score = 0.0
        
        # Content spam indicators
        if 'content_spam_score' in record and pd.notna(record['content_spam_score']):
            score += float(record['content_spam_score']) * 0.4
        
        # Bulk/marketing indicators
        spam_indicators = self.classification_rules['spam_indicators']
        spam_count = 0
        for signal in spam_indicators:
            if signal in record:
                if signal.endswith('_score') or signal.endswith('_detected'):
                    if pd.notna(record[signal]) and float(record[signal]) > 0.5:
                        spam_count += 1
                elif record[signal] == 1:
                    spam_count += 1
        
        score += min(spam_count * 0.15, 0.6)
        
        return min(score, 1.0)
    
    def _calculate_warning_score(self, record):
        """Calculate warning likelihood score (0-1)"""
        score = 0.0
        
        # Warning indicators
        warning_signals = self.classification_rules['warning_indicators']
        for signal in warning_signals:
            if signal in record and pd.notna(record[signal]):
                if signal.endswith('_likelihood') or signal.endswith('_similarity_to_vip'):
                    score += min(float(record[signal]) * 0.2, 0.3)
                elif record[signal] == 1:
                    score += 0.15
        
        # Request type analysis
        if 'request_type' in record and record['request_type'] not in ['none', '']:
            if record['request_type'] in ['wire_transfer', 'credential_request', 'executive_request']:
                score += 0.4
            elif record['request_type'] in ['invoice_payment', 'sensitive_data_request']:
                score += 0.3
            else:
                score += 0.1
        
        return min(score, 1.0)

def process_batch(df, start_idx, end_idx, analyzer):
    """Process a batch of records and return analysis results"""
    results = []
    batch_data = df.iloc[start_idx:end_idx].copy()
    
    for idx, record in batch_data.iterrows():
        try:
            original_classification = record['Classification']
            new_classification = analyzer.analyze_record(record)
            
            # Handle inconsistent labels (0,1,2,3,4,5) - map to proper categories
            if str(original_classification).isdigit():
                digit_map = {'0': 'No Action', '1': 'Warning', '2': 'Spam', 
                           '3': 'Malicious', '4': 'Warning', '5': 'Malicious'}
                original_classification = digit_map.get(str(int(float(original_classification))), 'No Action')
            
            results.append({
                'Data': record['Data '],
                'Original_Classification': original_classification,
                'New_Classification': new_classification,
                'Classification_Changed': original_classification != new_classification,
                'Analysis_Confidence': 'High' if new_classification in ['Malicious', 'No Action'] else 'Medium'
            })
            
        except Exception as e:
            results.append({
                'Data': record['Data '],
                'Original_Classification': record['Classification'],
                'New_Classification': 'Error',
                'Classification_Changed': False,
                'Analysis_Confidence': 'Error',
                'Error': str(e)
            })
    
    return results

if __name__ == "__main__":
    # Load the dataset
    print("Loading email security dataset...")
    df = pd.read_csv('/home/u3/email_data/1-6332/1-6332final.csv')
    
    # Initialize analyzer
    analyzer = EmailSecurityAnalyzer()
    
    # Process first batch (Task 1: Records 1-100)
    print("\n=== TASK 1: Processing Records 1-100 ===")
    batch1_results = process_batch(df, 0, 100, analyzer)
    
    # Analysis summary
    changes_count = sum(1 for r in batch1_results if r['Classification_Changed'])
    print(f"Records analyzed: 100")
    print(f"Classifications changed: {changes_count}")
    
    # Show sample results
    print(f"\nSample results from first 10 records:")
    for i, result in enumerate(batch1_results[:10]):
        status = "CHANGED" if result['Classification_Changed'] else "UNCHANGED"
        print(f"Record {i+1}: {result['Original_Classification']} → {result['New_Classification']} [{status}]")
    
    print(f"\nTask 1 completed. Ready for Task 2...")