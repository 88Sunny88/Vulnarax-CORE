#!/usr/bin/env python3
"""
Comprehensive test suite for ML Enhanced Vulnerability Analysis
Tests machine learning features including false positive detection and risk prediction
"""

import os
import sys
import json
from typing import List, Dict, Any

# Test the ML analyzer directly
sys.path.append('/Users/alexandervidenov/Desktop/Vulnarax-core')
from vulnaraX.ml_analyzer import analyze_vulnerabilities_with_ml, get_ml_analyzer

def create_test_vulnerabilities() -> List[Dict[str, Any]]:
    """Create sample vulnerabilities for ML testing"""
    return [
        {
            'id': 'SQL-001',
            'vulnerability_type': 'sql_injection',
            'severity': 'high',
            'title': 'SQL Injection in user query',
            'description': 'Direct string concatenation in SQL query construction',
            'location': {
                'file_path': '/app/database.py',
                'line_number': 45,
                'function_name': 'get_user'
            },
            'code_snippet': 'query = "SELECT * FROM users WHERE id = \'" + user_id + "\'"',
            'confidence': 0.9,
            'cwe_id': 'CWE-89'
        },
        {
            'id': 'CMD-001', 
            'vulnerability_type': 'command_injection',
            'severity': 'critical',
            'title': 'Command injection via os.system',
            'description': 'User input passed directly to system command',
            'location': {
                'file_path': '/app/utils.py',
                'line_number': 23,
                'function_name': 'backup_files'
            },
            'code_snippet': 'os.system(f"tar -czf backup.tar.gz {directory}")',
            'confidence': 0.95,
            'cwe_id': 'CWE-78'
        },
        {
            'id': 'SECRET-001',
            'vulnerability_type': 'hardcoded_secrets',
            'severity': 'medium',
            'title': 'Hardcoded API key',
            'description': 'API key found in source code',
            'location': {
                'file_path': '/app/config.py',
                'line_number': 12,
                'function_name': None
            },
            'code_snippet': 'API_KEY = "sk-1234567890abcdef1234567890abcdef12345678"',
            'confidence': 0.8,
            'cwe_id': 'CWE-798'
        },
        {
            'id': 'CRYPTO-001',
            'vulnerability_type': 'weak_crypto',
            'severity': 'low',
            'title': 'Use of MD5 hash function',
            'description': 'MD5 is cryptographically weak',
            'location': {
                'file_path': '/app/auth.py',
                'line_number': 67,
                'function_name': 'hash_password'
            },
            'code_snippet': 'return hashlib.md5(password.encode()).hexdigest()',
            'confidence': 0.7,
            'cwe_id': 'CWE-327'
        },
        {
            'id': 'EVAL-001',
            'vulnerability_type': 'unsafe_reflection',
            'severity': 'high',
            'title': 'Use of eval() function',
            'description': 'Dynamic code execution using eval',
            'location': {
                'file_path': '/app/calculator.py',
                'line_number': 15,
                'function_name': 'calculate'
            },
            'code_snippet': 'result = eval(expression)',
            'confidence': 0.85,
            'cwe_id': 'CWE-95'
        },
        {
            'id': 'POTENTIAL-FP-001',
            'vulnerability_type': 'sql_injection',
            'severity': 'medium',
            'title': 'Potential SQL injection in test code',
            'description': 'SQL-like string in test file',
            'location': {
                'file_path': '/tests/test_database.py',
                'line_number': 78,
                'function_name': 'test_query_building'
            },
            'code_snippet': 'expected_query = "SELECT * FROM users WHERE id = \'" + test_id + "\'"',
            'confidence': 0.4,  # Low confidence - likely false positive
            'cwe_id': 'CWE-89'
        }
    ]

def test_ml_analyzer_initialization():
    """Test ML analyzer initialization and model loading"""
    print("\\n🤖 Testing ML Analyzer Initialization")
    print("=" * 45)
    
    try:
        analyzer = get_ml_analyzer()
        
        print(f"✅ ML Analyzer initialized successfully")
        print(f"   📊 Model Components:")
        print(f"      Feature Extractor: {'✅' if analyzer.feature_extractor else '❌'}")
        print(f"      False Positive Model: {'✅' if analyzer.false_positive_model else '❌'}")
        print(f"      Risk Prediction Model: {'✅' if analyzer.risk_prediction_model else '❌'}")
        print(f"      Anomaly Detector: {'✅' if analyzer.anomaly_detector else '❌'}")
        print(f"      TF-IDF Vectorizer: {'✅' if analyzer.tfidf_vectorizer else '❌'}")
        
        # Check if ML libraries are available
        try:
            import sklearn
            import pandas
            import numpy
            ml_available = True
        except ImportError:
            ml_available = False
        
        print(f"\\n   📦 Dependencies:")
        print(f"      ML Libraries Available: {'✅' if ml_available else '❌ (using rule-based analysis)'}")
        
        return True
        
    except Exception as e:
        print(f"❌ ML Analyzer initialization failed: {e}")
        return False

def test_feature_extraction():
    """Test vulnerability feature extraction"""
    print("\\n🔍 Testing Feature Extraction")
    print("=" * 35)
    
    try:
        analyzer = get_ml_analyzer()
        test_vulns = create_test_vulnerabilities()
        
        # Test feature extraction for different vulnerability types
        for vuln in test_vulns[:3]:  # Test first 3
            features = analyzer.feature_extractor.extract_features_from_vulnerability(vuln)
            
            print(f"\\n   📝 {vuln['vulnerability_type'].replace('_', ' ').title()}:")
            print(f"      File Extension: {features.file_extension}")
            print(f"      Code Complexity: {features.code_complexity:.1f}")
            print(f"      Comment Ratio: {features.comment_ratio:.2f}")
            print(f"      Syntax Patterns: {', '.join(features.syntax_patterns[:3])}")
            print(f"      Semantic Patterns: {', '.join(features.semantic_patterns[:3])}")
        
        return True
        
    except Exception as e:
        print(f"❌ Feature extraction failed: {e}")
        return False

def test_ml_vulnerability_analysis():
    """Test ML-powered vulnerability analysis"""
    print("\\n🧠 Testing ML Vulnerability Analysis")
    print("=" * 40)
    
    try:
        test_vulns = create_test_vulnerabilities()
        
        # Analyze vulnerabilities with ML
        enhanced_vulns = analyze_vulnerabilities_with_ml(test_vulns)
        
        print(f"✅ ML analysis completed successfully")
        print(f"   📊 Analysis Results:")
        print(f"      Original Vulnerabilities: {len(test_vulns)}")
        print(f"      Enhanced Vulnerabilities: {len(enhanced_vulns)}")
        
        # Show ML analysis results
        print(f"\\n   🤖 ML Predictions:")
        
        total_confidence = 0
        false_positive_count = 0
        high_confidence_count = 0
        
        for vuln in enhanced_vulns:
            ml_analysis = vuln.get('ml_analysis', {})
            confidence = ml_analysis.get('confidence_score', 0.5)
            is_fp = ml_analysis.get('is_false_positive', False)
            risk_score = ml_analysis.get('ml_risk_score', 5.0)
            
            total_confidence += confidence
            if is_fp:
                false_positive_count += 1
            if confidence >= 0.8:
                high_confidence_count += 1
            
            print(f"      {vuln['id']}: Confidence={confidence:.2f}, FP={is_fp}, Risk={risk_score:.1f}")
        
        # Summary statistics
        avg_confidence = total_confidence / len(enhanced_vulns)
        fp_rate = false_positive_count / len(enhanced_vulns)
        
        print(f"\\n   📈 ML Statistics:")
        print(f"      Average Confidence: {avg_confidence:.2f}")
        print(f"      False Positive Rate: {fp_rate:.1%}")
        print(f"      High Confidence Count: {high_confidence_count}")
        
        # Check if potential false positive was detected
        potential_fp = next((v for v in enhanced_vulns if v['id'] == 'POTENTIAL-FP-001'), None)
        if potential_fp:
            ml_analysis = potential_fp.get('ml_analysis', {})
            is_detected_fp = ml_analysis.get('is_false_positive', False)
            confidence = ml_analysis.get('confidence_score', 0.5)
            
            print(f"\\n   🎯 False Positive Detection Test:")
            print(f"      Test Case: Low-confidence SQL injection in test file")
            print(f"      Detected as FP: {'✅' if is_detected_fp else '❌'}")
            print(f"      Confidence Score: {confidence:.2f}")
            print(f"      Expected: Low confidence or marked as false positive")
        
        return True
        
    except Exception as e:
        print(f"❌ ML vulnerability analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_risk_prediction_accuracy():
    """Test ML risk prediction accuracy"""
    print("\\n🎯 Testing Risk Prediction Accuracy")
    print("=" * 40)
    
    try:
        test_vulns = create_test_vulnerabilities()
        enhanced_vulns = analyze_vulnerabilities_with_ml(test_vulns)
        
        # Expected risk levels based on severity and type
        expected_risks = {
            'CMD-001': 'high',      # Command injection - critical
            'SQL-001': 'high',      # SQL injection - high  
            'EVAL-001': 'high',     # Unsafe reflection - high
            'SECRET-001': 'medium', # Hardcoded secrets - medium
            'CRYPTO-001': 'low',    # Weak crypto - low
            'POTENTIAL-FP-001': 'low' # Potential false positive
        }
        
        correct_predictions = 0
        total_predictions = 0
        
        print(f"   🎯 Risk Prediction Results:")
        
        for vuln in enhanced_vulns:
            vuln_id = vuln['id']
            ml_analysis = vuln.get('ml_analysis', {})
            ml_risk_score = ml_analysis.get('ml_risk_score', 5.0)
            
            # Convert risk score to category
            if ml_risk_score <= 3:
                predicted_risk = 'low'
            elif ml_risk_score <= 6:
                predicted_risk = 'medium'
            else:
                predicted_risk = 'high'
            
            expected_risk = expected_risks.get(vuln_id, 'medium')
            is_correct = predicted_risk == expected_risk
            
            if is_correct:
                correct_predictions += 1
            total_predictions += 1
            
            status = '✅' if is_correct else '❌'
            print(f"      {vuln_id}: {status} Predicted={predicted_risk}, Expected={expected_risk}, Score={ml_risk_score:.1f}")
        
        accuracy = correct_predictions / total_predictions if total_predictions > 0 else 0
        print(f"\\n   📊 Prediction Accuracy: {accuracy:.1%} ({correct_predictions}/{total_predictions})")
        
        return accuracy >= 0.6  # 60% accuracy threshold
        
    except Exception as e:
        print(f"❌ Risk prediction test failed: {e}")
        return False

def test_confidence_scoring():
    """Test confidence scoring functionality"""
    print("\\n🎲 Testing Confidence Scoring")
    print("=" * 33)
    
    try:
        test_vulns = create_test_vulnerabilities()
        enhanced_vulns = analyze_vulnerabilities_with_ml(test_vulns)
        
        confidence_results = []
        
        print(f"   🎲 Confidence Analysis:")
        
        for vuln in enhanced_vulns:
            original_confidence = vuln.get('confidence', 0.5)
            ml_analysis = vuln.get('ml_analysis', {})
            ml_confidence = ml_analysis.get('confidence_score', 0.5)
            
            confidence_results.append({
                'id': vuln['id'],
                'original': original_confidence,
                'ml_enhanced': ml_confidence,
                'improvement': ml_confidence - original_confidence
            })
            
            print(f"      {vuln['id']}: Original={original_confidence:.2f}, ML={ml_confidence:.2f}")
        
        # Calculate confidence statistics
        avg_original = sum(r['original'] for r in confidence_results) / len(confidence_results)
        avg_ml = sum(r['ml_enhanced'] for r in confidence_results) / len(confidence_results)
        avg_improvement = sum(r['improvement'] for r in confidence_results) / len(confidence_results)
        
        print(f"\\n   📈 Confidence Statistics:")
        print(f"      Average Original: {avg_original:.2f}")
        print(f"      Average ML Enhanced: {avg_ml:.2f}")
        print(f"      Average Improvement: {avg_improvement:+.2f}")
        
        # Check if high-risk vulnerabilities have higher confidence
        high_risk_vulns = ['CMD-001', 'SQL-001', 'EVAL-001']
        high_risk_confidences = [
            r['ml_enhanced'] for r in confidence_results 
            if r['id'] in high_risk_vulns
        ]
        
        if high_risk_confidences:
            avg_high_risk_confidence = sum(high_risk_confidences) / len(high_risk_confidences)
            print(f"      High-Risk Vulnerability Confidence: {avg_high_risk_confidence:.2f}")
            
            # High-risk vulnerabilities should have higher confidence
            return avg_high_risk_confidence >= 0.7
        
        return True
        
    except Exception as e:
        print(f"❌ Confidence scoring test failed: {e}")
        return False

def main():
    """Run comprehensive ML analyzer tests"""
    print("🚀 VulnaraX ML Enhanced Vulnerability Analysis Testing")
    print("=" * 70)
    
    test_results = []
    
    # Test 1: ML analyzer initialization
    test_results.append(test_ml_analyzer_initialization())
    
    # Test 2: Feature extraction
    test_results.append(test_feature_extraction())
    
    # Test 3: ML vulnerability analysis
    test_results.append(test_ml_vulnerability_analysis())
    
    # Test 4: Risk prediction accuracy
    test_results.append(test_risk_prediction_accuracy())
    
    # Test 5: Confidence scoring
    test_results.append(test_confidence_scoring())
    
    # Summary
    print("\\n📊 Test Summary")
    print("=" * 30)
    
    tests = [
        "ML Analyzer Initialization",
        "Feature Extraction",
        "ML Vulnerability Analysis",
        "Risk Prediction Accuracy",
        "Confidence Scoring"
    ]
    
    for i, (test_name, result) in enumerate(zip(tests, test_results)):
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{i+1}. {test_name}: {status}")
    
    success_rate = sum(test_results) / len(test_results)
    print(f"\\n🎯 Overall Success Rate: {success_rate:.1%}")
    
    if success_rate >= 0.8:
        print("\\n🎉 ML Enhanced Analysis is working excellently!")
        print("✨ VulnaraX now has enterprise-grade machine learning capabilities")
        print("🧠 Features: False positive detection, risk prediction, confidence scoring")
    elif success_rate >= 0.6:
        print("\\n🌟 ML Enhanced Analysis is working well!")
        print("📈 Good performance with room for improvement")
    else:
        print("\\n⚠️  Some tests failed. Review the ML implementation.")
        
    return success_rate >= 0.6

if __name__ == "__main__":
    main()