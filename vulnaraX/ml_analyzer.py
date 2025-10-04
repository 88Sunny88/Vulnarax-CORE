"""
Machine Learning Enhanced Security Analysis
Provides ML-powered vulnerability prediction, false positive reduction, and risk assessment
"""

import os
import json
import logging
import pickle
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
from datetime import datetime, timedelta

# ML libraries (with fallbacks)
try:
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score
    from sklearn.preprocessing import StandardScaler
    import pandas as pd
    HAS_ML_LIBS = True
except ImportError:
    # Create dummy numpy for basic functionality
    class DummyArray:
        def __init__(self, data):
            self.data = data
        def reshape(self, *args):
            return self
    
    class DummyNumPy:
        def array(self, data):
            return DummyArray(data)
    
    np = DummyNumPy()
    HAS_ML_LIBS = False
    logging.warning("ML libraries not available. Using rule-based analysis only.")

# Advanced ML libraries (optional)
try:
    import torch
    import torch.nn as nn
    from transformers import AutoTokenizer, AutoModel
    HAS_ADVANCED_ML = True
except ImportError:
    HAS_ADVANCED_ML = False


@dataclass
class MLPrediction:
    """ML model prediction result"""
    vulnerability_id: str
    confidence_score: float
    is_false_positive: bool
    risk_score: float
    prediction_reason: str
    model_version: str
    features_used: List[str]


@dataclass
class VulnerabilityFeatures:
    """Feature representation of a vulnerability"""
    code_complexity: float
    line_count: int
    function_depth: int
    variable_count: int
    import_count: int
    comment_ratio: float
    string_literal_count: int
    file_extension: str
    file_size: int
    syntax_patterns: List[str]
    semantic_patterns: List[str]
    historical_patterns: Dict[str, Any]


class VulnerabilityFeatureExtractor:
    """Extract features from vulnerability findings for ML analysis"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def extract_features_from_vulnerability(self, vuln: Dict[str, Any], code_content: str = None) -> VulnerabilityFeatures:
        """Extract comprehensive features from vulnerability"""
        try:
            # Basic file features
            file_path = vuln.get('location', {}).get('file_path', '')
            file_extension = Path(file_path).suffix.lower()
            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            
            # Code analysis features
            if code_content:
                lines = code_content.split('\\n')
                line_count = len(lines)
                comment_ratio = self._calculate_comment_ratio(lines, file_extension)
                string_literal_count = self._count_string_literals(code_content)
                variable_count = self._estimate_variable_count(code_content, file_extension)
                import_count = self._count_imports(code_content, file_extension)
                function_depth = self._estimate_function_depth(code_content, file_extension)
                code_complexity = self._estimate_complexity(code_content, file_extension)
            else:
                # Default values when code not available
                line_count = 0
                comment_ratio = 0.0
                string_literal_count = 0
                variable_count = 0
                import_count = 0
                function_depth = 1
                code_complexity = 1.0
            
            # Vulnerability pattern features
            syntax_patterns = self._extract_syntax_patterns(vuln)
            semantic_patterns = self._extract_semantic_patterns(vuln)
            historical_patterns = self._get_historical_patterns(vuln)
            
            return VulnerabilityFeatures(
                code_complexity=code_complexity,
                line_count=line_count,
                function_depth=function_depth,
                variable_count=variable_count,
                import_count=import_count,
                comment_ratio=comment_ratio,
                string_literal_count=string_literal_count,
                file_extension=file_extension,
                file_size=file_size,
                syntax_patterns=syntax_patterns,
                semantic_patterns=semantic_patterns,
                historical_patterns=historical_patterns
            )
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            # Return default features
            return VulnerabilityFeatures(
                code_complexity=1.0, line_count=0, function_depth=1,
                variable_count=0, import_count=0, comment_ratio=0.0,
                string_literal_count=0, file_extension='', file_size=0,
                syntax_patterns=[], semantic_patterns=[], historical_patterns={}
            )
    
    def _calculate_comment_ratio(self, lines: List[str], file_ext: str) -> float:
        """Calculate ratio of comment lines to total lines"""
        if not lines:
            return 0.0
            
        comment_prefixes = {
            '.py': ['#'],
            '.js': ['//', '/*'],
            '.jsx': ['//', '/*'],
            '.ts': ['//', '/*'],
            '.tsx': ['//', '/*'],
            '.java': ['//', '/*'],
            '.c': ['//', '/*'],
            '.cpp': ['//', '/*'],
            '.go': ['//', '/*'],
            '.rs': ['//', '/*'],
        }
        
        prefixes = comment_prefixes.get(file_ext, ['#'])
        comment_lines = 0
        
        for line in lines:
            stripped = line.strip()
            if any(stripped.startswith(prefix) for prefix in prefixes):
                comment_lines += 1
                
        return comment_lines / len(lines) if lines else 0.0
    
    def _count_string_literals(self, code: str) -> int:
        """Count string literals in code"""
        import re
        # Simple string literal counting (single and double quotes)
        single_quotes = len(re.findall(r"'[^']*'", code))
        double_quotes = len(re.findall(r'"[^"]*"', code))
        return single_quotes + double_quotes
    
    def _estimate_variable_count(self, code: str, file_ext: str) -> int:
        """Estimate number of variable declarations"""
        import re
        
        patterns = {
            '.py': [r'\\b\\w+\\s*=', r'\\bdef\\s+\\w+', r'\\bclass\\s+\\w+'],
            '.js': [r'\\b(var|let|const)\\s+\\w+', r'\\bfunction\\s+\\w+'],
            '.java': [r'\\b(int|String|boolean|double|float)\\s+\\w+'],
            '.go': [r'\\bvar\\s+\\w+', r'\\w+\\s*:='],
        }
        
        file_patterns = patterns.get(file_ext, [r'\\b\\w+\\s*='])
        count = 0
        
        for pattern in file_patterns:
            count += len(re.findall(pattern, code, re.IGNORECASE))
            
        return count
    
    def _count_imports(self, code: str, file_ext: str) -> int:
        """Count import statements"""
        import re
        
        patterns = {
            '.py': [r'^\\s*import\\s+', r'^\\s*from\\s+.*import'],
            '.js': [r'import\\s+.*from', r'require\\s*\\('],
            '.java': [r'^\\s*import\\s+'],
            '.go': [r'^\\s*import\\s+'],
        }
        
        file_patterns = patterns.get(file_ext, [r'import'])
        count = 0
        
        for pattern in file_patterns:
            count += len(re.findall(pattern, code, re.MULTILINE | re.IGNORECASE))
            
        return count
    
    def _estimate_function_depth(self, code: str, file_ext: str) -> int:
        """Estimate maximum nesting depth"""
        lines = code.split('\\n')
        max_depth = 0
        current_depth = 0
        
        indent_chars = {'.py': ' ', '.yaml': ' ', '.yml': ' '}
        indent_char = indent_chars.get(file_ext, ' ')
        
        for line in lines:
            if not line.strip():
                continue
                
            # Count leading whitespace
            leading_spaces = len(line) - len(line.lstrip(indent_char))
            
            # Estimate depth (assuming 2 or 4 spaces per level)
            if indent_char == ' ':
                estimated_depth = leading_spaces // 2 if leading_spaces > 0 else 0
            else:
                estimated_depth = leading_spaces
                
            max_depth = max(max_depth, estimated_depth)
            
        return max(max_depth, 1)
    
    def _estimate_complexity(self, code: str, file_ext: str) -> float:
        """Estimate code complexity based on control structures"""
        import re
        
        complexity_patterns = {
            '.py': [r'\\bif\\b', r'\\bfor\\b', r'\\bwhile\\b', r'\\btry\\b', r'\\bexcept\\b'],
            '.js': [r'\\bif\\b', r'\\bfor\\b', r'\\bwhile\\b', r'\\btry\\b', r'\\bcatch\\b'],
            '.java': [r'\\bif\\b', r'\\bfor\\b', r'\\bwhile\\b', r'\\btry\\b', r'\\bcatch\\b'],
            '.go': [r'\\bif\\b', r'\\bfor\\b', r'\\bswitch\\b', r'\\bselect\\b'],
        }
        
        patterns = complexity_patterns.get(file_ext, [r'\\bif\\b', r'\\bfor\\b', r'\\bwhile\\b'])
        complexity = 1.0  # Base complexity
        
        for pattern in patterns:
            matches = len(re.findall(pattern, code, re.IGNORECASE))
            complexity += matches * 0.5
            
        return min(complexity, 10.0)  # Cap at 10
    
    def _extract_syntax_patterns(self, vuln: Dict[str, Any]) -> List[str]:
        """Extract syntax patterns from vulnerability"""
        patterns = []
        
        vuln_type = vuln.get('vulnerability_type', '')
        code_snippet = vuln.get('code_snippet', '')
        
        # Pattern extraction based on vulnerability type
        if 'sql_injection' in vuln_type:
            patterns.extend(['string_concatenation', 'sql_query', 'user_input'])
        elif 'command_injection' in vuln_type:
            patterns.extend(['system_call', 'user_input', 'shell_execution'])
        elif 'xss' in vuln_type:
            patterns.extend(['html_output', 'user_input', 'dom_manipulation'])
        elif 'hardcoded_secrets' in vuln_type:
            patterns.extend(['string_literal', 'assignment', 'credential_pattern'])
            
        # Code pattern analysis
        if code_snippet:
            if '+' in code_snippet:
                patterns.append('string_concatenation')
            if '(' in code_snippet and ')' in code_snippet:
                patterns.append('function_call')
            if '=' in code_snippet:
                patterns.append('assignment')
                
        return list(set(patterns))
    
    def _extract_semantic_patterns(self, vuln: Dict[str, Any]) -> List[str]:
        """Extract semantic patterns from vulnerability"""
        patterns = []
        
        title = vuln.get('title', '').lower()
        description = vuln.get('description', '').lower()
        
        # Semantic pattern mapping
        semantic_keywords = {
            'data_flow': ['input', 'output', 'flow', 'data', 'user'],
            'authentication': ['auth', 'login', 'password', 'token', 'session'],
            'authorization': ['permission', 'access', 'role', 'privilege'],
            'encryption': ['crypto', 'encrypt', 'hash', 'cipher', 'key'],
            'validation': ['validate', 'sanitize', 'check', 'verify'],
            'network': ['http', 'url', 'request', 'response', 'network'],
        }
        
        text = f"{title} {description}"
        for pattern, keywords in semantic_keywords.items():
            if any(keyword in text for keyword in keywords):
                patterns.append(pattern)
                
        return patterns
    
    def _get_historical_patterns(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Get historical patterns for this vulnerability type"""
        # This would connect to a historical database in a real implementation
        return {
            'frequency': 1.0,
            'false_positive_rate': 0.1,
            'severity_distribution': {'high': 0.3, 'medium': 0.5, 'low': 0.2},
            'common_contexts': []
        }


class MLVulnerabilityAnalyzer:
    """ML-powered vulnerability analysis and prediction"""
    
    def __init__(self, model_dir: str = None):
        self.model_dir = model_dir or os.path.join(os.path.dirname(__file__), '..', 'ml_models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        self.feature_extractor = VulnerabilityFeatureExtractor()
        self.logger = logging.getLogger(__name__)
        
        # ML models
        self.false_positive_model = None
        self.risk_prediction_model = None
        self.anomaly_detector = None
        self.feature_scaler = None
        
        # Vector storage for semantic analysis
        self.tfidf_vectorizer = None
        
        # Initialize models
        self._load_or_train_models()
    
    def _load_or_train_models(self):
        """Load existing models or train new ones"""
        if not HAS_ML_LIBS:
            self.logger.warning("ML libraries not available. Using rule-based analysis.")
            return
            
        try:
            # Try to load existing models
            if self._load_models():
                self.logger.info("Loaded existing ML models")
            else:
                # Train new models with synthetic data
                self.logger.info("Training new ML models")
                self._train_models_with_synthetic_data()
                self._save_models()
                
        except Exception as e:
            self.logger.error(f"Error initializing ML models: {e}")
    
    def _load_models(self) -> bool:
        """Load models from disk"""
        model_files = {
            'false_positive_model.pkl': 'false_positive_model',
            'risk_prediction_model.pkl': 'risk_prediction_model', 
            'anomaly_detector.pkl': 'anomaly_detector',
            'feature_scaler.pkl': 'feature_scaler',
            'tfidf_vectorizer.pkl': 'tfidf_vectorizer'
        }
        
        try:
            for filename, attr_name in model_files.items():
                filepath = os.path.join(self.model_dir, filename)
                if os.path.exists(filepath):
                    with open(filepath, 'rb') as f:
                        setattr(self, attr_name, pickle.load(f))
                else:
                    return False
            return True
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
            return False
    
    def _save_models(self):
        """Save models to disk"""
        models = {
            'false_positive_model.pkl': self.false_positive_model,
            'risk_prediction_model.pkl': self.risk_prediction_model,
            'anomaly_detector.pkl': self.anomaly_detector,
            'feature_scaler.pkl': self.feature_scaler,
            'tfidf_vectorizer.pkl': self.tfidf_vectorizer
        }
        
        for filename, model in models.items():
            if model is not None:
                filepath = os.path.join(self.model_dir, filename)
                with open(filepath, 'wb') as f:
                    pickle.dump(model, f)
    
    def _train_models_with_synthetic_data(self):
        """Train models using synthetic vulnerability data"""
        if not HAS_ML_LIBS:
            return
            
        # Generate synthetic training data
        training_data = self._generate_synthetic_training_data()
        
        if not training_data:
            self.logger.warning("No training data available")
            return
        
        # Convert to DataFrame for easier handling
        df = pd.DataFrame(training_data)
        
        # Prepare features
        feature_columns = [
            'code_complexity', 'line_count', 'function_depth', 'variable_count',
            'import_count', 'comment_ratio', 'string_literal_count', 'file_size'
        ]
        
        X = df[feature_columns].fillna(0)
        
        # Train false positive classifier
        y_fp = df['is_false_positive']
        self.false_positive_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.false_positive_model.fit(X, y_fp)
        
        # Train risk prediction model
        y_risk = df['risk_score']
        self.risk_prediction_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.risk_prediction_model.fit(X, (y_risk > 5).astype(int))  # Binary high/low risk
        
        # Train anomaly detector
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.anomaly_detector.fit(X)
        
        # Train feature scaler
        self.feature_scaler = StandardScaler()
        self.feature_scaler.fit(X)
        
        # Train TF-IDF vectorizer for text analysis
        text_data = df['description'].fillna('').tolist()
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.tfidf_vectorizer.fit(text_data)
        
        self.logger.info("Successfully trained ML models")
    
    def _generate_synthetic_training_data(self) -> List[Dict[str, Any]]:
        """Generate synthetic training data for model training"""
        synthetic_data = []
        
        # Vulnerability types and their characteristics
        vuln_types = {
            'sql_injection': {'base_risk': 8, 'fp_rate': 0.15},
            'command_injection': {'base_risk': 9, 'fp_rate': 0.10},
            'xss': {'base_risk': 7, 'fp_rate': 0.20},
            'hardcoded_secrets': {'base_risk': 6, 'fp_rate': 0.25},
            'weak_crypto': {'base_risk': 5, 'fp_rate': 0.30},
        }
        
        import random
        random.seed(42)
        
        for vuln_type, props in vuln_types.items():
            for i in range(200):  # Generate 200 samples per type
                # Generate realistic feature values
                complexity = random.uniform(1.0, 8.0)
                line_count = random.randint(10, 1000)
                function_depth = random.randint(1, 6)
                variable_count = random.randint(5, 50)
                import_count = random.randint(1, 20)
                comment_ratio = random.uniform(0.0, 0.5)
                string_literal_count = random.randint(0, 30)
                file_size = random.randint(100, 50000)
                
                # Risk score influenced by complexity and type
                base_risk = props['base_risk']
                risk_score = base_risk + (complexity - 4) + random.uniform(-2, 2)
                risk_score = max(1, min(10, risk_score))
                
                # False positive probability influenced by complexity and comment ratio
                fp_prob = props['fp_rate']
                if complexity < 2:
                    fp_prob *= 2  # Simple code more likely to be false positive
                if comment_ratio > 0.3:
                    fp_prob *= 0.5  # Well-documented code less likely to be false positive
                    
                is_false_positive = random.random() < fp_prob
                
                synthetic_data.append({
                    'vulnerability_type': vuln_type,
                    'code_complexity': complexity,
                    'line_count': line_count,
                    'function_depth': function_depth,
                    'variable_count': variable_count,
                    'import_count': import_count,
                    'comment_ratio': comment_ratio,
                    'string_literal_count': string_literal_count,
                    'file_size': file_size,
                    'risk_score': risk_score,
                    'is_false_positive': is_false_positive,
                    'description': f"Sample {vuln_type} vulnerability with complexity {complexity:.1f}"
                })
        
        return synthetic_data
    
    def analyze_vulnerability_with_ml(self, vuln: Dict[str, Any], code_content: str = None) -> MLPrediction:
        """Analyze vulnerability using ML models"""
        try:
            # Extract features
            features = self.feature_extractor.extract_features_from_vulnerability(vuln, code_content)
            
            # Convert to feature vector
            feature_vector = self._features_to_vector(features)
            
            # Get predictions
            confidence_score = self._predict_confidence(feature_vector, vuln)
            is_false_positive = self._predict_false_positive(feature_vector)
            risk_score = self._predict_risk_score(feature_vector, vuln)
            prediction_reason = self._generate_prediction_reason(features, vuln)
            
            return MLPrediction(
                vulnerability_id=vuln.get('id', 'unknown'),
                confidence_score=confidence_score,
                is_false_positive=is_false_positive,
                risk_score=risk_score,
                prediction_reason=prediction_reason,
                model_version="1.0",
                features_used=list(asdict(features).keys())
            )
            
        except Exception as e:
            self.logger.error(f"Error in ML analysis: {e}")
            # Return default prediction
            return MLPrediction(
                vulnerability_id=vuln.get('id', 'unknown'),
                confidence_score=0.5,
                is_false_positive=False,
                risk_score=5.0,
                prediction_reason="ML analysis failed, using default values",
                model_version="1.0",
                features_used=[]
            )
    
    def _features_to_vector(self, features: VulnerabilityFeatures) -> Any:
        """Convert features to numerical vector"""
        if not HAS_ML_LIBS:
            return np.array([1.0])
            
        feature_dict = asdict(features)
        
        # Extract numerical features
        numerical_features = [
            feature_dict['code_complexity'],
            feature_dict['line_count'],
            feature_dict['function_depth'],
            feature_dict['variable_count'],
            feature_dict['import_count'],
            feature_dict['comment_ratio'],
            feature_dict['string_literal_count'],
            feature_dict['file_size']
        ]
        
        return np.array(numerical_features).reshape(1, -1)
    
    def _predict_confidence(self, feature_vector: Any, vuln: Dict[str, Any]) -> float:
        """Predict confidence score for vulnerability"""
        if not HAS_ML_LIBS or self.false_positive_model is None:
            # Rule-based confidence
            return self._rule_based_confidence(vuln)
        
        try:
            # Use false positive probability as inverse confidence
            fp_prob = self.false_positive_model.predict_proba(feature_vector)[0][1]
            confidence = 1.0 - fp_prob
            return max(0.1, min(0.99, confidence))
        except:
            return self._rule_based_confidence(vuln)
    
    def _predict_false_positive(self, feature_vector: Any) -> bool:
        """Predict if vulnerability is a false positive"""
        if not HAS_ML_LIBS or self.false_positive_model is None:
            return False
        
        try:
            prediction = self.false_positive_model.predict(feature_vector)[0]
            return bool(prediction)
        except:
            return False
    
    def _predict_risk_score(self, feature_vector: Any, vuln: Dict[str, Any]) -> float:
        """Predict risk score for vulnerability"""
        if not HAS_ML_LIBS or self.risk_prediction_model is None:
            # Rule-based risk scoring
            return self._rule_based_risk_score(vuln)
        
        try:
            # Get high-risk probability and convert to score
            high_risk_prob = self.risk_prediction_model.predict_proba(feature_vector)[0][1]
            base_score = 5.0 + (high_risk_prob * 5.0)  # Scale to 5-10 range
            
            # Adjust based on vulnerability type
            vuln_type = vuln.get('vulnerability_type', '')
            type_modifiers = {
                'command_injection': 1.2,
                'sql_injection': 1.1,
                'unsafe_reflection': 1.1,
                'hardcoded_secrets': 0.9,
                'weak_crypto': 0.8
            }
            
            modifier = type_modifiers.get(vuln_type, 1.0)
            risk_score = base_score * modifier
            
            return max(1.0, min(10.0, risk_score))
        except:
            return self._rule_based_risk_score(vuln)
    
    def _rule_based_confidence(self, vuln: Dict[str, Any]) -> float:
        """Rule-based confidence scoring when ML is not available"""
        confidence = 0.7  # Base confidence
        
        vuln_type = vuln.get('vulnerability_type', '')
        severity = vuln.get('severity', 'medium')
        
        # High-confidence vulnerability types
        if vuln_type in ['sql_injection', 'command_injection', 'hardcoded_secrets']:
            confidence += 0.2
        
        # Severity adjustment
        if severity == 'critical':
            confidence += 0.1
        elif severity == 'low':
            confidence -= 0.1
        
        return max(0.1, min(0.95, confidence))
    
    def _rule_based_risk_score(self, vuln: Dict[str, Any]) -> float:
        """Rule-based risk scoring when ML is not available"""
        base_scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0,
            'info': 1.0
        }
        
        severity = vuln.get('severity', 'medium')
        return base_scores.get(severity, 5.0)
    
    def _generate_prediction_reason(self, features: VulnerabilityFeatures, vuln: Dict[str, Any]) -> str:
        """Generate human-readable explanation for the prediction"""
        reasons = []
        
        # Code complexity factors
        if features.code_complexity > 6:
            reasons.append("high code complexity increases confidence")
        elif features.code_complexity < 2:
            reasons.append("low complexity may indicate false positive")
        
        # Documentation factors
        if features.comment_ratio > 0.3:
            reasons.append("well-documented code reduces false positive risk")
        elif features.comment_ratio < 0.1:
            reasons.append("poor documentation increases risk")
        
        # File size factors
        if features.file_size > 10000:
            reasons.append("large file size suggests complex functionality")
        
        # Vulnerability type factors
        vuln_type = vuln.get('vulnerability_type', '')
        if vuln_type in ['sql_injection', 'command_injection']:
            reasons.append("high-impact vulnerability type")
        
        if not reasons:
            reasons.append("standard risk assessment applied")
        
        return "; ".join(reasons)


# Global ML analyzer instance
ml_analyzer = None

def get_ml_analyzer() -> MLVulnerabilityAnalyzer:
    """Get global ML analyzer instance"""
    global ml_analyzer
    if ml_analyzer is None:
        ml_analyzer = MLVulnerabilityAnalyzer()
    return ml_analyzer

def analyze_vulnerabilities_with_ml(vulnerabilities: List[Dict[str, Any]], 
                                  code_contents: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """Analyze vulnerabilities using ML models"""
    analyzer = get_ml_analyzer()
    enhanced_vulnerabilities = []
    
    for vuln in vulnerabilities:
        # Get code content if available
        file_path = vuln.get('location', {}).get('file_path', '')
        code_content = code_contents.get(file_path) if code_contents else None
        
        # Get ML prediction
        ml_prediction = analyzer.analyze_vulnerability_with_ml(vuln, code_content)
        
        # Enhance vulnerability with ML insights
        enhanced_vuln = vuln.copy()
        enhanced_vuln['ml_analysis'] = {
            'confidence_score': ml_prediction.confidence_score,
            'is_false_positive': ml_prediction.is_false_positive,
            'ml_risk_score': ml_prediction.risk_score,
            'prediction_reason': ml_prediction.prediction_reason,
            'model_version': ml_prediction.model_version
        }
        
        # Update confidence and risk based on ML
        enhanced_vuln['confidence'] = ml_prediction.confidence_score
        if 'risk_score' in enhanced_vuln:
            # Blend original and ML risk scores
            original_risk = enhanced_vuln['risk_score']
            ml_risk = ml_prediction.risk_score
            enhanced_vuln['risk_score'] = (original_risk + ml_risk) / 2
        else:
            enhanced_vuln['risk_score'] = ml_prediction.risk_score
        
        enhanced_vulnerabilities.append(enhanced_vuln)
    
    return enhanced_vulnerabilities