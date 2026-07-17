#!/usr/bin/env python3
"""
Predictive ML Scoring Module
Learns from burn-test results to predict which SNI hosts will work
Uses simple but effective algorithms: Decision Tree + Logistic Regression
"""

import json
import os
import time
import pickle
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

# ============ CONFIG ============

DATA_DIR = os.path.expanduser("~/snihost_pro/ml_data")
MODEL_FILE = os.path.join(DATA_DIR, "sni_model.pkl")
FEATURE_LOG = os.path.join(DATA_DIR, "feature_log.json")
BURN_LOG = os.path.expanduser("~/snihost_pro/burn_test_log.json")

os.makedirs(DATA_DIR, exist_ok=True)

# ============ FEATURE EXTRACTION ============

def extract_features(scan_result):
    """
    Extract numerical features from a scan result
    These features are used to train the model
    """
    features = {}
    
    # 1. Category encoding
    category = scan_result.get('category', 'other')
    category_scores = {
        'government': 5, 'education': 4, 'health': 3,
        'social': 2, 'cdn': 1, 'other': 0
    }
    features['category_score'] = category_scores.get(category, 0)
    
    # 2. TLS version
    tls_version = scan_result.get('tls_version', '')
    tls_scores = {
        'TLSv1.3': 3, 'TLSv1.2': 2, 'TLSv1.1': 1, 'TLSv1.0': 0, None: -1
    }
    features['tls_version_score'] = tls_scores.get(tls_version, -1)
    
    # 3. HTTP status
    status = scan_result.get('http_status', 0)
    if status == 200:
        features['http_status_score'] = 3
    elif status in (301, 302):
        features['http_status_score'] = 2
    elif status in (403, 401):
        features['http_status_score'] = 1
    else:
        features['http_status_score'] = 0
    
    # 4. Response time (faster = better)
    tls_time = scan_result.get('tls_time_ms', 9999)
    if tls_time < 50:
        features['speed_score'] = 3
    elif tls_time < 100:
        features['speed_score'] = 2
    elif tls_time < 500:
        features['speed_score'] = 1
    else:
        features['speed_score'] = 0
    
    # 5. CDN detection
    cdn = scan_result.get('cdn', None)
    features['has_cdn'] = 1 if cdn else 0
    cdn_scores = {
        'cloudflare': 3, 'aws_cloudfront': 2, 'fastly': 2,
        'akamai': 2, None: 0
    }
    features['cdn_score'] = cdn_scores.get(cdn, 0)
    
    # 6. DNS stability
    ipv4_count = len(scan_result.get('ipv4', []))
    features['single_ip'] = 1 if ipv4_count == 1 else 0
    
    # 7. Has reverse DNS
    features['has_reverse_dns'] = 1 if scan_result.get('reverse_dns') else 0
    
    # 8. In personal DB
    features['in_personal_db'] = 1 if scan_result.get('in_personal_db') else 0
    
    # 9. TLS success
    features['tls_success'] = 1 if scan_result.get('tls_success') else 0
    
    # 10. Score from heuristic (our existing score)
    features['heuristic_score'] = scan_result.get('score', 0)
    
    return features

# ============ SIMPLE ML MODEL (No external libraries needed) ============

class SimpleSNIClassifier:
    """
    A simple but effective classifier using weighted rules
    No sklearn needed — pure Python
    Learns weights from burn-test results
    """
    
    def __init__(self):
        self.weights = {
            'category_score': 5.0,
            'tls_version_score': 3.0,
            'http_status_score': 2.0,
            'speed_score': 1.0,
            'has_cdn': 2.0,
            'cdn_score': 1.5,
            'single_ip': 1.0,
            'has_reverse_dns': 0.5,
            'in_personal_db': 10.0,  # HUGE weight
            'tls_success': 5.0,
            'heuristic_score': 0.3
        }
        self.bias = -10.0
        self.trained = False
        self.training_data = []
    
    def predict_score(self, features):
        """
        Predict success probability (0-100)
        """
        score = self.bias
        
        for feature_name, weight in self.weights.items():
            feature_value = features.get(feature_name, 0)
            score += feature_value * weight
        
        # Convert to probability-like score (0-100)
        probability = max(0, min(100, score * 2))
        
        return probability
    
    def train(self, training_data):
        """
        Train the model on burn-test results
        
        training_data: list of dicts with:
            - features: dict of feature values
            - worked: bool (True if host worked)
        """
        if not training_data:
            print(f"{Fore.YELLOW}No training data available{Style.RESET_ALL}")
            return
        
        self.training_data = training_data
        
        # Simple perceptron-style weight update
        learning_rate = 0.1
        
        for _ in range(100):  # 100 epochs
            for sample in training_data:
                features = sample['features']
                actual = 1 if sample['worked'] else 0
                
                predicted = self.predict_score(features) / 100.0  # Normalize to 0-1
                error = actual - predicted
                
                # Update weights
                for feature_name in self.weights:
                    feature_value = features.get(feature_name, 0)
                    self.weights[feature_name] += learning_rate * error * feature_value
                
                # Update bias
                self.bias += learning_rate * error
        
        self.trained = True
        
        # Print learned weights
        print(f"\n{Fore.GREEN}=== Model Trained ==={Style.RESET_ALL}")
        print(f"Training samples: {len(training_data)}")
        for name, weight in sorted(self.weights.items(), key=lambda x: -abs(x[1])):
            print(f"  {name}: {weight:.3f}")
    
    def save(self, filepath):
        """Save model to file"""
        data = {
            'weights': self.weights,
            'bias': self.bias,
            'trained': self.trained,
            'training_data_count': len(self.training_data)
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load(self, filepath):
        """Load model from file"""
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                data = json.load(f)
            self.weights = data.get('weights', self.weights)
            self.bias = data.get('bias', self.bias)
            self.trained = data.get('trained', False)
            return True
        return False

# ============ TRAINING DATA MANAGEMENT ============

def load_burn_test_history():
    """
    Load all burn-test results from history
    """
    if not os.path.exists(BURN_LOG):
        return []
    
    try:
        with open(BURN_LOG, 'r') as f:
            return json.load(f)
    except:
        return []

def load_feature_log():
    """
    Load feature log that maps scan results to features
    """
    if not os.path.exists(FEATURE_LOG):
        return {}
    
    try:
        with open(FEATURE_LOG, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_feature_log(feature_log):
    """Save feature log"""
    with open(FEATURE_LOG, 'w') as f:
        json.dump(feature_log, f, indent=2)

def build_training_data():
    """
    Build training data from burn-test history and feature log
    """
    burn_history = load_burn_test_history()
    feature_log = load_feature_log()
    
    training_data = []
    
    for entry in burn_history:
        domain = entry.get('domain', '')
        worked = entry.get('worked', False)
        
        # Find features for this domain
        domain_features = feature_log.get(domain)
        
        if domain_features:
            training_data.append({
                'domain': domain,
                'features': domain_features,
                'worked': worked
            })
    
    return training_data

def log_scan_features(domain, features):
    """Log features for a domain after scanning"""
    feature_log = load_feature_log()
    feature_log[domain] = features
    save_feature_log(feature_log)

# ============ PREDICTION INTERFACE ============

class SNIPredictor:
    """
    Main interface for predicting SNI host success
    """
    
    def __init__(self):
        self.model = SimpleSNIClassifier()
        self.model.load(MODEL_FILE)
    
    def predict(self, scan_result):
        """
        Predict success probability for a scan result
        
        Returns: dict with prediction details
        """
        features = extract_features(scan_result)
        
        # Log features for future training
        domain = scan_result.get('domain', '')
        if domain:
            log_scan_features(domain, features)
        
        # Get prediction
        probability = self.model.predict_score(features)
        
        # Determine confidence level
        if probability >= 70:
            confidence = 'HIGH'
            color = Fore.GREEN
        elif probability >= 40:
            confidence = 'MEDIUM'
            color = Fore.YELLOW
        else:
            confidence = 'LOW'
            color = Fore.RED
        
        # Feature importance breakdown
        feature_scores = {}
        for name, weight in self.model.weights.items():
            feature_scores[name] = features.get(name, 0) * weight
        
        return {
            'domain': domain,
            'predicted_probability': round(probability, 1),
            'confidence_level': confidence,
            'features': features,
            'feature_scores': feature_scores,
            'model_trained': self.model.trained,
            'top_positive_features': sorted(
                [(k, v) for k, v in feature_scores.items() if v > 0],
                key=lambda x: -x[1]
            )[:5],
            'top_negative_features': sorted(
                [(k, v) for k, v in feature_scores.items() if v < 0],
                key=lambda x: x[1]
            )[:3]
        }
    
    def train_from_history(self):
        """Train model on all burn-test history"""
        training_data = build_training_data()
        
        if len(training_data) < 5:
            print(f"{Fore.YELLOW}Need at least 5 burn-test results to train. You have {len(training_data)}.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Run more burn tests and try again.{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.CYAN}Training model on {len(training_data)} samples...{Style.RESET_ALL}")
        self.model.train(training_data)
        self.model.save(MODEL_FILE)
        
        # Show accuracy on training data
        correct = 0
        for sample in training_data:
            pred = self.model.predict_score(sample['features'])
            predicted_worked = pred >= 50
            actual_worked = sample['worked']
            if predicted_worked == actual_worked:
                correct += 1
        
        accuracy = (correct / len(training_data)) * 100
        print(f"\n{Fore.GREEN}Training accuracy: {accuracy:.1f}%{Style.RESET_ALL}")
        
        return True
    
    def rank_candidates(self, scan_results):
        """
        Rank scan results by predicted probability
        Returns sorted list with predictions
        """
        ranked = []
        
        for result in scan_results:
            prediction = self.predict(result)
            ranked.append({
                'scan_result': result,
                'prediction': prediction
            })
        
        # Sort by predicted probability (highest first)
        ranked.sort(key=lambda x: x['prediction']['predicted_probability'], reverse=True)
        
        return ranked

# ============ MAIN INTERFACE ============

def display_prediction(prediction):
    """Pretty print a prediction"""
    p = prediction
    color = Fore.GREEN if p['predicted_probability'] >= 70 else Fore.YELLOW if p['predicted_probability'] >= 40 else Fore.RED
    
    print(f"\n{color}{'='*50}{Style.RESET_ALL}")
    print(f"{color}  Prediction for: {p['domain']}{Style.RESET_ALL}")
    print(f"{color}{'='*50}{Style.RESET_ALL}")
    print(f"  Success Probability: {color}{p['predicted_probability']}%{Style.RESET_ALL}")
    print(f"  Confidence: {p['confidence_level']}")
    print(f"  Model Trained: {'✅' if p['model_trained'] else '❌'}")
    
    print(f"\n  Feature Breakdown:")
    for feature, score in p['top_positive_features']:
        print(f"    + {feature}: +{score:.2f}")
    
    for feature, score in p['top_negative_features']:
        print(f"    - {feature}: {score:.2f}")
    
    print(f"\n  Recommendation: ", end="")
    if p['predicted_probability'] >= 70:
        print(f"{Fore.GREEN}HIGH PRIORITY — Test this host first!{Style.RESET_ALL}")
    elif p['predicted_probability'] >= 40:
        print(f"{Fore.YELLOW}MEDIUM PRIORITY — Worth testing{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}LOW PRIORITY — Skip unless desperate{Style.RESET_ALL}")

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Predictive ML Scoring{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Learns from your burn-test results{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    predictor = SNIPredictor()
    
    print("Select mode:")
    print("1. Train model from burn-test history")
    print("2. Predict single host (enter features manually)")
    print("3. Show model status")
    print("4. Reset model (clear all training)")
    
    choice = input("\nChoice (1-4): ").strip()
    
    if choice == '1':
        success = predictor.train_from_history()
        if success:
            print(f"\n{Fore.GREEN}Model trained and saved!{Style.RESET_ALL}")
    
    elif choice == '2':
        print(f"\n{Fore.YELLOW}Enter scan result features:{Style.RESET_ALL}")
        
        scan_result = {
            'domain': input("Domain: ").strip(),
            'category': input("Category (government/education/health/social/cdn/other): ").strip(),
            'tls_version': input("TLS version (TLSv1.3/TLSv1.2/TLSv1.1/TLSv1.0): ").strip(),
            'http_status': int(input("HTTP status (200/301/302/403/0): ").strip() or 0),
            'tls_time_ms': float(input("TLS response time (ms): ").strip() or 9999),
            'cdn': input("CDN (cloudflare/aws_cloudfront/fastly/akamai/none): ").strip() or None,
            'ipv4': input("IPv4 addresses (comma-separated): ").strip().split(','),
            'reverse_dns': input("Reverse DNS (or empty): ").strip() or None,
            'in_personal_db': input("In personal DB? (y/n): ").strip().lower() == 'y',
            'tls_success': True,
            'score': int(input("Heuristic score (0-100): ").strip() or 0)
        }
        
        prediction = predictor.predict(scan_result)
        display_prediction(prediction)
    
    elif choice == '3':
        history = load_burn_test_history()
        feature_log = load_feature_log()
        
        print(f"\n{Fore.CYAN}=== Model Status ==={Style.RESET_ALL}")
        print(f"Burn-test entries: {len(history)}")
        print(f"Feature-logged domains: {len(feature_log)}")
        print(f"Model trained: {'✅' if predictor.model.trained else '❌'}")
        print(f"Model file exists: {'✅' if os.path.exists(MODEL_FILE) else '❌'}")
        
        if predictor.model.trained:
            print(f"\nCurrent weights:")
            for name, weight in sorted(predictor.model.weights.items(), key=lambda x: -abs(x[1])):
                print(f"  {name}: {weight:.3f}")
    
    elif choice == '4':
        confirm = input(f"{Fore.RED}Are you sure? This deletes all training data. (yes/no): {Style.RESET_ALL}").strip().lower()
        if confirm == 'yes':
            for f in [MODEL_FILE, FEATURE_LOG]:
                if os.path.exists(f):
                    os.remove(f)
            print(f"{Fore.GREEN}Model reset complete.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Cancelled.{Style.RESET_ALL}")
    
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
