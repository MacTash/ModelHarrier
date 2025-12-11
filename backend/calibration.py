"""
Risk Score Calibration

Implements calibration curves and risk bucketing to validate
that risk scores correspond to actual malicious likelihood.
"""
import json
from typing import Optional
from dataclasses import dataclass
import numpy as np

# Optional sklearn imports
try:
    from sklearn.calibration import calibration_curve
    from sklearn.isotonic import IsotonicRegression
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


@dataclass
class CalibrationResult:
    """Result of calibration analysis"""
    is_calibrated: bool
    mean_error: float  # Average difference between predicted and actual
    max_error: float
    buckets: list[dict]  # Risk buckets with actual malicious rates
    recommendations: list[str]


class RiskCalibrator:
    """
    Calibrates risk scores against actual outcomes.
    
    Validates: Does a "risk score 8/10" correspond to ~80% malicious likelihood?
    """
    
    def __init__(self):
        self.isotonic_model: Optional[IsotonicRegression] = None
        self.calibration_data = []
    
    def add_sample(self, predicted_score: float, actual_malicious: bool):
        """Add a calibration sample"""
        self.calibration_data.append({
            'predicted': predicted_score,
            'actual': 1 if actual_malicious else 0
        })
    
    def load_from_telemetry(self, telemetry_data: list[dict]):
        """Load calibration data from telemetry records"""
        self.calibration_data = []
        
        for record in telemetry_data:
            # Normalize score to 0-1
            score = record.get('aieye_score', 0)
            if isinstance(score, (int, float)):
                predicted = min(1.0, max(0.0, score / 100))
            else:
                continue
            
            # Determine if actually malicious based on consensus
            label = record.get('label', '')
            actual = 1 if label in ('CRITICAL', 'HIGH') else 0
            
            # Adjust for FP/FN
            if record.get('is_false_positive'):
                actual = 0  # Was flagged but actually safe
            if record.get('is_false_negative'):
                actual = 1  # Was missed but actually malicious
            
            self.calibration_data.append({
                'predicted': predicted,
                'actual': actual
            })
    
    def compute_calibration(self, n_bins: int = 10) -> CalibrationResult:
        """
        Compute calibration curve and bucket analysis.
        """
        if len(self.calibration_data) < 20:
            return CalibrationResult(
                is_calibrated=False,
                mean_error=0.0,
                max_error=0.0,
                buckets=[],
                recommendations=['Insufficient data for calibration (need 20+ samples)']
            )
        
        predictions = np.array([d['predicted'] for d in self.calibration_data])
        actuals = np.array([d['actual'] for d in self.calibration_data])
        
        # Create risk buckets
        buckets = []
        bucket_errors = []
        
        for i in range(n_bins):
            lower = i / n_bins
            upper = (i + 1) / n_bins
            
            mask = (predictions >= lower) & (predictions < upper)
            bucket_preds = predictions[mask]
            bucket_actuals = actuals[mask]
            
            if len(bucket_preds) > 0:
                expected_rate = (lower + upper) / 2  # Midpoint
                actual_rate = bucket_actuals.mean()
                error = abs(expected_rate - actual_rate)
                bucket_errors.append(error)
                
                buckets.append({
                    'range': f'{int(lower*10)}-{int(upper*10)}/10',
                    'samples': int(len(bucket_preds)),
                    'expected_malicious_rate': round(expected_rate * 100, 1),
                    'actual_malicious_rate': round(actual_rate * 100, 1),
                    'error': round(error * 100, 1),
                    'well_calibrated': error < 0.15  # <15% error
                })
        
        mean_error = np.mean(bucket_errors) if bucket_errors else 0.0
        max_error = np.max(bucket_errors) if bucket_errors else 0.0
        
        # Generate recommendations
        recommendations = []
        
        # Find systematic over/under-prediction
        low_buckets = [b for b in buckets if b['expected_malicious_rate'] <= 30]
        high_buckets = [b for b in buckets if b['expected_malicious_rate'] >= 70]
        
        if low_buckets:
            avg_error_low = np.mean([b['actual_malicious_rate'] - b['expected_malicious_rate'] for b in low_buckets])
            if avg_error_low > 10:
                recommendations.append(
                    f'Low scores are under-detecting: actual malicious rate is {abs(avg_error_low):.0f}% higher than expected'
                )
            elif avg_error_low < -10:
                recommendations.append(
                    f'Low scores are over-flagging: actual malicious rate is {abs(avg_error_low):.0f}% lower than expected'
                )
        
        if high_buckets:
            avg_error_high = np.mean([b['actual_malicious_rate'] - b['expected_malicious_rate'] for b in high_buckets])
            if avg_error_high < -10:
                recommendations.append(
                    f'High scores are over-confident: actual malicious rate is {abs(avg_error_high):.0f}% lower than expected'
                )
        
        # Check for problematic buckets
        problematic = [b for b in buckets if not b['well_calibrated'] and b['samples'] >= 5]
        for b in problematic[:3]:  # Top 3 problematic
            if b['actual_malicious_rate'] > b['expected_malicious_rate']:
                recommendations.append(
                    f"Bucket {b['range']}: Increase score sensitivity (missing {b['error']}% malicious)"
                )
            else:
                recommendations.append(
                    f"Bucket {b['range']}: Reduce score (over-flagging by {b['error']}%)"
                )
        
        if not recommendations:
            recommendations.append('Calibration looks good! Risk scores align with actual malicious likelihood.')
        
        is_calibrated = mean_error < 0.15 and max_error < 0.25
        
        return CalibrationResult(
            is_calibrated=is_calibrated,
            mean_error=round(mean_error * 100, 1),
            max_error=round(max_error * 100, 1),
            buckets=buckets,
            recommendations=recommendations
        )
    
    def fit_isotonic(self):
        """Fit isotonic regression for score adjustment"""
        if not SKLEARN_AVAILABLE or len(self.calibration_data) < 20:
            return False
        
        predictions = np.array([d['predicted'] for d in self.calibration_data])
        actuals = np.array([d['actual'] for d in self.calibration_data])
        
        self.isotonic_model = IsotonicRegression(out_of_bounds='clip')
        self.isotonic_model.fit(predictions, actuals)
        
        return True
    
    def adjust_score(self, raw_score: float) -> float:
        """
        Adjust a raw score using isotonic calibration.
        Returns the calibrated score (0-1 probability of malicious).
        """
        if self.isotonic_model is None:
            return raw_score
        
        normalized = min(1.0, max(0.0, raw_score / 100))
        calibrated = self.isotonic_model.predict([normalized])[0]
        
        return calibrated


# Singleton
calibrator = RiskCalibrator()


def get_calibration_summary(telemetry_data: list[dict]) -> dict:
    """
    Get calibration summary for dashboard.
    """
    calibrator.load_from_telemetry(telemetry_data)
    result = calibrator.compute_calibration()
    
    return {
        'is_calibrated': result.is_calibrated,
        'mean_error': result.mean_error,
        'max_error': result.max_error,
        'buckets': result.buckets,
        'recommendations': result.recommendations,
        'sample_count': len(calibrator.calibration_data)
    }
