"""
Telemetry Collection and Statistical Analysis

Stores scan results and computes:
- False-positive/false-negative patterns
- Opcode frequency distributions
- PCA-based anomaly detection
- Distribution shift alerts
"""
import json
import sqlite3
from dataclasses import dataclass
from typing import Optional
from pathlib import Path
import numpy as np

from config import TELEMETRY_DB, DATA_DIR

# Optional sklearn import
try:
    from sklearn.decomposition import PCA
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# All pickle opcodes for feature vector
ALL_OPCODES = [
    'MARK', 'STOP', 'POP', 'POP_MARK', 'DUP', 'FLOAT', 'INT', 'BININT',
    'BININT1', 'LONG', 'BININT2', 'NONE', 'PERSID', 'BINPERSID', 'REDUCE',
    'STRING', 'BINSTRING', 'SHORT_BINSTRING', 'UNICODE', 'BINUNICODE',
    'APPEND', 'BUILD', 'GLOBAL', 'DICT', 'EMPTY_DICT', 'APPENDS', 'GET',
    'BINGET', 'INST', 'LONG_BINGET', 'LIST', 'EMPTY_LIST', 'OBJ', 'PUT',
    'BINPUT', 'LONG_BINPUT', 'SETITEM', 'TUPLE', 'EMPTY_TUPLE', 'SETITEMS',
    'BINFLOAT', 'PROTO', 'NEWOBJ', 'EXT1', 'EXT2', 'EXT4', 'TUPLE1', 'TUPLE2',
    'TUPLE3', 'NEWTRUE', 'NEWFALSE', 'LONG1', 'LONG4', 'BINBYTES', 'SHORT_BINBYTES',
    'SHORT_BINUNICODE', 'BINUNICODE8', 'BINBYTES8', 'EMPTY_SET', 'ADDITEMS',
    'FROZENSET', 'NEWOBJ_EX', 'STACK_GLOBAL', 'MEMOIZE', 'FRAME', 'BYTEARRAY8',
    'NEXT_BUFFER', 'READONLY_BUFFER'
]


@dataclass
class ScanRecord:
    """A telemetry record for a scan"""
    file_hash: str
    timestamp: str
    label: str  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    file_size: int
    aieye_score: int
    consensus_score: Optional[int]
    is_false_positive: bool
    is_false_negative: bool
    has_reduce: bool
    has_global: bool
    dangerous_globals: int
    opcode_vector: str  # JSON array of opcode counts
    model_type: Optional[str]  # PEFT, Trainer, Unknown
    confidence: float


class TelemetryStore:
    """
    SQLite-backed telemetry storage and analysis.
    """
    
    def __init__(self, db_path: Path = TELEMETRY_DB):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema"""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                label TEXT NOT NULL,
                file_size INTEGER,
                aieye_score INTEGER,
                consensus_score INTEGER,
                is_false_positive BOOLEAN DEFAULT FALSE,
                is_false_negative BOOLEAN DEFAULT FALSE,
                has_reduce BOOLEAN DEFAULT FALSE,
                has_global BOOLEAN DEFAULT FALSE,
                dangerous_globals INTEGER DEFAULT 0,
                opcode_vector TEXT,
                model_type TEXT,
                confidence REAL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_label ON scans(label)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_hash ON scans(file_hash)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_fp ON scans(is_false_positive)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_fn ON scans(is_false_negative)
        ''')
        
        conn.commit()
        conn.close()
    
    def record_scan(self, record: ScanRecord):
        """Store a scan record"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scans (
                file_hash, timestamp, label, file_size, aieye_score,
                consensus_score, is_false_positive, is_false_negative,
                has_reduce, has_global, dangerous_globals, opcode_vector,
                model_type, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            record.file_hash, record.timestamp, record.label, record.file_size,
            record.aieye_score, record.consensus_score, record.is_false_positive,
            record.is_false_negative, record.has_reduce, record.has_global,
            record.dangerous_globals, record.opcode_vector, record.model_type,
            record.confidence
        ))
        
        conn.commit()
        conn.close()
    
    def get_stats(self) -> dict:
        """Get overall statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {
            'total_scans': 0,
            'by_label': {},
            'fp_count': 0,
            'fn_count': 0,
            'fp_rate': 0.0,
            'fn_rate': 0.0,
            'avg_confidence': 0.0,
            'by_model_type': {}
        }
        
        # Total scans
        cursor.execute('SELECT COUNT(*) FROM scans')
        stats['total_scans'] = cursor.fetchone()[0]
        
        if stats['total_scans'] == 0:
            conn.close()
            return stats
        
        # By label
        cursor.execute('SELECT label, COUNT(*) FROM scans GROUP BY label')
        stats['by_label'] = dict(cursor.fetchall())
        
        # FP/FN counts
        cursor.execute('SELECT COUNT(*) FROM scans WHERE is_false_positive = 1')
        stats['fp_count'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scans WHERE is_false_negative = 1')
        stats['fn_count'] = cursor.fetchone()[0]
        
        # Rates
        risky_scans = sum(v for k, v in stats['by_label'].items() if k in ('HIGH', 'CRITICAL'))
        safe_scans = sum(v for k, v in stats['by_label'].items() if k in ('SAFE', 'LOW'))
        
        if risky_scans > 0:
            stats['fp_rate'] = stats['fp_count'] / risky_scans
        if safe_scans > 0:
            stats['fn_rate'] = stats['fn_count'] / safe_scans
        
        # Average confidence
        cursor.execute('SELECT AVG(confidence) FROM scans WHERE confidence IS NOT NULL')
        result = cursor.fetchone()[0]
        stats['avg_confidence'] = result if result else 0.0
        
        # By model type
        cursor.execute('SELECT model_type, COUNT(*) FROM scans WHERE model_type IS NOT NULL GROUP BY model_type')
        stats['by_model_type'] = dict(cursor.fetchall())
        
        conn.close()
        return stats
    
    def get_fp_clusters(self, limit: int = 100) -> list[dict]:
        """Get false-positive patterns for analysis"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT file_hash, label, model_type, opcode_vector, confidence
            FROM scans
            WHERE is_false_positive = 1
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'file_hash': row[0],
                'label': row[1],
                'model_type': row[2],
                'opcode_vector': json.loads(row[3]) if row[3] else None,
                'confidence': row[4]
            })
        
        conn.close()
        return results
    
    def get_fn_outliers(self, limit: int = 100) -> list[dict]:
        """Get false-negative patterns for analysis"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT file_hash, label, model_type, opcode_vector, has_reduce, has_global, dangerous_globals
            FROM scans
            WHERE is_false_negative = 1
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'file_hash': row[0],
                'label': row[1],
                'model_type': row[2],
                'opcode_vector': json.loads(row[3]) if row[3] else None,
                'has_reduce': row[4],
                'has_global': row[5],
                'dangerous_globals': row[6]
            })
        
        conn.close()
        return results
    
    def get_opcode_vectors(self, limit: int = 1000) -> tuple[np.ndarray, list[str]]:
        """Get opcode vectors for PCA analysis"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT opcode_vector, label
            FROM scans
            WHERE opcode_vector IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        vectors = []
        labels = []
        
        for row in cursor.fetchall():
            try:
                vec = json.loads(row[0])
                if len(vec) == len(ALL_OPCODES):
                    vectors.append(vec)
                    labels.append(row[1])
            except (json.JSONDecodeError, TypeError):
                continue
        
        conn.close()
        
        if vectors:
            return np.array(vectors), labels
        return np.array([]), []
    
    def run_pca_analysis(self, n_components: int = 2) -> Optional[dict]:
        """Run PCA on opcode vectors to detect anomalies"""
        if not SKLEARN_AVAILABLE:
            return {'error': 'scikit-learn not installed'}
        
        vectors, labels = self.get_opcode_vectors()
        
        if len(vectors) < 10:
            return {'error': 'Not enough samples for PCA', 'samples': len(vectors)}
        
        # Standardize
        scaler = StandardScaler()
        scaled = scaler.fit_transform(vectors)
        
        # PCA
        pca = PCA(n_components=n_components)
        transformed = pca.fit_transform(scaled)
        
        # Cluster
        n_clusters = min(3, len(vectors) // 5)
        if n_clusters >= 2:
            kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            clusters = kmeans.fit_predict(transformed)
        else:
            clusters = [0] * len(vectors)
        
        # Analyze clusters
        cluster_analysis = {}
        for i in range(max(clusters) + 1):
            cluster_labels = [labels[j] for j in range(len(labels)) if clusters[j] == i]
            safe_count = sum(1 for l in cluster_labels if l in ('SAFE', 'LOW'))
            risky_count = sum(1 for l in cluster_labels if l in ('HIGH', 'CRITICAL'))
            
            cluster_analysis[f'cluster_{i}'] = {
                'size': len(cluster_labels),
                'safe_count': safe_count,
                'risky_count': risky_count,
                'dominant': 'safe' if safe_count > risky_count else 'risky'
            }
        
        return {
            'n_samples': len(vectors),
            'n_components': n_components,
            'explained_variance': pca.explained_variance_ratio_.tolist(),
            'n_clusters': max(clusters) + 1 if clusters else 0,
            'cluster_analysis': cluster_analysis,
            'transformed_shape': transformed.shape
        }
    
    def detect_distribution_shift(self, window_days: int = 7) -> dict:
        """Detect distribution shift in recent scans"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get label distribution for recent period
        cursor.execute('''
            SELECT label, COUNT(*) 
            FROM scans 
            WHERE datetime(timestamp) > datetime('now', ?)
            GROUP BY label
        ''', (f'-{window_days} days',))
        
        recent = dict(cursor.fetchall())
        
        # Get historical distribution
        cursor.execute('''
            SELECT label, COUNT(*) 
            FROM scans 
            WHERE datetime(timestamp) <= datetime('now', ?)
            GROUP BY label
        ''', (f'-{window_days} days',))
        
        historical = dict(cursor.fetchall())
        
        conn.close()
        
        # Calculate shift
        all_labels = set(recent.keys()) | set(historical.keys())
        recent_total = sum(recent.values()) or 1
        historical_total = sum(historical.values()) or 1
        
        shifts = {}
        for label in all_labels:
            recent_pct = recent.get(label, 0) / recent_total
            historical_pct = historical.get(label, 0) / historical_total
            shift = recent_pct - historical_pct
            shifts[label] = {
                'recent_pct': round(recent_pct * 100, 2),
                'historical_pct': round(historical_pct * 100, 2),
                'shift': round(shift * 100, 2),
                'significant': abs(shift) > 0.1  # >10% shift
            }
        
        return {
            'window_days': window_days,
            'recent_samples': sum(recent.values()),
            'historical_samples': sum(historical.values()),
            'shifts': shifts,
            'drift_detected': any(s['significant'] for s in shifts.values())
        }


def opcode_counts_to_vector(opcode_counts: dict) -> list[int]:
    """Convert opcode count dict to fixed-size vector"""
    return [opcode_counts.get(op, 0) for op in ALL_OPCODES]


# Singleton
telemetry = TelemetryStore()
