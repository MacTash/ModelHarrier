"""
AI-Eye Corpus Check API - Vercel Python Serverless Function

Endpoint: POST /api/corpus-check
Triggers reference corpus verification and returns drift detection results.
"""
import json
from http.server import BaseHTTPRequestHandler
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from reference_corpus import corpus, initialize_corpus


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            # Parse request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b'{}'
            data = json.loads(body) if body else {}
            
            action = data.get('action', 'check')
            
            if action == 'initialize':
                # Initialize corpus with sample files
                result = initialize_corpus()
                self._send_json(200, {
                    'status': 'initialized',
                    'samples_created': result
                })
            
            elif action == 'check':
                # Run corpus verification
                result = corpus.run_corpus_check()
                self._send_json(200, {
                    'status': 'completed',
                    'timestamp': result.timestamp,
                    'samples_checked': result.samples_checked,
                    'samples_passed': result.samples_passed,
                    'samples_failed': result.samples_failed,
                    'drift_detected': result.drift_detected,
                    'new_fp': result.new_fp,
                    'new_fn': result.new_fn
                })
            
            elif action == 'summary':
                # Get corpus summary
                summary = corpus.get_summary()
                self._send_json(200, summary)
            
            elif action == 'history':
                # Get drift history
                history = corpus.get_drift_history()
                self._send_json(200, {'history': history[-30:]})  # Last 30 entries
            
            else:
                self._send_error(400, f'Unknown action: {action}')
                
        except Exception as e:
            self._send_error(500, str(e))
    
    def do_GET(self):
        """GET returns corpus summary"""
        try:
            summary = corpus.get_summary()
            history = corpus.get_drift_history()
            
            self._send_json(200, {
                **summary,
                'recent_checks': history[-7:]  # Last 7 checks
            })
        except Exception as e:
            self._send_error(500, str(e))
    
    def do_OPTIONS(self):
        self.send_response(204)
        self._set_cors_headers()
        self.end_headers()
    
    def _set_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
    
    def _send_json(self, status: int, data: dict):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def _send_error(self, status: int, message: str):
        self._send_json(status, {'error': message})
