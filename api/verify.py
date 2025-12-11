"""
AI-Eye Verification API - Vercel Python Serverless Function

Endpoint: POST /api/verify
Body: { "pickle_data": "<base64 encoded pickle bytes>", "aieye_score": <optional int> }
"""
import json
import base64
from http.server import BaseHTTPRequestHandler
import sys
import os

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from verification_engine import engine, RiskLevel
from telemetry import opcode_counts_to_vector


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            # Parse request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body)
            
            # Get pickle data (base64 encoded)
            pickle_b64 = data.get('pickle_data')
            if not pickle_b64:
                self._send_error(400, 'pickle_data is required')
                return
            
            # Decode base64
            try:
                pickle_bytes = base64.b64decode(pickle_b64)
            except Exception as e:
                self._send_error(400, f'Invalid base64: {str(e)}')
                return
            
            # Get optional AIEye score
            aieye_score = data.get('aieye_score', 0)
            
            # Run triangulation
            result = engine.triangulate(pickle_bytes, aieye_score)
            
            # Build response
            response = {
                'file_hash': result.file_hash,
                'file_size': result.file_size,
                'aieye_result': result.aieye_result.value,
                'aieye_score': result.aieye_score,
                'consensus': result.consensus.value if result.consensus else None,
                'confidence': result.confidence,
                'is_false_positive': result.is_false_positive,
                'is_false_negative': result.is_false_negative,
                'reasoning': result.reasoning,
                'pickletools': {
                    'risk_level': result.pickletools_result.risk_level.value,
                    'risk_score': result.pickletools_result.risk_score,
                    'has_reduce': result.pickletools_result.has_reduce,
                    'has_global': result.pickletools_result.has_global,
                    'opcode_counts': result.pickletools_result.opcode_counts,
                    'dangerous_globals': [
                        {
                            'module': g.module,
                            'name': g.name,
                            'reason': g.reason
                        }
                        for g in result.pickletools_result.global_refs
                        if g.is_dangerous
                    ],
                    'disassembly': result.pickletools_result.raw_disassembly[:2000]  # Truncate for response size
                },
                'fickling': {
                    'available': result.fickling_result.available,
                    'is_safe': result.fickling_result.is_safe,
                    'findings': result.fickling_result.findings[:10]  # Limit findings
                },
                'sandbox': {
                    'load_succeeded': result.sandbox_result.load_succeeded,
                    'blocked_imports': result.sandbox_result.blocked_imports,
                    'loaded_type': result.sandbox_result.loaded_type,
                    'error': result.sandbox_result.error
                },
                'peft': {
                    'is_peft_adapter': result.peft_result.is_peft_adapter,
                    'is_trainer_output': result.peft_result.is_trainer_output,
                    'matched_signatures': result.peft_result.matched_signatures,
                    'confidence': result.peft_result.confidence
                },
                # Opcode vector for telemetry (frontend stores this)
                'opcode_vector': opcode_counts_to_vector(result.pickletools_result.opcode_counts)
            }
            
            self._send_json(200, response)
            
        except Exception as e:
            self._send_error(500, str(e))
    
    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(204)
        self._set_cors_headers()
        self.end_headers()
    
    def _set_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
    
    def _send_json(self, status: int, data: dict):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def _send_error(self, status: int, message: str):
        self._send_json(status, {'error': message})
