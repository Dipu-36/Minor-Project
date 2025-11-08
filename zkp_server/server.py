import socket
import json
import time
import threading
import sys
from urllib.parse import parse_qs
from . import crypto_utils as crypto
from .storage import Storage
from .protocol import ZKPProtocol
from .config import HOST, PORT, MAX_REQUEST_SIZE

class ZKPServer:
    def __init__(self):
        self.storage = Storage()
        self.protocol = ZKPProtocol(self.storage)
        self.rate_limits = {}
        self._shutdown = False
    
    def _parse_request(self, data: bytes) -> dict:
        """Parse HTTP request into method, path, headers, body"""
        try:
            # Handle potential Unicode decoding issues
            text = data.decode('utf-8', errors='replace')
            lines = text.split('\r\n')
            if not lines or not lines[0]:
                return None
            
            # Parse request line
            request_parts = lines[0].split(' ', 2)
            if len(request_parts) < 3:
                return None
                
            method, path, _ = request_parts
            
            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if not line.strip():
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Parse body
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
            
            return {
                'method': method,
                'path': path,
                'headers': headers,
                'body': body
            }
        except Exception as e:
            print(f"Error parsing request: {e}")
            return None
    
    def _build_response(self, status: int, body: dict, content_type: str = "application/json") -> str:
        """Build HTTP response"""
        try:
            body_json = json.dumps(body)
            response_lines = [
                f"HTTP/1.1 {status} {'OK' if status == 200 else 'Error'}",
                f"Content-Type: {content_type}",
                f"Content-Length: {len(body_json)}",
                "Access-Control-Allow-Origin: *",
                "Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE, PUT",
                "Access-Control-Allow-Headers: Content-Type, Authorization",
                "Access-Control-Max-Age: 86400",
                "Connection: close",
                "",  # Empty line before body
                body_json
            ]
            return '\r\n'.join(response_lines)
        except Exception as e:
            print(f"Error building response: {e}")
            # Fallback error response
            return "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: 36\r\n\r\n{\"error\": \"Internal server error\"}"
    
    def _get_client_ip(self, client_socket) -> str:
        """Get client IP address"""
        try:
            return client_socket.getpeername()[0]
        except:
            return "unknown"
    
    def _check_rate_limit(self, key: str) -> bool:
        """Simple rate limiting"""
        now = time.time()
        window = 3600  # 1 hour
        
        # Clean up old entries periodically
        if len(self.rate_limits) > 1000:  # Prevent memory leaks
            old_keys = [k for k, v in self.rate_limits.items() if now - v['window_start'] > window * 2]
            for old_key in old_keys:
                del self.rate_limits[old_key]
        
        if key not in self.rate_limits:
            self.rate_limits[key] = {'count': 1, 'window_start': now}
            return True
        
        if now - self.rate_limits[key]['window_start'] > window:
            self.rate_limits[key] = {'count': 1, 'window_start': now}
            return True
        
        if self.rate_limits[key]['count'] >= 10:  # max 10 attempts per hour
            return False
        
        self.rate_limits[key]['count'] += 1
        return True
    
    def _handle_client(self, client_socket, client_address):
        """Handle individual client connection in a separate thread"""
        try:
            # Set timeout to prevent hanging
            client_socket.settimeout(30.0)
            
            # Receive data with buffer
            data = b""
            while True:
                try:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > MAX_REQUEST_SIZE:
                        response = self._build_response(413, {'error': 'Request too large'})
                        client_socket.send(response.encode())
                        return
                    # Check if we have complete headers
                    if b'\r\n\r\n' in data:
                        # For POST requests, check if we have complete body
                        headers_end = data.find(b'\r\n\r\n')
                        headers = data[:headers_end].decode('utf-8', errors='replace')
                        if 'Content-Length:' in headers:
                            for line in headers.split('\r\n'):
                                if line.lower().startswith('content-length:'):
                                    content_length = int(line.split(':')[1].strip())
                                    body_start = headers_end + 4
                                    if len(data) >= body_start + content_length:
                                        break
                            else:
                                continue  # Continue receiving if body not complete
                        break
                except socket.timeout:
                    response = self._build_response(408, {'error': 'Request timeout'})
                    client_socket.send(response.encode())
                    return
                except Exception as e:
                    print(f"Error receiving data: {e}")
                    return
            
            if not data:
                return
            
            request = self._parse_request(data)
            if not request:
                response = self._build_response(400, {'error': 'Invalid request'})
                client_socket.send(response.encode())
                return
            
            client_ip = self._get_client_ip(client_socket)
            print(f"Request: {request['method']} {request['path']} from {client_ip}")
            
            # Handle CORS preflight
            if request['method'] == 'OPTIONS':
                response = self._build_response(200, {})
                client_socket.send(response.encode())
                return
            
            # Route requests
            if request['method'] == 'POST':
                try:
                    body = json.loads(request['body']) if request['body'].strip() else {}
                except json.JSONDecodeError as e:
                    response = self._build_response(400, {'error': f'Invalid JSON: {str(e)}'})
                    client_socket.send(response.encode())
                    return
                except Exception as e:
                    response = self._build_response(400, {'error': 'Invalid request body'})
                    client_socket.send(response.encode())
                    return
                
                if request['path'] == '/register':
                    response_text = self.handle_register(body, client_ip)
                elif request['path'] == '/login/start':
                    response_text = self.handle_login_start(body, client_ip)
                elif request['path'] == '/login/finish':
                    response_text = self.handle_login_finish(body, client_ip)
                else:
                    response_text = self._build_response(404, {'error': 'Not found'})
            else:
                response_text = self._build_response(405, {'error': 'Method not allowed'})
            
            # Send response
            client_socket.send(response_text.encode('utf-8'))
            
        except socket.timeout:
            print(f"Client {client_address} timed out")
        except BrokenPipeError:
            print(f"Client {client_address} disconnected prematurely")
        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
            try:
                error_response = self._build_response(500, {'error': 'Internal server error'})
                client_socket.send(error_response.encode())
            except:
                pass  # Client may already be disconnected
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def handle_register(self, body: dict, client_ip: str) -> str:
        if not self._check_rate_limit(f"register_{client_ip}"):
            return self._build_response(429, {'error': 'Rate limit exceeded'})
        
        user_id = body.get('userID')
        v = body.get('v')
        
        if not user_id or not v:
            return self._build_response(400, {'error': 'Missing userID or v'})
        
        # Basic input validation
        if not isinstance(user_id, str) or len(user_id) > 255:
            return self._build_response(400, {'error': 'Invalid userID format'})
        
        try:
            # Validate v format
            v_bytes = crypto.base64url_decode(v)
            if len(v_bytes) != 32:
                raise ValueError("Invalid v format")
        except Exception as e:
            print(f"Registration error for {user_id}: {e}")
            return self._build_response(400, {'error': 'Invalid v encoding'})
        
        try:
            self.storage.store_verifier(user_id, v)
            print(f"User registered: {user_id}")
            return self._build_response(200, {'status': 'registered'})
        except Exception as e:
            print(f"Storage error for {user_id}: {e}")
            return self._build_response(500, {'error': 'Registration failed'})
    
    def handle_login_start(self, body: dict, client_ip: str) -> str:
        if not self._check_rate_limit(f"login_{client_ip}"):
            return self._build_response(429, {'error': 'Rate limit exceeded'})
        
        user_id = body.get('userID')
        t = body.get('t')
        
        if not user_id or not t:
            return self._build_response(400, {'error': 'Missing userID or t'})
        
        if not isinstance(user_id, str) or len(user_id) > 255:
            return self._build_response(400, {'error': 'Invalid userID format'})
        
        try:
            challenge_data = self.protocol.generate_challenge(user_id, t, client_ip)
            print(f"Login started for: {user_id}, session: {challenge_data['session_id']}")
            return self._build_response(200, challenge_data)
        except ValueError as e:
            print(f"Login start error for {user_id}: {e}")
            return self._build_response(400, {'error': str(e)})
        except Exception as e:
            print(f"Unexpected error in login start for {user_id}: {e}")
            return self._build_response(500, {'error': 'Internal server error'})
    
    def handle_login_finish(self, body: dict, client_ip: str) -> str:
        user_id = body.get('userID')
        session_id = body.get('session_id')
        s = body.get('s')
        
        if not all([user_id, session_id, s]):
            return self._build_response(400, {'error': 'Missing required fields'})
        
        if not isinstance(user_id, str) or len(user_id) > 255:
            return self._build_response(400, {'error': 'Invalid userID format'})
        
        try:
            if self.protocol.verify_proof(user_id, session_id, s):
                # In real implementation, generate JWT here
                token = crypto.base64url_encode(crypto.secure_random_bytes(32))
                print(f"Login successful for: {user_id}, session: {session_id}")
                return self._build_response(200, {'token': token, 'status': 'authenticated'})
            else:
                print(f"Login failed for: {user_id}, session: {session_id}")
                return self._build_response(401, {'error': 'Invalid proof'})
        except Exception as e:
            print(f"Login finish error for {user_id}: {e}")
            return self._build_response(500, {'error': 'Internal server error'})
    
    def start(self):
        """Start the server with proper error handling and threading"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((HOST, PORT))
            server_socket.listen(10)  # Increased backlog
            server_socket.settimeout(1.0)  # Allow for graceful shutdown
            
            print(f"ZKP Server running on {HOST}:{PORT}")
            print("Press Ctrl+C to stop the server")
            
            self._shutdown = False
            while not self._shutdown:
                try:
                    client_socket, client_address = server_socket.accept()
                    print(f"New connection from: {client_address[0]}:{client_address[1]}")
                    
                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.timeout:
                    # Timeout is expected, allows checking for shutdown
                    continue
                except OSError as e:
                    if not self._shutdown:
                        print(f"Socket error: {e}")
                    break
                except Exception as e:
                    print(f"Unexpected error accepting connection: {e}")
                    if not self._shutdown:
                        time.sleep(1)  # Prevent busy loop on persistent errors
                    
        except OSError as e:
            print(f"Failed to start server on {HOST}:{PORT}: {e}")
            if "Address already in use" in str(e):
                print(f"Port {PORT} is already in use. Try using a different port.")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\nShutting down server...")
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self._shutdown = True
            try:
                server_socket.close()
            except:
                pass
            print("Server stopped")
    
    def stop(self):
        """Gracefully stop the server"""
        self._shutdown = True

if __name__ == "__main__":
    server = ZKPServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()