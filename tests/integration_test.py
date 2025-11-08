#!/usr/bin/env python3
"""
Integration tests for the complete ZKP authentication flow
"""

import os
import sys
import time
import json
import socket
import threading
import unittest
from urllib.parse import urlencode

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from zkp_server.server import ZKPServer
from zkp_server.storage import Storage
import zkp_server.crypto_utils as crypto
from test_config import TEST_DB_PATH, TEST_HOST, TEST_PORT, TEST_USER_ID, TEST_PASSWORD, cleanup_test_db


class TestZKPIntegration(unittest.TestCase):
    """Integration tests for the complete ZKP authentication flow"""
    
    def setUp(self):
        """Set up test server"""
        self.server = ZKPServer()
        self.server.storage = Storage(TEST_DB_PATH)
        cleanup_test_db()
        
        # Start server in a separate thread
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True
        self.server_running = False
        
    def tearDown(self):
        """Stop server and clean up"""
        self.server_running = False
        cleanup_test_db()
    
    def _run_server(self):
        """Run server for testing"""
        # Modify server to use test config
        original_handle_request = self.server.handle_request
        
        def test_handle_request(client_socket, client_address):
            # Use test database
            self.server.storage = Storage(TEST_DB_PATH)
            original_handle_request(client_socket, client_address)
        
        self.server.handle_request = test_handle_request
        
        # Create test socket
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        test_socket.bind((TEST_HOST, TEST_PORT))
        test_socket.listen(5)
        test_socket.settimeout(1)  # 1 second timeout
        
        self.server_running = True
        while self.server_running:
            try:
                client_socket, client_address = test_socket.accept()
                self.server.handle_request(client_socket, client_address)
            except socket.timeout:
                continue
            except Exception as e:
                if self.server_running:
                    print(f"Server error: {e}")
        
        test_socket.close()
    
    def _send_http_request(self, method, path, body=None, headers=None):
        """Send HTTP request to test"""