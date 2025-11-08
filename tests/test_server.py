#!/usr/bin/env python3
"""
Unit tests for the ZKP authentication server
"""

import os
import sys
import json
import time
import unittest
import threading
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from zkp_server.server import ZKPServer
from zkp_server.storage import Storage
from zkp_server.protocol import ZKPProtocol
import zkp_server.crypto_utils as crypto
from test_config import TEST_DB_PATH, TEST_USER_ID, cleanup_test_db


class TestStorage(unittest.TestCase):
    """Test the storage layer"""
    
    def setUp(self):
        """Set up test database"""
        self.storage = Storage(TEST_DB_PATH)
        cleanup_test_db()
    
    def tearDown(self):
        """Clean up test database"""
        cleanup_test_db()
    
    def test_store_and_retrieve_verifier(self):
        """Test storing and retrieving user verifier"""
        test_v = "test_verifier_data"
        
        # Store verifier
        self.storage.store_verifier(TEST_USER_ID, test_v)
        
        # Retrieve verifier
        retrieved_v = self.storage.get_verifier(TEST_USER_ID)
        
        self.assertEqual(retrieved_v, test_v)
    
    def test_get_nonexistent_user(self):
        """Test retrieving non-existent user returns None"""
        result = self.storage.get_verifier("nonexistent@example.com")
        self.assertIsNone(result)
    
    def test_session_management(self):
        """Test session storage and retrieval"""
        session_id = "test_session_123"
        user_id = TEST_USER_ID
        t_data = "test_t_data"
        challenge = "test_challenge"
        expires_at = int(time.time()) + 300
        client_ip = "127.0.0.1"
        
        # Store session
        self.storage.store_session(session_id, user_id, t_data, challenge, expires_at, client_ip)
        
        # Retrieve session
        session = self.storage.get_session(session_id)
        
        self.assertIsNotNone(session)
        self.assertEqual(session['user_id'], user_id)
        self.assertEqual(session['t_data'], t_data)
        self.assertEqual(session['challenge'], challenge)
        self.assertEqual(session['expires_at'], expires_at)
        self.assertFalse(session['used'])
    
    def test_mark_session_used(self):
        """Test marking session as used"""
        session_id = "test_session_456"
        
        # Store session
        self.storage.store_session(session_id, TEST_USER_ID, "t_data", "challenge", 
                                 int(time.time()) + 300, "127.0.0.1")
        
        # Mark as used
        self.storage.mark_session_used(session_id)
        
        # Retrieve and verify
        session = self.storage.get_session(session_id)
        self.assertTrue(session['used'])


class TestCryptoUtils(unittest.TestCase):
    """Test cryptographic utility functions"""
    
    def test_sha256(self):
        """Test SHA-256 hashing"""
        test_data = b"test_data"
        hash_result = crypto.sha256(test_data)
        
        self.assertEqual(len(hash_result), 32)
        # Ensure deterministic results
        self.assertEqual(crypto.sha256(test_data), hash_result)
    
    def test_secure_random_bytes(self):
        """Test secure random byte generation"""
        random_data = crypto.secure_random_bytes(32)
        
        self.assertEqual(len(random_data), 32)
        # Very basic test to ensure we get different results
        random_data2 = crypto.secure_random_bytes(32)
        self.assertNotEqual(random_data, random_data2)
    
    def test_constant_time_compare(self):
        """Test constant-time comparison"""
        data1 = b"same_data"
        data2 = b"same_data"
        data3 = b"different"
        
        self.assertTrue(crypto.constant_time_compare(data1, data2))
        self.assertFalse(crypto.constant_time_compare(data1, data3))
        self.assertFalse(crypto.constant_time_compare(data1, b""))
    
    def test_base64url_encoding(self):
        """Test base64url encoding and decoding"""
        test_data = b"test_data_for_encoding"
        
        # Encode
        encoded = crypto.base64url_encode(test_data)
        self.assertIsInstance(encoded, str)
        self.assertNotIn('+', encoded)
        self.assertNotIn('/', encoded)
        self.assertNotIn('=', encoded)
        
        # Decode
        decoded = crypto.base64url_decode(encoded)
        self.assertEqual(decoded, test_data)
    
    def test_bytes_int_conversion(self):
        """Test bytes to integer conversion and back"""
        test_int = 1234567890
        
        # Convert to bytes and back
        bytes_data = crypto.int_to_bytes(test_int, 8)
        recovered_int = crypto.bytes_to_int(bytes_data)
        
        self.assertEqual(test_int, recovered_int)


class TestZKPProtocol(unittest.TestCase):
    """Test ZKP protocol logic"""
    
    def setUp(self):
        """Set up test protocol instance"""
        self.storage = Storage(TEST_DB_PATH)
        self.protocol = ZKPProtocol(self.storage)
        cleanup_test_db()
    
    def tearDown(self):
        """Clean up test database"""
        cleanup_test_db()
    
    def test_generate_challenge(self):
        """Test challenge generation"""
        user_id = TEST_USER_ID
        t_data = crypto.base64url_encode(b"t" * 32)  # Simulate 32-byte t
        client_ip = "127.0.0.1"
        
        challenge_data = self.protocol.generate_challenge(user_id, t_data, client_ip)
        
        self.assertIn('session_id', challenge_data)
        self.assertIn('c', challenge_data)
        self.assertIn('expires_at', challenge_data)
        
        # Verify session was stored
        session = self.storage.get_session(challenge_data['session_id'])
        self.assertIsNotNone(session)
        self.assertEqual(session['user_id'], user_id)
        self.assertEqual(session['t_data'], t_data)
    
    def test_generate_challenge_invalid_t(self):
        """Test challenge generation with invalid t data"""
        with self.assertRaises(ValueError):
            self.protocol.generate_challenge(TEST_USER_ID, "invalid_data", "127.0.0.1")
    
    @patch('zkp_server.protocol.time.time')
    def test_verify_proof_expired_session(self, mock_time):
        """Test verification with expired session"""
        mock_time.return_value = 1000
        
        # Create an expired session
        session_id = "expired_session"
        self.storage.store_session(session_id, TEST_USER_ID, "t_data", "challenge", 
                                 999, "127.0.0.1")  # Expired at 999
        
        result = self.protocol.verify_proof(TEST_USER_ID, session_id, "s_data")
        self.assertFalse(result)
    
    def test_verify_proof_nonexistent_session(self):
        """Test verification with non-existent session"""
        result = self.protocol.verify_proof(TEST_USER_ID, "nonexistent", "s_data")
        self.assertFalse(result)
    
    def test_verify_proof_used_session(self):
        """Test verification with already used session"""
        session_id = "used_session"
        self.storage.store_session(session_id, TEST_USER_ID, "t_data", "challenge", 
                                 int(time.time()) + 300, "127.0.0.1")
        self.storage.mark_session_used(session_id)
        
        result = self.protocol.verify_proof(TEST_USER_ID, session_id, "s_data")
        self.assertFalse(result)
    
    def test_verify_proof_user_mismatch(self):
        """Test verification with user ID mismatch"""
        session_id = "user_mismatch_session"
        self.storage.store_session(session_id, "different_user", "t_data", "challenge",
                                 int(time.time()) + 300, "127.0.0.1")
        
        result = self.protocol.verify_proof(TEST_USER_ID, session_id, "s_data")
        self.assertFalse(result)


class TestZKPServer(unittest.TestCase):
    """Test the main server class"""
    
    def setUp(self):
        """Set up test server"""
        self.server = ZKPServer()
        self.server.storage = Storage(TEST_DB_PATH)
        cleanup_test_db()
    
    def tearDown(self):
        """Clean up test database"""
        cleanup_test_db()
    
    def test_parse_request(self):
        """Test HTTP request parsing"""
        http_request = (
            "POST /register HTTP/1.1\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 25\r\n"
            "\r\n"
            '{"userID": "test", "v": "data"}'
        )
        
        parsed = self.server._parse_request(http_request.encode())
        
        self.assertEqual(parsed['method'], 'POST')
        self.assertEqual(parsed['path'], '/register')
        self.assertEqual(parsed['headers']['Content-Type'], 'application/json')
        self.assertEqual(parsed['body'], '{"userID": "test", "v": "data"}')
    
    def test_build_response(self):
        """Test HTTP response building"""
        response_body = {'status': 'success'}
        response = self.server._build_response(200, response_body)
        
        self.assertIn('HTTP/1.1 200 OK', response)
        self.assertIn('Content-Type: application/json', response)
        self.assertIn('{"status": "success"}', response)
        self.assertIn('Access-Control-Allow-Origin: *', response)
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        key = "test_key"
        
        # First attempt should succeed
        self.assertTrue(self.server._check_rate_limit(key))
        
        # Multiple attempts within window
        for i in range(8):  # 8 more attempts (total 9)
            self.assertTrue(self.server._check_rate_limit(key))
        
        # 10th attempt should fail
        self.assertFalse(self.server._check_rate_limit(key))
    
    def test_rate_limit_reset(self):
        """Test rate limit window reset"""
        key = "test_key_reset"
        
        # Fill the window
        for i in range(10):
            self.server._check_rate_limit(key)
        
        # Should be blocked
        self.assertFalse(self.server._check_rate_limit(key))
        
        # Simulate window expiration by manipulating internal state
        self.server.rate_limits[key]['window_start'] = time.time() - 4000  # 4000 seconds ago
        
        # Should be allowed again
        self.assertTrue(self.server._check_rate_limit(key))


if __name__ == '__main__':
    unittest.main()