#!/usr/bin/env python3
"""
Tests for WASM cryptographic mathematics
Note: These tests simulate the WASM math operations in Python
"""

import os
import sys
import unittest
import hashlib
import base64

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import zkp_server.crypto_utils as crypto
from test_config import TEST_USER_ID, TEST_PASSWORD, cleanup_test_db


class TestWASMMathSimulation(unittest.TestCase):
    """
    Simulate the WASM cryptographic operations in Python for testing.
    In a real scenario, these would call the actual WASM functions.
    """
    
    def setUp(self):
        """Set up test parameters"""
        # Use a simple simulation of Ed25519 operations
        # In reality, these would use proper curve operations
        self.group_order = 2**252 + 27742317777372353535851937790883648493
    
    def simulate_compute_v_from_password(self, password):
        """Simulate WASM compute_v_from_password function"""
        # x = SHA256(password) mod group_order
        x_hash = hashlib.sha256(password.encode()).digest()
        x_int = int.from_bytes(x_hash, 'little') % self.group_order
        x_bytes = x_int.to_bytes(32, 'little')
        
        # v = g^x (simulated as just encoding x for testing)
        # In real implementation, this would be scalar_mult_base(x)
        v_bytes = hashlib.sha256(x_bytes).digest()  # Simulate curve point
        
        return crypto.base64url_encode(v_bytes)
    
    def simulate_initiate_login(self, password):
        """Simulate WASM initiate_login_from_password function"""
        # Generate random r
        r_bytes = crypto.secure_random_bytes(32)
        r_int = int.from_bytes(r_bytes, 'little') % self.group_order
        
        # t = g^r (simulated)
        t_bytes = hashlib.sha256(r_bytes).digest()  # Simulate curve point
        
        # x = SHA256(password)
        x_hash = hashlib.sha256(password.encode()).digest()
        x_int = int.from_bytes(x_hash, 'little') % self.group_order
        
        # Store state (r, x) - in WASM this would be in memory
        state = {
            'r': r_int,
            'x': x_int,
            'r_bytes': r_bytes
        }
        
        return crypto.base64url_encode(t_bytes), state
    
    def simulate_compute_response(self, state, challenge_b64):
        """Simulate WASM compute_response_from_state function"""
        challenge_bytes = crypto.base64url_decode(challenge_b64)
        challenge_int = int.from_bytes(challenge_bytes, 'little') % self.group_order
        
        # s = r + c*x mod group_order
        s_int = (state['r'] + challenge_int * state['x']) % self.group_order
        s_bytes = s_int.to_bytes(32, 'little')
        
        return crypto.base64url_encode(s_bytes)
    
    def test_password_to_verifier_consistency(self):
        """Test that the same password always produces the same verifier"""
        password = TEST_PASSWORD
        
        v1 = self.simulate_compute_v_from_password(password)
        v2 = self.simulate_compute_v_from_password(password)
        
        self.assertEqual(v1, v2)
        self.assertIsInstance(v1, str)
        self.assertGreater(len(v1), 0)
    
    def test_different_passwords_different_verifiers(self):
        """Test that different passwords produce different verifiers"""
        password1 = "password1"
        password2 = "password2"
        
        v1 = self.simulate_compute_v_from_password(password1)
        v2 = self.simulate_compute_v_from_password(password2)
        
        self.assertNotEqual(v1, v2)
    
    def test_login_flow_simulation(self):
        """Simulate the complete login flow"""
        password = TEST_PASSWORD
        
        # Step 1: Compute verifier (registration)
        v = self.simulate_compute_v_from_password(password)
        
        # Step 2: Initiate login
        t, state = self.simulate_initiate_login(password)
        
        self.assertIsInstance(t, str)
        self.assertIsInstance(state, dict)
        self.assertIn('r', state)
        self.assertIn('x', state)
        
        # Step 3: Generate challenge (server-side)
        challenge_data = b"simulated_challenge_data"
        challenge_b64 = crypto.base64url_encode(challenge_data)
        
        # Step 4: Compute response
        s = self.simulate_compute_response(state, challenge_b64)
        
        self.assertIsInstance(s, str)
        self.assertGreater(len(s), 0)
    
    def test_proof_verification_simulation(self):
        """
        Simulate proof verification.
        In a real implementation, this would verify: g^s == t * v^c
        """
        password = TEST_PASSWORD
        
        # Registration
        v = self.simulate_compute_v_from_password(password)
        
        # Login initiation
        t, state = self.simulate_initiate_login(password)
        
        # Server generates challenge
        challenge_data = b"test_challenge_" + crypto.secure_random_bytes(16)
        challenge_b64 = crypto.base64url_encode(challenge_data)
        
        # Client computes response
        s = self.simulate_compute_response(state, challenge_b64)
        
        # Verification (simplified)
        # In real implementation, this would be the actual curve math:
        # g^s == t * v^c
        
        # For this simulation, we'll just verify that we can decode everything
        try:
            s_bytes = crypto.base64url_decode(s)
            t_bytes = crypto.base64url_decode(t)
            v_bytes = crypto.base64url_decode(v)
            challenge_bytes = crypto.base64url_decode(challenge_b64)
            
            # All should be valid base64 and proper lengths
            self.assertEqual(len(s_bytes), 32)
            self.assertEqual(len(t_bytes), 32)
            self.assertEqual(len(v_bytes), 32)
            self.assertEqual(len(challenge_bytes), len(challenge_data))
            
            verification_passed = True
            
        except Exception as e:
            verification_passed = False
        
        self.assertTrue(verification_passed)
    
    def test_base64url_roundtrip(self):
        """Test that base64url encoding/decoding works correctly for WASM data"""
        test_data = crypto.secure_random_bytes(32)
        
        encoded = crypto.base64url_encode(test_data)
        decoded = crypto.base64url_decode(encoded)
        
        self.assertEqual(test_data, decoded)
        self.assertIsInstance(encoded, str)
        # Should not contain base64url-incompatible characters
        self.assertNotIn('+', encoded)
        self.assertNotIn('/', encoded)
        self.assertNotIn('=', encoded)
    
    def test_state_cleanup_simulation(self):
        """Test that sensitive data is properly cleaned up"""
        password = TEST_PASSWORD
        
        # Create state
        t, state = self.simulate_initiate_login(password)
        
        # Verify state contains sensitive data
        self.assertIn('r', state)
        self.assertIn('x', state)
        self.assertIn('r_bytes', state)
        
        # Simulate state cleanup (like WASM would do)
        state_data = [state['r'], state['x'], state['r_bytes']]
        
        # "Zero" the state by replacing with None
        state.clear()
        
        # Verify state is empty
        self.assertEqual(len(state), 0)
        
        # Original data should still exist in our test list
        # but in WASM, the memory would be actually zeroed
        self.assertEqual(len(state_data), 3)


class TestCryptographicProperties(unittest.TestCase):
    """Test important cryptographic properties"""
    
    def test_randomness_quality(self):
        """Test that generated random data has good entropy"""
        # Generate multiple random samples
        samples = [crypto.secure_random_bytes(32) for _ in range(10)]
        
        # All samples should be different
        for i in range(len(samples)):
            for j in range(i + 1, len(samples)):
                self.assertNotEqual(samples[i], samples[j],
                                  "Random samples should not be equal")
        
        # Each sample should have high entropy (non-zero)
        for sample in samples:
            self.assertNotEqual(sample, b'\x00' * 32,
                              "Random sample should not be all zeros")
    
    def test_hash_collision_resistance(self):
        """Test that different inputs produce different hashes"""
        inputs = [b"input1", b"input2", b"input3", b"input4"]
        hashes = [hashlib.sha256(inp).digest() for inp in inputs]
        
        # All hashes should be unique
        self.assertEqual(len(set(hashes)), len(inputs))
    
    def test_deterministic_operations(self):
        """Test that deterministic operations produce identical results"""
        password = "test_password"
        
        # Multiple calls should produce identical results
        results = []
        for _ in range(5):
            # Simulate x = SHA256(password)
            x = hashlib.sha256(password.encode()).digest()
            results.append(x)
        
        # All results should be identical
        for i in range(1, len(results)):
            self.assertEqual(results[0], results[i])


if __name__ == '__main__':
    unittest.main()