"""
Tests for Fix #1 (P0 CRITICAL): OAuth Token Validation Bypass Remediation.

Verifies:
1. Rejection of invalid, empty, and oversized tokens.
2. Sovereign production mode gate blocking external OAuth validation.
3. Provider-specific identity extraction (Google, Microsoft, GitHub, Custom).
4. Provider HTTP error (401/403) and API error handling (fail-closed).
5. Integration with accept_authentication in TLSChannelManager.
"""

import pytest
import urllib.error
from unittest.mock import patch, MagicMock

from tls_channel_manager import OAuth2DeviceFlowAuth, TLSSecureChannel, AuthenticationError


class TestOAuthTokenValidationP0:
    """Test suite for OAuth token validation security controls."""

    def test_reject_empty_or_none_token(self):
        auth = OAuth2DeviceFlowAuth(provider='google', client_id='test-client-id')
        
        valid, info, reason = auth.validate_received_token("")
        assert not valid
        assert info is None
        assert "Empty" in reason or "Invalid" in reason

        valid, info, reason = auth.validate_received_token(None)
        assert not valid
        assert info is None
        assert "Invalid" in reason

        valid, info, reason = auth.validate_received_token("   ")
        assert not valid
        assert info is None
        assert "Empty" in reason

    def test_reject_oversized_token(self):
        auth = OAuth2DeviceFlowAuth(provider='google', client_id='test-client-id')
        oversized = "A" * 8193
        valid, info, reason = auth.validate_received_token(oversized)
        assert not valid
        assert info is None
        assert "exceeds maximum allowed length" in reason

    @patch('tls_channel_manager._tls_is_production', return_value=True)
    def test_sovereign_production_blocks_external_oauth(self, mock_prod):
        # In sovereign production mode, instantiating public OAuth throws AuthenticationError
        with pytest.raises(AuthenticationError):
            OAuth2DeviceFlowAuth(provider='google', client_id='test-client-id')

    def test_google_token_validation_success(self):
        auth = OAuth2DeviceFlowAuth(provider='google', client_id='test-client-id')
        mock_response = {
            "sub": "1234567890",
            "email": "pilot@destroyer.mil",
            "email_verified": True,
            "name": "Tactical Pilot"
        }
        with patch('tls_channel_manager._hardened_https_post_json', return_value=mock_response):
            valid, info, identity = auth.validate_received_token("valid-google-token-xyz")
            assert valid is True
            assert info == mock_response
            assert identity == "pilot@destroyer.mil"

    def test_microsoft_token_validation_success(self):
        auth = OAuth2DeviceFlowAuth(provider='microsoft', client_id='test-client-id')
        mock_response = {
            "id": "ms-user-uuid",
            "userPrincipalName": "commander@cosp-tactical.org",
            "displayName": "Commander Bravo",
            "mail": "commander@cosp-tactical.org"
        }
        with patch('tls_channel_manager._hardened_https_post_json', return_value=mock_response):
            valid, info, identity = auth.validate_received_token("valid-ms-token-abc")
            assert valid is True
            assert info == mock_response
            assert identity == "commander@cosp-tactical.org"

    def test_github_token_validation_success(self):
        auth = OAuth2DeviceFlowAuth(provider='github', client_id='test-client-id')
        mock_response = {
            "id": 998877,
            "login": "destroyer-agent",
            "name": "Destroyer Core Agent"
        }
        with patch('tls_channel_manager._hardened_https_post_json', return_value=mock_response):
            valid, info, identity = auth.validate_received_token("gho_1234567890abcdef")
            assert valid is True
            assert info == mock_response
            assert identity == "destroyer-agent"

    def test_provider_error_payload_rejected(self):
        auth = OAuth2DeviceFlowAuth(provider='google', client_id='test-client-id')
        mock_response = {
            "error": "invalid_token",
            "error_description": "The access token provided has expired"
        }
        with patch('tls_channel_manager._hardened_https_post_json', return_value=mock_response):
            valid, info, reason = auth.validate_received_token("expired-token")
            assert valid is False
            assert info is None
            assert "expired" in reason

    def test_provider_http_401_rejected(self):
        auth = OAuth2DeviceFlowAuth(provider='google', client_id='test-client-id')
        with patch('tls_channel_manager._hardened_https_post_json', side_effect=urllib.error.HTTPError(
            url="https://oauth2.googleapis.com/oauth2/v3/userinfo",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=None
        )):
            valid, info, reason = auth.validate_received_token("bad-token")
            assert valid is False
            assert info is None
            assert "401" in reason

    def test_accept_authentication_fails_on_invalid_token(self):
        # TLSChannelManager.accept_authentication must fail closed if token is invalid
        mgr = TLSSecureChannel(require_authentication=True)
        mgr.is_server = True
        mgr.ssl_socket = MagicMock()
        mgr.ssl_socket.gettimeout.return_value = 10.0
        
        # Peer sends message with invalid token
        import json
        payload = json.dumps({"token_type": "Bearer", "access_token": "aW52YWxpZA=="}).encode('utf-8')
        mgr.recv_secure = MagicMock(return_value=payload)
        
        # Attach OAuth handler
        mgr.oauth_auth = OAuth2DeviceFlowAuth(provider='google', client_id='test-client-id')
        with patch.object(mgr.oauth_auth, 'validate_received_token', return_value=(False, None, "Invalid token")):
            result = mgr.accept_authentication(timeout=5.0)
            assert result is False
            assert not getattr(mgr, 'authenticated', False)

    def test_accept_authentication_succeeds_on_valid_token(self):
        mgr = TLSSecureChannel(require_authentication=True)
        mgr.is_server = True
        mgr.ssl_socket = MagicMock()
        mgr.ssl_socket.gettimeout.return_value = 10.0

        import json
        payload = json.dumps({"token_type": "Bearer", "access_token": "dmFsaWQtdG9rZW4="}).encode('utf-8')
        mgr.recv_secure = MagicMock(return_value=payload)

        mgr.oauth_auth = OAuth2DeviceFlowAuth(provider='google', client_id='test-client-id')
        mock_user = {"email": "verified@destroyer.mil"}
        with patch.object(mgr.oauth_auth, 'validate_received_token', return_value=(True, mock_user, "verified@destroyer.mil")):
            result = mgr.accept_authentication(timeout=5.0)
            assert result is True
            assert mgr.authenticated is True
            assert mgr.authenticated_user == "verified@destroyer.mil"
            assert mgr.client_user_info == mock_user
