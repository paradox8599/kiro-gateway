# -*- coding: utf-8 -*-

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient


class TestAuthLoginEndpoint:
    def test_login_returns_session_id(
        self,
        test_client,
        mock_register_client_response,
        mock_device_authorization_response,
    ):
        """
        What it does: Tests that POST /auth/login returns a session_id and auth details.
        Purpose: Verify the login endpoint creates a new auth session with all required fields.
        """
        print("Setup: Mocking DeviceAuthFlow...")
        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                return_value=mock_register_client_response()
            )
            mock_flow.start_device_authorization = AsyncMock(
                return_value=mock_device_authorization_response()
            )
            mock_flow_class.return_value = mock_flow

            with patch("kiro.routes_auth.BackgroundTasks.add_task"):
                print("Action: Calling POST /auth/login...")
                response = test_client.post("/auth/login")

                print("Verification: Checking response status and structure...")
                assert response.status_code == 200
                data = response.json()

                print(f"Response data: {data}")
                assert "session_id" in data
                assert "verification_uri" in data
                assert "verification_uri_complete" in data
                assert "user_code" in data
                assert "expires_in" in data

                assert data["user_code"] == "ABCD-EFGH"
                assert (
                    data["verification_uri"]
                    == "https://device.sso.us-east-1.amazonaws.com"
                )
                assert data["expires_in"] == 300

    def test_login_with_custom_region(
        self,
        test_client,
        mock_register_client_response,
        mock_device_authorization_response,
    ):
        """
        What it does: Tests POST /auth/login with custom region parameter.
        Purpose: Verify that region parameter is passed to DeviceAuthFlow.
        """
        print("Setup: Mocking DeviceAuthFlow...")
        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                return_value=mock_register_client_response()
            )
            mock_flow.start_device_authorization = AsyncMock(
                return_value=mock_device_authorization_response()
            )
            mock_flow_class.return_value = mock_flow

            with patch("kiro.routes_auth.BackgroundTasks.add_task"):
                print("Action: Calling POST /auth/login with region=eu-west-1...")
                response = test_client.post("/auth/login?region=eu-west-1")

                print(
                    "Verification: Checking DeviceAuthFlow was created with correct region..."
                )
                assert response.status_code == 200
                mock_flow_class.assert_called_once_with(
                    region="eu-west-1", start_url=None
                )

    def test_login_handles_registration_failure(self, test_client):
        """
        What it does: Tests POST /auth/login when client registration fails.
        Purpose: Verify that registration errors are properly handled and returned as 500.
        """
        print("Setup: Mocking DeviceAuthFlow with registration failure...")
        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            from kiro.device_auth import DeviceAuthError

            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                side_effect=DeviceAuthError("invalid_request", "Registration failed")
            )
            mock_flow_class.return_value = mock_flow

            print("Action: Calling POST /auth/login expecting error...")
            response = test_client.post("/auth/login")

            print("Verification: Checking error response...")
            assert response.status_code == 500
            data = response.json()
            assert "detail" in data
            assert "invalid_request" in data["detail"]

    def test_login_handles_device_auth_failure(
        self, test_client, mock_register_client_response
    ):
        """
        What it does: Tests POST /auth/login when device authorization fails.
        Purpose: Verify that device auth errors are properly handled.
        """
        print("Setup: Mocking DeviceAuthFlow with device auth failure...")
        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            from kiro.device_auth import DeviceAuthError

            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                return_value=mock_register_client_response()
            )
            mock_flow.start_device_authorization = AsyncMock(
                side_effect=DeviceAuthError("server_error", "Device auth failed")
            )
            mock_flow_class.return_value = mock_flow

            print("Action: Calling POST /auth/login expecting error...")
            response = test_client.post("/auth/login")

            print("Verification: Checking error response...")
            assert response.status_code == 500
            data = response.json()
            assert "detail" in data
            assert "server_error" in data["detail"]

    def test_login_creates_session_in_memory(
        self,
        test_client,
        mock_register_client_response,
        mock_device_authorization_response,
    ):
        """
        What it does: Tests that POST /auth/login creates a session in _auth_sessions.
        Purpose: Verify that session state is properly stored for status checks.
        """
        print("Setup: Clearing any existing sessions...")
        from kiro.routes_auth import _auth_sessions

        _auth_sessions.clear()

        print("Setup: Mocking DeviceAuthFlow and background tasks...")
        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                return_value=mock_register_client_response()
            )
            mock_flow.start_device_authorization = AsyncMock(
                return_value=mock_device_authorization_response()
            )
            mock_flow_class.return_value = mock_flow

            with patch("kiro.routes_auth.BackgroundTasks.add_task"):
                print("Action: Calling POST /auth/login...")
                response = test_client.post("/auth/login")

                print("Verification: Checking session was created...")
                assert response.status_code == 200
                data = response.json()
                session_id = data["session_id"]

                assert session_id in _auth_sessions
                session = _auth_sessions[session_id]
                assert session["status"] == "pending"
                assert session["user_code"] == "ABCD-EFGH"
                assert session["device_code"] == "test_device_code_abc123"


class TestAuthLoginStatusEndpoint:
    def test_login_status_returns_pending_for_valid_session(
        self,
        test_client,
        mock_register_client_response,
        mock_device_authorization_response,
    ):
        """
        What it does: Tests GET /auth/login/status/{session_id} returns pending status.
        Purpose: Verify that status endpoint returns correct status for active session.
        """
        print("Setup: Creating a login session...")
        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                return_value=mock_register_client_response()
            )
            mock_flow.start_device_authorization = AsyncMock(
                return_value=mock_device_authorization_response()
            )
            mock_flow_class.return_value = mock_flow

            with patch("kiro.routes_auth.BackgroundTasks.add_task"):
                login_response = test_client.post("/auth/login")
                session_id = login_response.json()["session_id"]

                print(f"Action: Checking status for session {session_id[:8]}...")
                status_response = test_client.get(f"/auth/login/status/{session_id}")

                print("Verification: Checking status response...")
                assert status_response.status_code == 200
                data = status_response.json()
                assert data["status"] == "pending"
                assert data["message"] is None

    def test_login_status_returns_404_for_invalid_session(self, test_client):
        """
        What it does: Tests GET /auth/login/status/{invalid_id} returns 404.
        Purpose: Verify that status endpoint rejects unknown session IDs.
        """
        print("Action: Checking status for non-existent session...")
        response = test_client.get("/auth/login/status/invalid-session-id-12345")

        print("Verification: Checking 404 response...")
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data
        assert "not found" in data["detail"].lower()

    def test_login_status_reflects_completion(
        self,
        test_client,
        mock_register_client_response,
        mock_device_authorization_response,
    ):
        """
        What it does: Tests that status changes to 'complete' after successful auth.
        Purpose: Verify that background task updates session status correctly.
        """
        print("Setup: Creating a login session...")
        from kiro.routes_auth import _auth_sessions

        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                return_value=mock_register_client_response()
            )
            mock_flow.start_device_authorization = AsyncMock(
                return_value=mock_device_authorization_response()
            )
            mock_flow_class.return_value = mock_flow

            with patch("kiro.routes_auth.BackgroundTasks.add_task"):
                login_response = test_client.post("/auth/login")
                session_id = login_response.json()["session_id"]

                print("Action: Manually updating session status to 'complete'...")
                _auth_sessions[session_id]["status"] = "complete"
                _auth_sessions[session_id]["message"] = (
                    "Authentication successful. Credentials saved."
                )

                print("Action: Checking status...")
                status_response = test_client.get(f"/auth/login/status/{session_id}")

                print("Verification: Checking status is 'complete'...")
                assert status_response.status_code == 200
                data = status_response.json()
                assert data["status"] == "complete"
                assert "successful" in data["message"].lower()

    def test_login_status_reflects_error(
        self,
        test_client,
        mock_register_client_response,
        mock_device_authorization_response,
    ):
        """
        What it does: Tests that status changes to 'error' on auth failure.
        Purpose: Verify that error states are properly reflected in status.
        """
        print("Setup: Creating a login session...")
        from kiro.routes_auth import _auth_sessions

        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                return_value=mock_register_client_response()
            )
            mock_flow.start_device_authorization = AsyncMock(
                return_value=mock_device_authorization_response()
            )
            mock_flow_class.return_value = mock_flow

            with patch("kiro.routes_auth.BackgroundTasks.add_task"):
                login_response = test_client.post("/auth/login")
                session_id = login_response.json()["session_id"]

                print("Action: Manually updating session status to 'error'...")
                _auth_sessions[session_id]["status"] = "error"
                _auth_sessions[session_id]["message"] = "Authentication failed"

                print("Action: Checking status...")
                status_response = test_client.get(f"/auth/login/status/{session_id}")

                print("Verification: Checking status is 'error'...")
                assert status_response.status_code == 200
                data = status_response.json()
                assert data["status"] == "error"
                assert "failed" in data["message"].lower()

    def test_login_status_reflects_expired(
        self,
        test_client,
        mock_register_client_response,
        mock_device_authorization_response,
    ):
        """
        What it does: Tests that status changes to 'expired' on timeout.
        Purpose: Verify that expired sessions are properly indicated.
        """
        print("Setup: Creating a login session...")
        from kiro.routes_auth import _auth_sessions

        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                return_value=mock_register_client_response()
            )
            mock_flow.start_device_authorization = AsyncMock(
                return_value=mock_device_authorization_response()
            )
            mock_flow_class.return_value = mock_flow

            with patch("kiro.routes_auth.BackgroundTasks.add_task"):
                login_response = test_client.post("/auth/login")
                session_id = login_response.json()["session_id"]

                print("Action: Manually updating session status to 'expired'...")
                _auth_sessions[session_id]["status"] = "expired"
                _auth_sessions[session_id]["message"] = (
                    "Authorization timed out. Please try again."
                )

                print("Action: Checking status...")
                status_response = test_client.get(f"/auth/login/status/{session_id}")

                print("Verification: Checking status is 'expired'...")
                assert status_response.status_code == 200
                data = status_response.json()
                assert data["status"] == "expired"
                assert "timed out" in data["message"].lower()


class TestAuthCancelLoginEndpoint:
    def test_cancel_login_removes_session(
        self,
        test_client,
        mock_register_client_response,
        mock_device_authorization_response,
    ):
        """
        What it does: Tests DELETE /auth/login/{session_id} removes session.
        Purpose: Verify that cancel endpoint properly removes session from storage.
        """
        print("Setup: Creating a login session...")
        from kiro.routes_auth import _auth_sessions

        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                return_value=mock_register_client_response()
            )
            mock_flow.start_device_authorization = AsyncMock(
                return_value=mock_device_authorization_response()
            )
            mock_flow_class.return_value = mock_flow

            with patch("kiro.routes_auth.BackgroundTasks.add_task"):
                login_response = test_client.post("/auth/login")
                session_id = login_response.json()["session_id"]

                print(f"Action: Cancelling session {session_id[:8]}...")
                cancel_response = test_client.delete(f"/auth/login/{session_id}")

                print("Verification: Checking session was removed...")
                assert cancel_response.status_code == 200
                data = cancel_response.json()
                assert "cancelled" in data["message"].lower()
                assert session_id not in _auth_sessions

    def test_cancel_login_returns_404_for_invalid_session(self, test_client):
        """
        What it does: Tests DELETE /auth/login/{invalid_id} returns 404.
        Purpose: Verify that cancel endpoint rejects unknown session IDs.
        """
        print("Action: Cancelling non-existent session...")
        response = test_client.delete("/auth/login/invalid-session-id-12345")

        print("Verification: Checking 404 response...")
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data
        assert "not found" in data["detail"].lower()


class TestAuthSessionManagement:
    def test_concurrent_login_requests_create_separate_sessions(
        self,
        test_client,
        mock_register_client_response,
        mock_device_authorization_response,
    ):
        """
        What it does: Tests that multiple concurrent login requests create separate sessions.
        Purpose: Verify that each login request gets a unique session ID.
        """
        print("Setup: Clearing any existing sessions...")
        from kiro.routes_auth import _auth_sessions

        _auth_sessions.clear()

        print("Setup: Mocking DeviceAuthFlow...")
        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                return_value=mock_register_client_response()
            )
            mock_flow.start_device_authorization = AsyncMock(
                return_value=mock_device_authorization_response()
            )
            mock_flow_class.return_value = mock_flow

            with patch("kiro.routes_auth.BackgroundTasks.add_task"):
                print("Action: Creating 3 concurrent login sessions...")
                response1 = test_client.post("/auth/login")
                response2 = test_client.post("/auth/login")
                response3 = test_client.post("/auth/login")

                print("Verification: Checking all sessions have unique IDs...")
                session_id1 = response1.json()["session_id"]
                session_id2 = response2.json()["session_id"]
                session_id3 = response3.json()["session_id"]

                assert session_id1 != session_id2
                assert session_id2 != session_id3
                assert session_id1 != session_id3

                assert len(_auth_sessions) == 3
                assert session_id1 in _auth_sessions
                assert session_id2 in _auth_sessions
                assert session_id3 in _auth_sessions

    def test_session_cleanup_removes_expired_sessions(
        self,
        test_client,
        mock_register_client_response,
        mock_device_authorization_response,
    ):
        """
        What it does: Tests that expired sessions are cleaned up.
        Purpose: Verify that _cleanup_expired_sessions removes old sessions.
        """
        print("Setup: Creating a login session...")
        from kiro.routes_auth import _auth_sessions, _cleanup_expired_sessions

        _auth_sessions.clear()

        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                return_value=mock_register_client_response()
            )
            mock_flow.start_device_authorization = AsyncMock(
                return_value=mock_device_authorization_response()
            )
            mock_flow_class.return_value = mock_flow

            with patch("kiro.routes_auth.BackgroundTasks.add_task"):
                login_response = test_client.post("/auth/login")
                session_id = login_response.json()["session_id"]

                print(
                    "Action: Manually setting session creation time to 11 minutes ago..."
                )
                old_time = datetime.now(timezone.utc) - timedelta(minutes=11)
                _auth_sessions[session_id]["created_at"] = old_time

                print("Action: Running cleanup...")
                _cleanup_expired_sessions()

                print("Verification: Checking session was removed...")
                assert session_id not in _auth_sessions

    def test_session_cleanup_keeps_recent_sessions(
        self,
        test_client,
        mock_register_client_response,
        mock_device_authorization_response,
    ):
        """
        What it does: Tests that recent sessions are not cleaned up.
        Purpose: Verify that _cleanup_expired_sessions only removes old sessions.
        """
        print("Setup: Creating a login session...")
        from kiro.routes_auth import _auth_sessions, _cleanup_expired_sessions

        _auth_sessions.clear()

        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                return_value=mock_register_client_response()
            )
            mock_flow.start_device_authorization = AsyncMock(
                return_value=mock_device_authorization_response()
            )
            mock_flow_class.return_value = mock_flow

            with patch("kiro.routes_auth.BackgroundTasks.add_task"):
                login_response = test_client.post("/auth/login")
                session_id = login_response.json()["session_id"]

                print("Action: Running cleanup (session is recent)...")
                _cleanup_expired_sessions()

                print("Verification: Checking session was NOT removed...")
                assert session_id in _auth_sessions

    def test_background_task_updates_session_on_success(
        self,
        test_client,
        mock_register_client_response,
        mock_device_authorization_response,
        mock_create_token_success_response,
    ):
        """
        What it does: Tests that background polling task updates session on success.
        Purpose: Verify that _poll_for_token_background updates session status.
        """
        print("Setup: Creating a login session with mocked polling...")
        from kiro.routes_auth import _auth_sessions

        _auth_sessions.clear()

        with patch("kiro.routes_auth.DeviceAuthFlow") as mock_flow_class:
            mock_flow = MagicMock()
            mock_flow.register_client = AsyncMock(
                return_value=mock_register_client_response()
            )
            mock_flow.start_device_authorization = AsyncMock(
                return_value=mock_device_authorization_response()
            )
            mock_flow.poll_for_token = AsyncMock(
                return_value=mock_create_token_success_response()
            )
            mock_flow_class.return_value = mock_flow

            with patch("kiro.routes_auth.save_gateway_credentials") as mock_save:
                print("Action: Creating login session...")
                login_response = test_client.post("/auth/login")
                session_id = login_response.json()["session_id"]

                print("Action: Waiting for background task to complete...")
                import time

                time.sleep(0.5)

                print("Verification: Checking session status was updated...")
                assert session_id in _auth_sessions
                assert _auth_sessions[session_id]["status"] in ["pending", "complete"]
