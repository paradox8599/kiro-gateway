# -*- coding: utf-8 -*-

import pytest
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime, timezone, timedelta

from kiro.device_auth import DeviceAuthFlow, DeviceAuthError


class TestDeviceAuthFlowRegisterClient:
    @pytest.mark.asyncio
    async def test_register_client_success(self, mock_register_client_response):
        """
        What it does: Tests successful OIDC client registration.
        Purpose: Verify that register_client() returns clientId and clientSecret.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking successful registration response...")
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value=mock_register_client_response())

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            print("Action: Calling register_client()...")
            result = await flow.register_client()

            print("Verification: Checking response structure...")
            assert "clientId" in result
            assert "clientSecret" in result
            assert result["clientId"] == "test_client_id_abc123"
            assert result["clientSecret"] == "test_client_secret_xyz789"

            print("Verification: Checking API call was made correctly...")
            mock_client.post.assert_called_once()
            call_args = mock_client.post.call_args
            assert "https://oidc.us-east-1.amazonaws.com/client/register" in str(
                call_args
            )

    @pytest.mark.asyncio
    async def test_register_client_http_error(self):
        """
        What it does: Tests handling of HTTP error during registration.
        Purpose: Verify that HTTP errors are properly handled.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking HTTP 500 error response...")
        mock_response = AsyncMock()
        mock_response.status_code = 500
        mock_response.json = Mock(
            return_value={
                "error": "server_error",
                "error_description": "Internal server error",
            }
        )

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            print("Action: Calling register_client() expecting error...")
            with pytest.raises(DeviceAuthError) as exc_info:
                await flow.register_client()

            print(f"Verification: DeviceAuthError raised: {exc_info.value}")
            assert exc_info.value.error_code == "server_error"

    @pytest.mark.asyncio
    async def test_register_client_missing_client_id(self):
        """
        What it does: Tests handling of missing clientId in response.
        Purpose: Verify that invalid responses are detected.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking response without clientId...")
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value={"clientSecret": "secret"})

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            print("Action: Calling register_client() expecting error...")
            with pytest.raises(DeviceAuthError) as exc_info:
                await flow.register_client()

            print(f"Verification: DeviceAuthError raised: {exc_info.value}")
            assert exc_info.value.error_code == "invalid_response"
            assert "clientId" in str(exc_info.value)


class TestDeviceAuthFlowStartDeviceAuth:
    @pytest.mark.asyncio
    async def test_start_device_authorization_success(
        self, mock_device_authorization_response
    ):
        """
        What it does: Tests successful device authorization start.
        Purpose: Verify that start_device_authorization() returns all required fields.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking successful device authorization response...")
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value=mock_device_authorization_response())

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            print("Action: Calling start_device_authorization()...")
            result = await flow.start_device_authorization("client_id", "client_secret")

            print("Verification: Checking all required fields present...")
            assert result["deviceCode"] == "test_device_code_abc123"
            assert result["userCode"] == "ABCD-EFGH"
            assert (
                result["verificationUri"]
                == "https://device.sso.us-east-1.amazonaws.com"
            )
            assert result["interval"] == 5
            assert result["expiresIn"] == 300

    @pytest.mark.asyncio
    async def test_start_device_authorization_missing_field(self):
        """
        What it does: Tests handling of missing required field in response.
        Purpose: Verify that incomplete responses are rejected.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking response without deviceCode...")
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = Mock(
            return_value={
                "userCode": "ABCD-EFGH",
                "verificationUri": "https://device.sso.us-east-1.amazonaws.com",
                "interval": 5,
                "expiresIn": 300,
            }
        )

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            print("Action: Calling start_device_authorization() expecting error...")
            with pytest.raises(DeviceAuthError) as exc_info:
                await flow.start_device_authorization("client_id", "client_secret")

            print(f"Verification: DeviceAuthError raised: {exc_info.value}")
            assert exc_info.value.error_code == "invalid_response"
            assert "deviceCode" in str(exc_info.value)


class TestDeviceAuthFlowPollForToken:
    @pytest.mark.asyncio
    async def test_poll_for_token_immediate_success(
        self, mock_create_token_success_response
    ):
        """
        What it does: Tests successful token retrieval on first poll.
        Purpose: Verify that poll_for_token() returns token on immediate success.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking immediate success response...")
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value=mock_create_token_success_response())

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with patch("kiro.device_auth.asyncio.sleep", new_callable=AsyncMock):
                print("Action: Calling poll_for_token()...")
                result = await flow.poll_for_token(
                    client_id="client_id",
                    client_secret="client_secret",
                    device_code="device_code",
                    interval=5,
                    expires_in=300,
                )

                print("Verification: Checking token returned...")
                assert result["accessToken"] == "test_access_token_abc123"
                assert result["refreshToken"] == "test_refresh_token_xyz789"
                assert result["expiresIn"] == 3600

    @pytest.mark.asyncio
    async def test_poll_for_token_pending_then_success(
        self, mock_create_token_pending_response, mock_create_token_success_response
    ):
        """
        What it does: Tests polling with authorization_pending then success.
        Purpose: Verify that poll_for_token() continues polling on pending status.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking pending then success responses...")
        pending_response = AsyncMock()
        pending_response.status_code = 400
        pending_response.json = Mock(return_value=mock_create_token_pending_response())

        success_response = AsyncMock()
        success_response.status_code = 200
        success_response.json = Mock(return_value=mock_create_token_success_response())

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(
                side_effect=[pending_response, success_response]
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with patch(
                "kiro.device_auth.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep:
                print("Action: Calling poll_for_token()...")
                result = await flow.poll_for_token(
                    client_id="client_id",
                    client_secret="client_secret",
                    device_code="device_code",
                    interval=5,
                    expires_in=300,
                )

                print("Verification: Checking token returned after retry...")
                assert result["accessToken"] == "test_access_token_abc123"
                assert mock_client.post.call_count == 2
                assert mock_sleep.call_count == 2

    @pytest.mark.asyncio
    async def test_poll_for_token_slow_down_increases_interval(
        self, mock_create_token_slow_down_response, mock_create_token_success_response
    ):
        """
        What it does: Tests that slow_down error increases polling interval.
        Purpose: Verify that poll_for_token() respects slow_down by increasing interval.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking slow_down then success responses...")
        slow_down_response = AsyncMock()
        slow_down_response.status_code = 400
        slow_down_response.json = Mock(
            return_value=mock_create_token_slow_down_response()
        )

        success_response = AsyncMock()
        success_response.status_code = 200
        success_response.json = Mock(return_value=mock_create_token_success_response())

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(
                side_effect=[slow_down_response, success_response]
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with patch(
                "kiro.device_auth.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep:
                print("Action: Calling poll_for_token()...")
                result = await flow.poll_for_token(
                    client_id="client_id",
                    client_secret="client_secret",
                    device_code="device_code",
                    interval=5,
                    expires_in=300,
                )

                print("Verification: Checking interval increased...")
                assert result["accessToken"] == "test_access_token_abc123"
                sleep_calls = [call[0][0] for call in mock_sleep.call_args_list]
                print(f"Sleep intervals: {sleep_calls}")
                assert sleep_calls[0] == 5
                assert sleep_calls[1] == 10

    @pytest.mark.asyncio
    async def test_poll_for_token_expired_token_error(
        self, mock_create_token_expired_response
    ):
        """
        What it does: Tests handling of expired_token error.
        Purpose: Verify that poll_for_token() raises DeviceAuthError on expired token.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking expired_token response...")
        mock_response = AsyncMock()
        mock_response.status_code = 400
        mock_response.json = Mock(return_value=mock_create_token_expired_response())

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with patch("kiro.device_auth.asyncio.sleep", new_callable=AsyncMock):
                print("Action: Calling poll_for_token() expecting error...")
                with pytest.raises(DeviceAuthError) as exc_info:
                    await flow.poll_for_token(
                        client_id="client_id",
                        client_secret="client_secret",
                        device_code="device_code",
                        interval=5,
                        expires_in=300,
                    )

                print(f"Verification: DeviceAuthError raised: {exc_info.value}")
                assert exc_info.value.error_code == "expired_token"

    @pytest.mark.asyncio
    async def test_poll_for_token_access_denied_error(
        self, mock_create_token_denied_response
    ):
        """
        What it does: Tests handling of access_denied error.
        Purpose: Verify that poll_for_token() raises DeviceAuthError on access denied.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking access_denied response...")
        mock_response = AsyncMock()
        mock_response.status_code = 400
        mock_response.json = Mock(return_value=mock_create_token_denied_response())

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with patch("kiro.device_auth.asyncio.sleep", new_callable=AsyncMock):
                print("Action: Calling poll_for_token() expecting error...")
                with pytest.raises(DeviceAuthError) as exc_info:
                    await flow.poll_for_token(
                        client_id="client_id",
                        client_secret="client_secret",
                        device_code="device_code",
                        interval=5,
                        expires_in=300,
                    )

                print(f"Verification: DeviceAuthError raised: {exc_info.value}")
                assert exc_info.value.error_code == "access_denied"

    @pytest.mark.asyncio
    async def test_poll_for_token_timeout(self, mock_create_token_pending_response):
        """
        What it does: Tests timeout when user never completes authorization.
        Purpose: Verify that poll_for_token() raises DeviceAuthError on timeout.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking continuous pending responses...")
        mock_response = AsyncMock()
        mock_response.status_code = 400
        mock_response.json = Mock(return_value=mock_create_token_pending_response())

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with patch("kiro.device_auth.asyncio.sleep", new_callable=AsyncMock):
                with patch("kiro.device_auth.datetime") as mock_datetime:
                    now = datetime.now(timezone.utc)
                    mock_datetime.now.side_effect = [
                        now,
                        now + timedelta(seconds=10),
                        now + timedelta(seconds=301),
                    ]
                    mock_datetime.side_effect = lambda *args, **kw: datetime(
                        *args, **kw
                    )

                    print("Action: Calling poll_for_token() expecting timeout...")
                    with pytest.raises(DeviceAuthError) as exc_info:
                        await flow.poll_for_token(
                            client_id="client_id",
                            client_secret="client_secret",
                            device_code="device_code",
                            interval=5,
                            expires_in=300,
                        )

                    print(f"Verification: DeviceAuthError raised: {exc_info.value}")
                    assert exc_info.value.error_code == "expired_token"
                    assert "expired before user completed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_poll_for_token_missing_access_token(self):
        """
        What it does: Tests handling of success response without accessToken.
        Purpose: Verify that invalid success responses are detected.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking success response without accessToken...")
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = Mock(
            return_value={"refreshToken": "token", "expiresIn": 3600}
        )

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with patch("kiro.device_auth.asyncio.sleep", new_callable=AsyncMock):
                print("Action: Calling poll_for_token() expecting error...")
                with pytest.raises(DeviceAuthError) as exc_info:
                    await flow.poll_for_token(
                        client_id="client_id",
                        client_secret="client_secret",
                        device_code="device_code",
                        interval=5,
                        expires_in=300,
                    )

                print(f"Verification: DeviceAuthError raised: {exc_info.value}")
                assert exc_info.value.error_code == "invalid_response"
                assert "accessToken" in str(exc_info.value)


class TestDeviceAuthFlowRunDeviceFlow:
    @pytest.mark.asyncio
    async def test_run_device_flow_success(
        self,
        mock_register_client_response,
        mock_device_authorization_response,
        mock_create_token_success_response,
        capsys,
    ):
        """
        What it does: Tests complete device flow from start to finish.
        Purpose: Verify that run_device_flow() orchestrates all steps correctly.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking all responses...")
        register_response = AsyncMock()
        register_response.status_code = 200
        register_response.json = Mock(return_value=mock_register_client_response())

        device_auth_response = AsyncMock()
        device_auth_response.status_code = 200
        device_auth_response.json = Mock(
            return_value=mock_device_authorization_response()
        )

        token_response = AsyncMock()
        token_response.status_code = 200
        token_response.json = Mock(return_value=mock_create_token_success_response())

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(
                side_effect=[register_response, device_auth_response, token_response]
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with patch("kiro.device_auth.asyncio.sleep", new_callable=AsyncMock):
                print("Action: Calling run_device_flow()...")
                result = await flow.run_device_flow()

                print("Verification: Checking credentials structure...")
                assert result["accessToken"] == "test_access_token_abc123"
                assert result["refreshToken"] == "test_refresh_token_xyz789"
                assert result["clientId"] == "test_client_id_abc123"
                assert result["clientSecret"] == "test_client_secret_xyz789"
                assert result["region"] == "us-east-1"
                assert "expiresAt" in result

                print("Verification: Checking user instructions printed...")
                captured = capsys.readouterr()
                assert "AWS Builder ID Authentication" in captured.out
                assert "ABCD-EFGH" in captured.out
                assert "https://device.sso.us-east-1.amazonaws.com" in captured.out

    @pytest.mark.asyncio
    async def test_run_device_flow_registration_fails(self):
        """
        What it does: Tests handling of registration failure.
        Purpose: Verify that run_device_flow() propagates registration errors.
        """
        print("Setup: Creating DeviceAuthFlow...")
        flow = DeviceAuthFlow(region="us-east-1")

        print("Setup: Mocking registration failure...")
        mock_response = AsyncMock()
        mock_response.status_code = 400
        mock_response.json = Mock(
            return_value={
                "error": "invalid_request",
                "error_description": "Invalid client name",
            }
        )

        with patch("kiro.device_auth.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            print("Action: Calling run_device_flow() expecting error...")
            with pytest.raises(DeviceAuthError) as exc_info:
                await flow.run_device_flow()

            print(f"Verification: DeviceAuthError raised: {exc_info.value}")
            assert exc_info.value.error_code == "invalid_request"


class TestDeviceAuthError:
    def test_device_auth_error_with_description(self):
        """
        What it does: Tests DeviceAuthError with error description.
        Purpose: Verify that error message includes both code and description.
        """
        print("Action: Creating DeviceAuthError with description...")
        error = DeviceAuthError("expired_token", "Device code has expired")

        print("Verification: Checking error attributes...")
        assert error.error_code == "expired_token"
        assert error.error_description == "Device code has expired"
        assert "expired_token" in str(error)
        assert "Device code has expired" in str(error)

    def test_device_auth_error_without_description(self):
        """
        What it does: Tests DeviceAuthError without error description.
        Purpose: Verify that error message works with just error code.
        """
        print("Action: Creating DeviceAuthError without description...")
        error = DeviceAuthError("access_denied")

        print("Verification: Checking error attributes...")
        assert error.error_code == "access_denied"
        assert error.error_description == ""
        assert "access_denied" in str(error)
