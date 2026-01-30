# -*- coding: utf-8 -*-

# Kiro Gateway
# https://github.com/jwadow/kiro-gateway
# Copyright (C) 2025 Jwadow
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Device Authorization Flow for AWS Builder ID OAuth.

Implements OAuth 2.0 Device Authorization Grant (RFC 8628) for headless/CLI
authentication with AWS Builder ID. This allows users to authenticate via
a browser on a separate device while the application polls for completion.

Flow:
1. Register OIDC client -> get clientId, clientSecret
2. Start device authorization -> get deviceCode, userCode, verificationUri
3. User visits URL and authenticates in browser
4. Poll for token until user completes auth or timeout
5. Return credentials compatible with KiroAuthManager
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

import httpx
from loguru import logger


class DeviceAuthError(Exception):
    """
    Exception raised for device authorization flow errors.

    Attributes:
        error_code: The OAuth error code (e.g., 'expired_token', 'access_denied')
        error_description: Human-readable error description
    """

    def __init__(self, error_code: str, error_description: str = ""):
        self.error_code = error_code
        self.error_description = error_description
        message = (
            f"{error_code}: {error_description}" if error_description else error_code
        )
        super().__init__(message)


class DeviceAuthFlow:
    """
    Implements OAuth 2.0 Device Authorization Grant for AWS Builder ID.

    This class handles the complete device code flow:
    1. Client registration with AWS SSO OIDC
    2. Device authorization request
    3. Token polling with proper error handling

    Args:
        region: AWS region for OIDC endpoint (default: us-east-1)

    Example:
        >>> flow = DeviceAuthFlow("us-east-1")
        >>> credentials = await flow.run_device_flow()
        >>> print(f"Visit: {credentials['verificationUriComplete']}")
        >>> # User authenticates in browser...
        >>> # credentials dict contains accessToken, refreshToken, etc.
    """

    # Default scopes for Kiro/CodeWhisperer access
    DEFAULT_SCOPES = [
        "codewhisperer:completions",
        "codewhisperer:analysis",
        "codewhisperer:conversations",
    ]

    # Default start URL for AWS Builder ID
    DEFAULT_START_URL = "https://view.awsapps.com/start"

    # Default polling timeout in seconds (5 minutes)
    DEFAULT_POLL_TIMEOUT = 300

    def __init__(self, region: str = "us-east-1"):
        """
        Initialize DeviceAuthFlow with AWS region.

        Args:
            region: AWS region for OIDC endpoint (e.g., 'us-east-1')
        """
        self._region = region
        self._base_url = f"https://oidc.{region}.amazonaws.com"

    async def register_client(self) -> Dict[str, str]:
        """
        Register an OIDC client with AWS SSO.

        This is Step 1 of the device authorization flow. Registers a public
        client with AWS SSO OIDC and returns client credentials.

        Returns:
            Dict containing:
                - clientId: The registered client ID
                - clientSecret: The client secret for token requests

        Raises:
            httpx.HTTPStatusError: On HTTP error from AWS
            DeviceAuthError: On AWS-specific error response

        Example:
            >>> flow = DeviceAuthFlow("us-east-1")
            >>> client = await flow.register_client()
            >>> print(client["clientId"])
        """
        url = f"{self._base_url}/client/register"

        payload = {
            "clientName": "Kiro Gateway",
            "clientType": "public",
            "scopes": self.DEFAULT_SCOPES,
        }

        headers = {
            "Content-Type": "application/json",
        }

        logger.debug(f"Registering OIDC client at {url}")

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(url, json=payload, headers=headers)

            if response.status_code != 200:
                self._handle_error_response(response, "Client registration failed")

            result = response.json()

        client_id = result.get("clientId")
        client_secret = result.get("clientSecret")

        if not client_id or not client_secret:
            raise DeviceAuthError(
                "invalid_response",
                f"Missing clientId or clientSecret in response: {result}",
            )

        logger.info(f"OIDC client registered: {client_id[:8]}...")

        return {
            "clientId": client_id,
            "clientSecret": client_secret,
        }

    async def start_device_authorization(
        self,
        client_id: str,
        client_secret: str,
    ) -> Dict[str, Any]:
        """
        Start device authorization flow.

        This is Step 2 of the device authorization flow. Requests a device code
        and verification URL that the user must visit to authenticate.

        Args:
            client_id: Client ID from register_client()
            client_secret: Client secret from register_client()

        Returns:
            Dict containing:
                - deviceCode: Code for polling token endpoint
                - userCode: Code to display to user (e.g., "ABCD-EFGH")
                - verificationUri: URL for user to visit
                - verificationUriComplete: URL with userCode embedded
                - expiresIn: Seconds until deviceCode expires
                - interval: Polling interval in seconds

        Raises:
            httpx.HTTPStatusError: On HTTP error from AWS
            DeviceAuthError: On AWS-specific error response

        Example:
            >>> device_auth = await flow.start_device_authorization(client_id, client_secret)
            >>> print(f"Visit: {device_auth['verificationUriComplete']}")
            >>> print(f"Code: {device_auth['userCode']}")
        """
        url = f"{self._base_url}/device_authorization"

        payload = {
            "clientId": client_id,
            "clientSecret": client_secret,
            "startUrl": self.DEFAULT_START_URL,
        }

        headers = {
            "Content-Type": "application/json",
        }

        logger.debug(f"Starting device authorization at {url}")

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(url, json=payload, headers=headers)

            if response.status_code != 200:
                self._handle_error_response(response, "Device authorization failed")

            result = response.json()

        # Validate required fields
        required_fields = [
            "deviceCode",
            "userCode",
            "verificationUri",
            "expiresIn",
            "interval",
        ]
        for field in required_fields:
            if field not in result:
                raise DeviceAuthError(
                    "invalid_response", f"Missing required field '{field}' in response"
                )

        logger.info(f"Device authorization started, user code: {result['userCode']}")

        return result

    async def poll_for_token(
        self,
        client_id: str,
        client_secret: str,
        device_code: str,
        interval: int,
        expires_in: int,
    ) -> Dict[str, Any]:
        """
        Poll for access token after user completes authorization.

        This is Step 3 of the device authorization flow. Polls the token endpoint
        until the user completes authentication or the device code expires.

        Args:
            client_id: Client ID from register_client()
            client_secret: Client secret from register_client()
            device_code: Device code from start_device_authorization()
            interval: Polling interval in seconds (from start_device_authorization)
            expires_in: Seconds until device code expires

        Returns:
            Dict containing:
                - accessToken: The access token for API calls
                - refreshToken: Token for refreshing access token
                - expiresIn: Seconds until access token expires

        Raises:
            DeviceAuthError: On expired_token, access_denied, or other fatal errors
            httpx.HTTPStatusError: On unexpected HTTP errors

        Example:
            >>> token = await flow.poll_for_token(
            ...     client_id, client_secret, device_code, interval=5, expires_in=300
            ... )
            >>> print(f"Access token: {token['accessToken'][:20]}...")
        """
        url = f"{self._base_url}/token"

        payload = {
            "clientId": client_id,
            "clientSecret": client_secret,
            "deviceCode": device_code,
            "grantType": "urn:ietf:params:oauth:grant-type:device_code",
        }

        headers = {
            "Content-Type": "application/json",
        }

        current_interval = interval
        deadline = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        logger.info(
            f"Polling for token (interval={current_interval}s, timeout={expires_in}s)"
        )

        while datetime.now(timezone.utc) < deadline:
            # Wait before polling (as per RFC 8628)
            await asyncio.sleep(current_interval)

            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(url, json=payload, headers=headers)

            # Success - user completed authorization
            if response.status_code == 200:
                result = response.json()

                access_token = result.get("accessToken")
                if not access_token:
                    raise DeviceAuthError(
                        "invalid_response", "Missing accessToken in token response"
                    )

                logger.info("Token obtained successfully")
                return result

            # Handle error responses
            try:
                error_data = response.json()
                error_code = error_data.get("error", "unknown_error")
                error_desc = error_data.get("error_description", "")
            except Exception:
                # Non-JSON error response
                response.raise_for_status()
                continue

            # authorization_pending - user hasn't completed auth yet
            if error_code == "authorization_pending":
                logger.debug("Authorization pending, continuing to poll...")
                continue

            # slow_down - increase polling interval
            if error_code == "slow_down":
                current_interval += 5
                logger.warning(
                    f"Received slow_down, increasing interval to {current_interval}s"
                )
                continue

            # Fatal errors - stop polling
            if error_code in ("expired_token", "access_denied"):
                logger.error(f"Device auth failed: {error_code} - {error_desc}")
                raise DeviceAuthError(error_code, error_desc)

            # Unknown error - treat as fatal
            logger.error(
                f"Unexpected error during polling: {error_code} - {error_desc}"
            )
            raise DeviceAuthError(error_code, error_desc)

        # Timeout - device code expired
        raise DeviceAuthError(
            "expired_token", "Device code expired before user completed authorization"
        )

    async def run_device_flow(self) -> Dict[str, Any]:
        """
        Run the complete device authorization flow.

        This is the main entry point that orchestrates all steps:
        1. Register OIDC client
        2. Start device authorization
        3. Print verification URL for user
        4. Poll for token completion
        5. Return credentials compatible with KiroAuthManager

        Returns:
            Dict containing credentials:
                - accessToken: The access token for API calls
                - refreshToken: Token for refreshing access token
                - clientId: Client ID for token refresh
                - clientSecret: Client secret for token refresh
                - expiresAt: ISO 8601 timestamp of token expiration
                - region: AWS region used for authentication

        Raises:
            DeviceAuthError: On any authentication error
            httpx.HTTPStatusError: On unexpected HTTP errors

        Example:
            >>> flow = DeviceAuthFlow("us-east-1")
            >>> creds = await flow.run_device_flow()
            >>> # User must visit the printed URL and authenticate
            >>> print(f"Authenticated! Token expires: {creds['expiresAt']}")
        """
        logger.info(f"Starting device authorization flow (region={self._region})")

        # Step 1: Register client
        client_reg = await self.register_client()
        client_id = client_reg["clientId"]
        client_secret = client_reg["clientSecret"]

        # Step 2: Start device authorization
        device_auth = await self.start_device_authorization(client_id, client_secret)

        # Display authorization URL to user (DO NOT auto-open browser)
        verification_url = device_auth.get(
            "verificationUriComplete", device_auth["verificationUri"]
        )
        user_code = device_auth["userCode"]

        print("\n" + "=" * 60)
        print("AWS Builder ID Authentication")
        print("=" * 60)
        print(f"\nPlease visit: {verification_url}")
        print(f"User code: {user_code}")
        print("\nWaiting for authentication...")
        print("=" * 60 + "\n")

        # Step 3: Poll for token
        token_response = await self.poll_for_token(
            client_id=client_id,
            client_secret=client_secret,
            device_code=device_auth["deviceCode"],
            interval=device_auth["interval"],
            expires_in=device_auth["expiresIn"],
        )

        # Calculate expiration time
        expires_in = token_response.get("expiresIn", 3600)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        # Build credentials dict compatible with KiroAuthManager
        credentials = {
            "accessToken": token_response["accessToken"],
            "refreshToken": token_response.get("refreshToken", ""),
            "clientId": client_id,
            "clientSecret": client_secret,
            "expiresAt": expires_at.isoformat(),
            "region": self._region,
        }

        logger.info(
            f"Device authorization completed, token expires: {expires_at.isoformat()}"
        )

        return credentials

    def _handle_error_response(self, response: httpx.Response, context: str) -> None:
        """
        Handle error response from AWS OIDC endpoint.

        Parses AWS error format and raises appropriate exception.

        Args:
            response: The HTTP response object
            context: Description of the operation that failed

        Raises:
            DeviceAuthError: With parsed error code and description
            httpx.HTTPStatusError: If response is not valid AWS error format
        """
        try:
            error_data = response.json()
            error_code = error_data.get("error", "unknown_error")
            error_desc = error_data.get("error_description", response.text)
            logger.error(f"{context}: {error_code} - {error_desc}")
            raise DeviceAuthError(error_code, error_desc)
        except (ValueError, KeyError):
            # Not a valid JSON error response
            logger.error(f"{context}: HTTP {response.status_code} - {response.text}")
            response.raise_for_status()
