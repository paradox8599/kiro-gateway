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
Account manager for multi-account support.

Manages multiple Kiro accounts with:
- Round-robin selection for load balancing
- Per-account token refresh
- Automatic failure tracking and account disabling
- Rate limit and payment error handling
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx
from loguru import logger

from kiro.config import (
    save_gateway_credentials,
    update_credential_status,
    get_kiro_refresh_url,
    get_aws_sso_oidc_url,
)
from kiro.utils import get_machine_fingerprint


class AccountManager:
    """
    Manages multiple Kiro accounts with round-robin selection.

    Provides:
    - Round-robin account selection across enabled accounts
    - Per-account token refresh (AWS SSO OIDC or Kiro Desktop Auth)
    - Automatic failure tracking with auto-disable after MAX_CONSECUTIVE_FAILURES
    - Rate limit and payment error handling

    Attributes:
        MAX_CONSECUTIVE_FAILURES: Number of failures before auto-disabling account
    """

    MAX_CONSECUTIVE_FAILURES = 5

    def __init__(self, credentials: list[dict], region: str = "us-east-1"):
        """
        Initialize AccountManager with credentials.

        Args:
            credentials: List of credential dictionaries, each containing:
                - accessToken: Current access token
                - refreshToken: Token for refreshing access
                - clientId: (optional) AWS SSO client ID
                - clientSecret: (optional) AWS SSO client secret
                - expiresAt: ISO format expiration timestamp
                - region: AWS region for this account
                - email: Account email identifier
                - enabled: Whether account is active (default True)
                - failureCount: Consecutive failure count (default 0)
            region: Default AWS region (used if account doesn't specify)
        """
        self._accounts = credentials
        self._current_index = 0
        self._region = region
        self._lock = asyncio.Lock()
        self._fingerprint = get_machine_fingerprint()

        for account in self._accounts:
            if "enabled" not in account:
                account["enabled"] = True
            if "failureCount" not in account:
                account["failureCount"] = 0

    def get_enabled_accounts(self) -> list[tuple[int, dict]]:
        """
        Get list of enabled accounts with their indices.

        Returns:
            List of (index, account) tuples for all enabled accounts
        """
        return [
            (i, account)
            for i, account in enumerate(self._accounts)
            if account.get("enabled", True)
        ]

    def get_next_account(self) -> Optional[tuple[int, dict]]:
        """
        Get next enabled account using round-robin selection.

        Advances internal index and skips disabled accounts.

        Returns:
            Tuple of (index, account) for next enabled account, or None if no enabled accounts
        """
        enabled = self.get_enabled_accounts()
        if not enabled:
            logger.warning("No enabled accounts available")
            return None

        num_accounts = len(self._accounts)
        for _ in range(num_accounts):
            index = self._current_index % num_accounts
            self._current_index = (self._current_index + 1) % num_accounts

            account = self._accounts[index]
            if account.get("enabled", True):
                logger.debug(
                    f"Selected account {index}: {account.get('email', 'unknown')}"
                )
                return (index, account)

        return None

    async def get_valid_token(self, index: int) -> str:
        """
        Get valid access token for account, refreshing if needed.

        Thread-safe method using asyncio.Lock.

        Args:
            index: Index of account in credentials list

        Returns:
            Valid access token

        Raises:
            IndexError: If index is out of range
            ValueError: If token refresh fails
        """
        if index < 0 or index >= len(self._accounts):
            raise IndexError(f"Account index {index} out of range")

        async with self._lock:
            account = self._accounts[index]

            if not self._is_token_expiring_soon(account):
                return account.get("accessToken", "")

            logger.info(
                f"Refreshing token for account {index}: {account.get('email', 'unknown')}"
            )
            await self._refresh_token(index)

            return self._accounts[index].get("accessToken", "")

    def mark_success(self, index: int) -> None:
        """
        Mark successful request for account, resetting failure count.

        Args:
            index: Index of account in credentials list
        """
        if 0 <= index < len(self._accounts):
            self._accounts[index]["failureCount"] = 0
            update_credential_status(
                index, self._accounts[index].get("enabled", True), 0
            )
            logger.debug(f"Account {index} success, failure count reset")

    def mark_failure(self, index: int) -> bool:
        """
        Mark failed request for account, incrementing failure count.

        Auto-disables account after MAX_CONSECUTIVE_FAILURES.

        Args:
            index: Index of account in credentials list

        Returns:
            True if account was auto-disabled, False otherwise
        """
        if not (0 <= index < len(self._accounts)):
            return False

        account = self._accounts[index]
        failure_count = account.get("failureCount", 0) + 1
        account["failureCount"] = failure_count

        logger.warning(
            f"Account {index} failure #{failure_count}: {account.get('email', 'unknown')}"
        )

        if failure_count >= self.MAX_CONSECUTIVE_FAILURES:
            logger.error(
                f"Account {index} disabled after {failure_count} consecutive failures: "
                f"{account.get('email', 'unknown')}"
            )
            account["enabled"] = False
            update_credential_status(index, False, failure_count)
            return True

        update_credential_status(index, account.get("enabled", True), failure_count)
        return False

    def handle_rate_limit(self, index: int) -> Optional[tuple[int, dict]]:
        """
        Handle rate limit error by returning next enabled account.

        Does not disable the rate-limited account (temporary condition).

        Args:
            index: Index of rate-limited account

        Returns:
            Tuple of (index, account) for next enabled account, or None if none available
        """
        logger.warning(f"Account {index} rate limited, trying next account")
        return self.get_next_account()

    def handle_payment_required(self, index: int) -> Optional[tuple[int, dict]]:
        """
        Handle payment required error by disabling account and returning next.

        Disables the account since payment issues are not temporary.

        Args:
            index: Index of account with payment issue

        Returns:
            Tuple of (index, account) for next enabled account, or None if none available
        """
        if 0 <= index < len(self._accounts):
            account = self._accounts[index]
            logger.error(
                f"Account {index} disabled due to payment required: "
                f"{account.get('email', 'unknown')}"
            )
            self.disable_account(index)

        return self.get_next_account()

    def disable_account(self, index: int) -> None:
        """
        Disable account and persist to storage.

        Args:
            index: Index of account to disable
        """
        if 0 <= index < len(self._accounts):
            self._accounts[index]["enabled"] = False
            update_credential_status(
                index, False, self._accounts[index].get("failureCount", 0)
            )
            logger.info(
                f"Account {index} disabled: {self._accounts[index].get('email', 'unknown')}"
            )

    def enable_account(self, index: int) -> None:
        """
        Enable account, reset failures, and persist to storage.

        Args:
            index: Index of account to enable
        """
        if 0 <= index < len(self._accounts):
            self._accounts[index]["enabled"] = True
            self._accounts[index]["failureCount"] = 0
            update_credential_status(index, True, 0)
            logger.info(
                f"Account {index} enabled: {self._accounts[index].get('email', 'unknown')}"
            )

    def remove_account(self, index: int) -> None:
        """
        Remove account from array and persist to storage.

        Args:
            index: Index of account to remove
        """
        if 0 <= index < len(self._accounts):
            email = self._accounts[index].get("email", "unknown")
            self._accounts.pop(index)
            save_gateway_credentials(self._accounts)
            logger.info(f"Account {index} removed: {email}")

            if self._current_index >= len(self._accounts) and len(self._accounts) > 0:
                self._current_index = 0

    def get_all_accounts(self) -> list[dict]:
        """
        Get all accounts with sensitive fields masked.

        Returns:
            List of account dictionaries with tokens masked/omitted
        """
        masked_accounts = []
        for account in self._accounts:
            masked = {
                "email": account.get("email", "unknown"),
                "region": account.get("region", self._region),
                "enabled": account.get("enabled", True),
                "failureCount": account.get("failureCount", 0),
                "expiresAt": account.get("expiresAt", ""),
            }
            masked_accounts.append(masked)
        return masked_accounts

    def _is_token_expiring_soon(
        self, account: dict, threshold_seconds: int = 300
    ) -> bool:
        """
        Check if account token is expiring within threshold.

        Args:
            account: Account dictionary with expiresAt field
            threshold_seconds: Seconds before expiration to consider "expiring soon"

        Returns:
            True if token is expired or expiring soon
        """
        expires_at_str = account.get("expiresAt", "")
        if not expires_at_str:
            return True  # No expiration info, assume expired

        try:
            expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            threshold = timedelta(seconds=threshold_seconds)

            return now >= (expires_at - threshold)
        except (ValueError, TypeError):
            logger.warning(f"Invalid expiresAt format: {expires_at_str}")
            return True

    async def _refresh_token(self, index: int) -> None:
        """
        Refresh token for account using appropriate auth method.

        Detects auth type based on presence of clientId/clientSecret:
        - With clientId/clientSecret: AWS SSO OIDC
        - Without: Kiro Desktop Auth

        Args:
            index: Index of account to refresh

        Raises:
            ValueError: If refresh fails or required credentials missing
        """
        account = self._accounts[index]

        has_client_credentials = bool(
            account.get("clientId") and account.get("clientSecret")
        )

        if has_client_credentials:
            await self._refresh_token_aws_sso_oidc(index)
        else:
            await self._refresh_token_kiro_desktop(index)

    async def _refresh_token_kiro_desktop(self, index: int) -> None:
        """
        Refresh token using Kiro Desktop Auth endpoint.

        Endpoint: https://prod.{region}.auth.desktop.kiro.dev/refreshToken

        Args:
            index: Index of account to refresh

        Raises:
            ValueError: If refresh token missing or response invalid
        """
        account = self._accounts[index]
        refresh_token = account.get("refreshToken")

        if not refresh_token:
            raise ValueError(f"Account {index} has no refresh token")

        region = account.get("region", self._region)
        url = get_kiro_refresh_url(region)

        payload = {"refreshToken": refresh_token}
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"KiroIDE-0.7.45-{self._fingerprint}",
        }

        logger.debug(f"Refreshing account {index} via Kiro Desktop Auth")

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        new_access_token = data.get("accessToken")
        if not new_access_token:
            raise ValueError(f"Response does not contain accessToken: {data}")

        account["accessToken"] = new_access_token
        if data.get("refreshToken"):
            account["refreshToken"] = data["refreshToken"]

        expires_in = data.get("expiresIn", 3600)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)
        account["expiresAt"] = expires_at.isoformat()

        save_gateway_credentials(self._accounts)

        logger.info(
            f"Account {index} token refreshed via Kiro Desktop Auth, expires: {account['expiresAt']}"
        )

    async def _refresh_token_aws_sso_oidc(self, index: int) -> None:
        """
        Refresh token using AWS SSO OIDC endpoint.

        Endpoint: https://oidc.{region}.amazonaws.com/token

        Args:
            index: Index of account to refresh

        Raises:
            ValueError: If required credentials missing or response invalid
        """
        account = self._accounts[index]

        refresh_token = account.get("refreshToken")
        client_id = account.get("clientId")
        client_secret = account.get("clientSecret")

        if not refresh_token:
            raise ValueError(f"Account {index} has no refresh token")
        if not client_id:
            raise ValueError(f"Account {index} has no client ID")
        if not client_secret:
            raise ValueError(f"Account {index} has no client secret")

        region = account.get("region", self._region)
        url = get_aws_sso_oidc_url(region)

        payload = {
            "grantType": "refresh_token",
            "clientId": client_id,
            "clientSecret": client_secret,
            "refreshToken": refresh_token,
        }
        headers = {"Content-Type": "application/json"}

        logger.debug(f"Refreshing account {index} via AWS SSO OIDC")

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(url, json=payload, headers=headers)

            if response.status_code != 200:
                error_body = response.text
                logger.error(
                    f"AWS SSO OIDC refresh failed: status={response.status_code}, body={error_body}"
                )
                response.raise_for_status()

            data = response.json()

        new_access_token = data.get("accessToken")
        if not new_access_token:
            raise ValueError(
                f"AWS SSO OIDC response does not contain accessToken: {data}"
            )

        account["accessToken"] = new_access_token
        if data.get("refreshToken"):
            account["refreshToken"] = data["refreshToken"]

        expires_in = data.get("expiresIn", 3600)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)
        account["expiresAt"] = expires_at.isoformat()

        save_gateway_credentials(self._accounts)

        logger.info(
            f"Account {index} token refreshed via AWS SSO OIDC, expires: {account['expiresAt']}"
        )
