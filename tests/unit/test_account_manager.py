# -*- coding: utf-8 -*-

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timezone, timedelta

from kiro.account_manager import AccountManager


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def make_test_credential():
    """
    Factory for creating test credentials.
    """

    def _create(
        email: str,
        enabled: bool = True,
        failure_count: int = 0,
        expires_at: str = None,
    ) -> dict:
        if expires_at is None:
            # Default: expires in 1 hour
            expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        return {
            "email": email,
            "enabled": enabled,
            "failureCount": failure_count,
            "accessToken": f"token_{email}",
            "refreshToken": f"refresh_{email}",
            "clientId": "test_client_id",
            "clientSecret": "test_client_secret",
            "expiresAt": expires_at,
            "region": "us-east-1",
        }

    return _create


@pytest.fixture
def sample_credentials(make_test_credential):
    """
    Returns a list of 3 test credentials.
    """
    return [
        make_test_credential("user1@example.com"),
        make_test_credential("user2@example.com"),
        make_test_credential("user3@example.com"),
    ]


@pytest.fixture
def mock_save_functions():
    """
    Mocks save_gateway_credentials and update_credential_status to avoid file I/O.
    """
    with (
        patch("kiro.account_manager.save_gateway_credentials") as mock_save,
        patch("kiro.account_manager.update_credential_status") as mock_update,
    ):
        yield {"save": mock_save, "update": mock_update}


# =============================================================================
# Test Round-Robin Selection
# =============================================================================


class TestRoundRobinSelection:
    def test_round_robin_selection(self, sample_credentials, mock_save_functions):
        """
        What it does: Tests that get_next_account() cycles through enabled accounts.
        Purpose: Verify round-robin load balancing works correctly.
        """
        print("Setup: Creating AccountManager with 3 accounts...")
        manager = AccountManager(sample_credentials)

        print("Action: Getting next account 3 times...")
        result1 = manager.get_next_account()
        result2 = manager.get_next_account()
        result3 = manager.get_next_account()

        print("Verification: Checking round-robin order...")
        assert result1 is not None
        assert result2 is not None
        assert result3 is not None

        index1, account1 = result1
        index2, account2 = result2
        index3, account3 = result3

        assert index1 == 0
        assert index2 == 1
        assert index3 == 2
        assert account1["email"] == "user1@example.com"
        assert account2["email"] == "user2@example.com"
        assert account3["email"] == "user3@example.com"

        print("Action: Getting 4th account (should wrap to first)...")
        result4 = manager.get_next_account()
        index4, account4 = result4
        assert index4 == 0
        assert account4["email"] == "user1@example.com"

    def test_skip_disabled_accounts(self, make_test_credential, mock_save_functions):
        """
        What it does: Tests that round-robin skips disabled accounts.
        Purpose: Verify disabled accounts are not selected.
        """
        print("Setup: Creating credentials with middle account disabled...")
        credentials = [
            make_test_credential("user1@example.com", enabled=True),
            make_test_credential("user2@example.com", enabled=False),
            make_test_credential("user3@example.com", enabled=True),
        ]
        manager = AccountManager(credentials)

        print("Action: Getting next account 3 times...")
        result1 = manager.get_next_account()
        result2 = manager.get_next_account()
        result3 = manager.get_next_account()

        print("Verification: Checking that disabled account is skipped...")
        index1, account1 = result1
        index2, account2 = result2
        index3, account3 = result3

        # Should get account 0, then skip 1 (disabled), get 2, then wrap to 0
        assert index1 == 0
        assert account1["email"] == "user1@example.com"
        assert index2 == 2
        assert account2["email"] == "user3@example.com"
        assert index3 == 0
        assert account3["email"] == "user1@example.com"


# =============================================================================
# Test Failure Tracking
# =============================================================================


class TestFailureTracking:
    def test_mark_success_resets_failures(
        self, sample_credentials, mock_save_functions
    ):
        """
        What it does: Tests that mark_success() resets failureCount to 0 for THIS account only.
        Purpose: Verify success resets failure count for the specific account.
        """
        print("Setup: Creating AccountManager with accounts having failures...")
        credentials = sample_credentials.copy()
        credentials[0]["failureCount"] = 3
        credentials[1]["failureCount"] = 2
        manager = AccountManager(credentials)

        print("Action: Marking account 0 as success...")
        manager.mark_success(0)

        print("Verification: Checking account 0 failure count reset...")
        assert manager._accounts[0]["failureCount"] == 0
        print("Verification: Checking account 1 failure count unchanged...")
        assert manager._accounts[1]["failureCount"] == 2

        print("Verification: Checking update_credential_status called...")
        mock_save_functions["update"].assert_called_with(0, True, 0)

    def test_mark_failure_increments_count(
        self, sample_credentials, mock_save_functions
    ):
        """
        What it does: Tests that mark_failure() increments failureCount.
        Purpose: Verify failure tracking increments correctly.
        """
        print("Setup: Creating AccountManager...")
        manager = AccountManager(sample_credentials)

        print("Action: Marking account 0 as failure...")
        auto_disabled = manager.mark_failure(0)

        print("Verification: Checking failure count incremented...")
        assert manager._accounts[0]["failureCount"] == 1
        assert auto_disabled is False

        print("Action: Marking account 0 as failure again...")
        auto_disabled = manager.mark_failure(0)
        assert manager._accounts[0]["failureCount"] == 2
        assert auto_disabled is False

    def test_auto_disable_after_5_failures(
        self, sample_credentials, mock_save_functions
    ):
        """
        What it does: Tests that 5 consecutive failures trigger auto-disable.
        Purpose: Verify MAX_CONSECUTIVE_FAILURES threshold works.
        """
        print("Setup: Creating AccountManager...")
        manager = AccountManager(sample_credentials)

        print("Action: Marking account 0 as failure 4 times...")
        for i in range(4):
            auto_disabled = manager.mark_failure(0)
            assert auto_disabled is False
            assert manager._accounts[0]["enabled"] is True

        print("Action: Marking account 0 as failure 5th time...")
        auto_disabled = manager.mark_failure(0)

        print("Verification: Checking account auto-disabled...")
        assert auto_disabled is True
        assert manager._accounts[0]["enabled"] is False
        assert manager._accounts[0]["failureCount"] == 5

        print("Verification: Checking update_credential_status called...")
        mock_save_functions["update"].assert_called_with(0, False, 5)


# =============================================================================
# Test Rate Limit Handling
# =============================================================================


class TestRateLimitHandling:
    def test_handle_rate_limit_switches_account(
        self, sample_credentials, mock_save_functions
    ):
        """
        What it does: Tests that handle_rate_limit() returns next account without disabling.
        Purpose: Verify rate limit handling doesn't disable account (temporary condition).
        """
        print("Setup: Creating AccountManager with 3 accounts...")
        manager = AccountManager(sample_credentials)

        print("Action: Advance to account 1 first...")
        manager.get_next_account()

        print("Action: Handling rate limit on account 0...")
        result = manager.handle_rate_limit(0)

        print("Verification: Checking next account returned...")
        assert result is not None
        index, account = result
        assert index == 1
        assert account["email"] == "user2@example.com"

        print("Verification: Checking account 0 still enabled...")
        assert manager._accounts[0]["enabled"] is True

    def test_handle_payment_required_disables_and_switches(
        self, sample_credentials, mock_save_functions
    ):
        """
        What it does: Tests that handle_payment_required() disables account and returns next.
        Purpose: Verify payment errors disable account (permanent condition).
        """
        print("Setup: Creating AccountManager with 3 accounts...")
        manager = AccountManager(sample_credentials)

        print("Action: Handling payment required on account 0...")
        result = manager.handle_payment_required(0)

        print("Verification: Checking account 0 disabled...")
        assert manager._accounts[0]["enabled"] is False

        print("Verification: Checking next account returned...")
        assert result is not None
        index, account = result
        assert index == 1
        assert account["email"] == "user2@example.com"

        print("Verification: Checking update_credential_status called...")
        mock_save_functions["update"].assert_called()


# =============================================================================
# Test Account Management
# =============================================================================


class TestAccountManagement:
    def test_enable_account_resets_failures(
        self, sample_credentials, mock_save_functions
    ):
        """
        What it does: Tests that enable_account() enables and resets failureCount.
        Purpose: Verify enabling account also resets failure tracking.
        """
        print("Setup: Creating AccountManager with disabled account...")
        credentials = sample_credentials.copy()
        credentials[0]["enabled"] = False
        credentials[0]["failureCount"] = 5
        manager = AccountManager(credentials)

        print("Action: Enabling account 0...")
        manager.enable_account(0)

        print("Verification: Checking account enabled and failures reset...")
        assert manager._accounts[0]["enabled"] is True
        assert manager._accounts[0]["failureCount"] == 0

        print("Verification: Checking update_credential_status called...")
        mock_save_functions["update"].assert_called_with(0, True, 0)

    def test_remove_account(self, sample_credentials, mock_save_functions):
        """
        What it does: Tests that remove_account() removes account from array.
        Purpose: Verify account removal updates array and persists.
        """
        print("Setup: Creating AccountManager with 3 accounts...")
        manager = AccountManager(sample_credentials)

        print("Action: Removing account 1...")
        manager.remove_account(1)

        print("Verification: Checking account removed...")
        assert len(manager._accounts) == 2
        assert manager._accounts[0]["email"] == "user1@example.com"
        assert manager._accounts[1]["email"] == "user3@example.com"

        print("Verification: Checking save_gateway_credentials called...")
        mock_save_functions["save"].assert_called_once()

    def test_disable_last_account_allowed(
        self, make_test_credential, mock_save_functions
    ):
        """
        What it does: Tests that disabling the last account is allowed.
        Purpose: Verify no special protection for last account.
        """
        print("Setup: Creating AccountManager with 1 account...")
        credentials = [make_test_credential("user1@example.com")]
        manager = AccountManager(credentials)

        print("Action: Disabling the only account...")
        manager.disable_account(0)

        print("Verification: Checking account disabled...")
        assert manager._accounts[0]["enabled"] is False

        print("Action: Getting next account...")
        result = manager.get_next_account()

        print("Verification: Checking None returned (no enabled accounts)...")
        assert result is None


# =============================================================================
# Test Edge Cases
# =============================================================================


class TestEdgeCases:
    def test_all_accounts_disabled_returns_none(
        self, make_test_credential, mock_save_functions
    ):
        """
        What it does: Tests that get_next_account() returns None when all disabled.
        Purpose: Verify graceful handling of no enabled accounts.
        """
        print("Setup: Creating AccountManager with all accounts disabled...")
        credentials = [
            make_test_credential("user1@example.com", enabled=False),
            make_test_credential("user2@example.com", enabled=False),
        ]
        manager = AccountManager(credentials)

        print("Action: Getting next account...")
        result = manager.get_next_account()

        print("Verification: Checking None returned...")
        assert result is None

    def test_get_all_accounts_masks_tokens(
        self, sample_credentials, mock_save_functions
    ):
        """
        What it does: Tests that get_all_accounts() masks sensitive fields.
        Purpose: Verify tokens are not exposed in account list.
        """
        print("Setup: Creating AccountManager...")
        manager = AccountManager(sample_credentials)

        print("Action: Getting all accounts...")
        accounts = manager.get_all_accounts()

        print("Verification: Checking sensitive fields masked...")
        assert len(accounts) == 3
        for account in accounts:
            assert "email" in account
            assert "region" in account
            assert "enabled" in account
            assert "failureCount" in account
            assert "expiresAt" in account
            # Sensitive fields should NOT be present
            assert "accessToken" not in account
            assert "refreshToken" not in account
            assert "clientId" not in account
            assert "clientSecret" not in account

    def test_mark_failure_invalid_index(self, sample_credentials, mock_save_functions):
        """
        What it does: Tests that mark_failure() handles invalid index gracefully.
        Purpose: Verify bounds checking for index parameter.
        """
        print("Setup: Creating AccountManager...")
        manager = AccountManager(sample_credentials)

        print("Action: Marking failure with invalid index...")
        result = manager.mark_failure(999)

        print("Verification: Checking False returned...")
        assert result is False

    def test_mark_success_invalid_index(self, sample_credentials, mock_save_functions):
        """
        What it does: Tests that mark_success() handles invalid index gracefully.
        Purpose: Verify bounds checking for index parameter.
        """
        print("Setup: Creating AccountManager...")
        manager = AccountManager(sample_credentials)

        print("Action: Marking success with invalid index...")
        # Should not raise exception
        manager.mark_success(999)

        print("Verification: Checking no exception raised...")
        # If we get here, test passed

    def test_get_enabled_accounts_returns_tuples(
        self, make_test_credential, mock_save_functions
    ):
        """
        What it does: Tests that get_enabled_accounts() returns (index, account) tuples.
        Purpose: Verify return format for enabled accounts list.
        """
        print("Setup: Creating AccountManager with mixed enabled/disabled...")
        credentials = [
            make_test_credential("user1@example.com", enabled=True),
            make_test_credential("user2@example.com", enabled=False),
            make_test_credential("user3@example.com", enabled=True),
        ]
        manager = AccountManager(credentials)

        print("Action: Getting enabled accounts...")
        enabled = manager.get_enabled_accounts()

        print("Verification: Checking format and content...")
        assert len(enabled) == 2
        assert enabled[0] == (0, credentials[0])
        assert enabled[1] == (2, credentials[2])

    def test_remove_account_adjusts_current_index(
        self, sample_credentials, mock_save_functions
    ):
        """
        What it does: Tests that removing account adjusts current_index if needed.
        Purpose: Verify index doesn't go out of bounds after removal.
        """
        print("Setup: Creating AccountManager and advancing to last account...")
        manager = AccountManager(sample_credentials)
        manager._current_index = 2  # Point to last account

        print("Action: Removing last account...")
        manager.remove_account(2)

        print("Verification: Checking current_index reset to 0...")
        assert manager._current_index == 0
        assert len(manager._accounts) == 2

    @pytest.mark.asyncio
    async def test_get_valid_token_refreshes_expiring_token(
        self, make_test_credential, mock_save_functions
    ):
        """
        What it does: Tests that get_valid_token() refreshes token when expiring soon.
        Purpose: Verify automatic token refresh before expiration.
        """
        print("Setup: Creating AccountManager with expiring token...")
        # Token expires in 2 minutes (less than 5 minute threshold)
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
        credentials = [make_test_credential("user1@example.com", expires_at=expires_at)]
        manager = AccountManager(credentials)

        print("Setup: Mocking token refresh response...")
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = MagicMock(
            return_value={
                "accessToken": "new_token",
                "refreshToken": "new_refresh",
                "expiresIn": 3600,
            }
        )
        mock_response.raise_for_status = MagicMock()

        with patch("kiro.account_manager.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            print("Action: Getting valid token...")
            token = await manager.get_valid_token(0)

            print("Verification: Checking token refreshed...")
            assert token == "new_token"
            assert manager._accounts[0]["accessToken"] == "new_token"
            mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_valid_token_returns_existing_if_not_expiring(
        self, sample_credentials, mock_save_functions
    ):
        """
        What it does: Tests that get_valid_token() returns existing token if not expiring.
        Purpose: Verify no unnecessary refresh when token is still valid.
        """
        print("Setup: Creating AccountManager with valid token...")
        manager = AccountManager(sample_credentials)

        print("Action: Getting valid token...")
        token = await manager.get_valid_token(0)

        print("Verification: Checking existing token returned...")
        assert token == "token_user1@example.com"

    @pytest.mark.asyncio
    async def test_get_valid_token_invalid_index_raises(
        self, sample_credentials, mock_save_functions
    ):
        """
        What it does: Tests that get_valid_token() raises IndexError for invalid index.
        Purpose: Verify bounds checking for async method.
        """
        print("Setup: Creating AccountManager...")
        manager = AccountManager(sample_credentials)

        print("Action: Getting valid token with invalid index...")
        with pytest.raises(IndexError):
            await manager.get_valid_token(999)

    def test_handle_rate_limit_with_only_one_enabled_returns_same(
        self, make_test_credential, mock_save_functions
    ):
        """
        What it does: Tests handle_rate_limit() when only one account is enabled.
        Purpose: Verify it returns the same account when no alternatives available.
        """
        print("Setup: Creating AccountManager with only one enabled account...")
        credentials = [
            make_test_credential("user1@example.com", enabled=True),
            make_test_credential("user2@example.com", enabled=False),
        ]
        manager = AccountManager(credentials)

        print("Action: Advance counter first...")
        manager.get_next_account()

        print("Action: Handling rate limit on only enabled account...")
        result = manager.handle_rate_limit(0)

        print("Verification: Checking same account returned...")
        assert result is not None
        index, account = result
        assert index == 0
        assert account["email"] == "user1@example.com"

    def test_handle_payment_required_with_all_disabled_returns_none(
        self, make_test_credential, mock_save_functions
    ):
        """
        What it does: Tests handle_payment_required() when all other accounts disabled.
        Purpose: Verify graceful handling when no alternative accounts available.
        """
        print("Setup: Creating AccountManager with only one enabled account...")
        credentials = [make_test_credential("user1@example.com", enabled=True)]
        manager = AccountManager(credentials)

        print("Action: Handling payment required on only account...")
        result = manager.handle_payment_required(0)

        print("Verification: Checking account disabled and None returned...")
        assert manager._accounts[0]["enabled"] is False
        assert result is None
