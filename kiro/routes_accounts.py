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
FastAPI routes for account management.

Provides endpoints for managing multiple OAuth accounts:
- GET /accounts: List all accounts with status
- POST /accounts/{index}/enable: Enable account by index
- POST /accounts/{index}/disable: Disable account by index
- DELETE /accounts/{index}: Remove account by index
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from loguru import logger

from kiro.routes_openai import verify_api_key


router = APIRouter(prefix="/accounts", tags=["accounts"])


class AccountInfo(BaseModel):
    """Information about a single account."""

    index: int
    email: str
    region: str
    enabled: bool
    failure_count: int


class AccountListResponse(BaseModel):
    """Response from GET /accounts endpoint."""

    total: int
    enabled: int
    accounts: list[AccountInfo]


@router.get("", response_model=AccountListResponse)
async def list_accounts(
    request: Request, api_key: bool = Depends(verify_api_key)
) -> AccountListResponse:
    """
    List all accounts with status (tokens masked).

    Returns account information including email, region, enabled status,
    and failure count. Access tokens are masked for security.

    Args:
        request: FastAPI request object
        api_key: API key verification dependency

    Returns:
        AccountListResponse with list of accounts

    Raises:
        HTTPException: 503 if account_manager is not initialized
    """
    account_manager = getattr(request.app.state, "account_manager", None)

    if account_manager is None:
        logger.error("AccountManager not initialized")
        raise HTTPException(
            status_code=503,
            detail="Account management not available. Run 'python main.py login' first.",
        )

    accounts_data = account_manager.get_all_accounts()
    enabled_count = sum(1 for acc in accounts_data if acc.get("enabled", True))

    accounts = [
        AccountInfo(
            index=i,
            email=acc.get("email", "unknown"),
            region=acc.get("region", "us-east-1"),
            enabled=acc.get("enabled", True),
            failure_count=acc.get("failureCount", 0),
        )
        for i, acc in enumerate(accounts_data)
    ]

    logger.info(f"Listed {len(accounts)} accounts ({enabled_count} enabled)")

    return AccountListResponse(
        total=len(accounts), enabled=enabled_count, accounts=accounts
    )


@router.post("/{index}/enable")
async def enable_account(
    index: int, request: Request, api_key: bool = Depends(verify_api_key)
) -> dict:
    """
    Enable account by index.

    Enables the account at the specified index and resets failure count.

    Args:
        index: Account index (0-based)
        request: FastAPI request object
        api_key: API key verification dependency

    Returns:
        Success message with account email

    Raises:
        HTTPException: 503 if account_manager not initialized, 404 if invalid index
    """
    account_manager = getattr(request.app.state, "account_manager", None)

    if account_manager is None:
        logger.error("AccountManager not initialized")
        raise HTTPException(
            status_code=503,
            detail="Account management not available. Run 'python main.py login' first.",
        )

    try:
        account_manager.enable_account(index)
        accounts = account_manager.get_all_accounts()
        email = accounts[index].get("email", "unknown")
        logger.info(f"Enabled account {index}: {email}")
        return {"message": f"Account enabled: {email}"}
    except IndexError:
        logger.warning(f"Invalid account index: {index}")
        raise HTTPException(status_code=404, detail=f"Account index {index} not found")


@router.post("/{index}/disable")
async def disable_account(
    index: int, request: Request, api_key: bool = Depends(verify_api_key)
) -> dict:
    """
    Disable account by index.

    Disables the account at the specified index. Failure count is preserved.

    Args:
        index: Account index (0-based)
        request: FastAPI request object
        api_key: API key verification dependency

    Returns:
        Success message with account email

    Raises:
        HTTPException: 503 if account_manager not initialized, 404 if invalid index
    """
    account_manager = getattr(request.app.state, "account_manager", None)

    if account_manager is None:
        logger.error("AccountManager not initialized")
        raise HTTPException(
            status_code=503,
            detail="Account management not available. Run 'python main.py login' first.",
        )

    try:
        account_manager.disable_account(index)
        accounts = account_manager.get_all_accounts()
        email = accounts[index].get("email", "unknown")
        logger.info(f"Disabled account {index}: {email}")
        return {"message": f"Account disabled: {email}"}
    except IndexError:
        logger.warning(f"Invalid account index: {index}")
        raise HTTPException(status_code=404, detail=f"Account index {index} not found")


@router.delete("/{index}")
async def remove_account(
    index: int, request: Request, api_key: bool = Depends(verify_api_key)
) -> dict:
    """
    Remove account by index.

    Permanently removes the account at the specified index from storage.

    Args:
        index: Account index (0-based)
        request: FastAPI request object
        api_key: API key verification dependency

    Returns:
        Success message with account email

    Raises:
        HTTPException: 503 if account_manager not initialized, 404 if invalid index
    """
    account_manager = getattr(request.app.state, "account_manager", None)

    if account_manager is None:
        logger.error("AccountManager not initialized")
        raise HTTPException(
            status_code=503,
            detail="Account management not available. Run 'python main.py login' first.",
        )

    try:
        accounts = account_manager.get_all_accounts()
        email = accounts[index].get("email", "unknown")
        account_manager.remove_account(index)
        logger.info(f"Removed account {index}: {email}")
        return {"message": f"Account removed: {email}"}
    except IndexError:
        logger.warning(f"Invalid account index: {index}")
        raise HTTPException(status_code=404, detail=f"Account index {index} not found")
