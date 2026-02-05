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
FastAPI routes for device code authentication.

Provides endpoints for OAuth 2.0 Device Authorization Grant flow:
- POST /auth/login: Start device authorization flow
- GET /auth/login/status/{session_id}: Check authorization status
- DELETE /auth/login/{session_id}: Cancel pending authorization
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, BackgroundTasks, Query, Request
from pydantic import BaseModel
from loguru import logger

from kiro.device_auth import DeviceAuthFlow, DeviceAuthError
from kiro.config import add_or_update_credential, REGION


async def _fetch_user_email(access_token: str, region: str) -> str:
    """Fetch user email via getUsageLimits API."""
    url = f"https://q.{region}.amazonaws.com/getUsageLimits"
    params = {
        "isEmailRequired": "true",
        "origin": "AI_EDITOR",
        "resourceType": "AGENTIC_REQUEST",
    }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "x-amz-user-agent": "kiro-gateway",
        "amz-sdk-invocation-id": str(uuid.uuid4()),
        "amz-sdk-request": "attempt=1;max=1",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()

    return data.get("userInfo", {}).get("email", "")


class LoginResponse(BaseModel):
    """Response from POST /auth/login endpoint."""

    session_id: str
    verification_uri: str
    verification_uri_complete: str
    user_code: str
    expires_in: int


class LoginStatusResponse(BaseModel):
    """Response from GET /auth/login/status/{session_id} endpoint."""

    status: str  # "pending", "complete", "expired", "error"
    message: str | None = None


_auth_sessions: dict[str, dict[str, Any]] = {}
SESSION_EXPIRATION_MINUTES = 10


router = APIRouter(prefix="/auth", tags=["auth"])


async def _poll_for_token_background(
    session_id: str,
    flow: DeviceAuthFlow,
    client_id: str,
    client_secret: str,
    device_code: str,
    interval: int,
    expires_in: int,
    app: Any,
) -> None:
    """
    Background task to poll for token after user completes authorization.

    Updates session status to 'complete' on success or 'error' on failure.
    Saves credentials to gateway credentials file on success.

    Args:
        session_id: Session ID to update
        flow: DeviceAuthFlow instance
        client_id: OIDC client ID
        client_secret: OIDC client secret
        device_code: Device code from authorization request
        interval: Polling interval in seconds
        expires_in: Seconds until device code expires
        app: FastAPI application instance for AccountManager access
    """
    try:
        logger.info(f"[{session_id[:8]}] Starting token polling...")

        token_response = await flow.poll_for_token(
            client_id=client_id,
            client_secret=client_secret,
            device_code=device_code,
            interval=interval,
            expires_in=expires_in,
        )

        token_expires_in = token_response.get("expiresIn", 3600)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=token_expires_in)
        region = _auth_sessions[session_id].get("region", REGION)

        try:
            email = await _fetch_user_email(token_response["accessToken"], region)
        except Exception as e:
            logger.warning(f"[{session_id[:8]}] Could not fetch email: {e}")
            email = ""

        credentials = {
            "accessToken": token_response["accessToken"],
            "refreshToken": token_response.get("refreshToken", ""),
            "clientId": client_id,
            "clientSecret": client_secret,
            "expiresAt": expires_at.isoformat(),
            "region": region,
            "email": email,
            "enabled": True,
            "failureCount": 0,
        }

        add_or_update_credential(credentials)
        logger.info(f"[{session_id[:8]}] Credentials saved successfully")

        if hasattr(app.state, "account_manager") and app.state.account_manager:
            app.state.account_manager.reload_credentials()
            logger.info(f"[{session_id[:8]}] AccountManager reloaded with new account")
        elif hasattr(app.state, "account_manager"):
            from kiro.account_manager import AccountManager

            app.state.account_manager = AccountManager([credentials], region=region)
            logger.info(
                f"[{session_id[:8]}] AccountManager initialized with first account"
            )

        if session_id in _auth_sessions:
            _auth_sessions[session_id]["status"] = "complete"
            _auth_sessions[session_id]["message"] = (
                "Authentication successful. Credentials saved."
            )

    except DeviceAuthError as e:
        logger.error(f"[{session_id[:8]}] Device auth failed: {e}")
        if session_id in _auth_sessions:
            if e.error_code == "expired_token":
                _auth_sessions[session_id]["status"] = "expired"
                _auth_sessions[session_id]["message"] = (
                    "Authorization timed out. Please try again."
                )
            else:
                _auth_sessions[session_id]["status"] = "error"
                _auth_sessions[session_id]["message"] = str(e)

    except Exception as e:
        logger.error(f"[{session_id[:8]}] Unexpected error during polling: {e}")
        if session_id in _auth_sessions:
            _auth_sessions[session_id]["status"] = "error"
            _auth_sessions[session_id]["message"] = f"Unexpected error: {str(e)}"


def _cleanup_expired_sessions() -> None:
    """Remove sessions older than SESSION_EXPIRATION_MINUTES."""
    now = datetime.now(timezone.utc)
    expired_sessions = [
        sid
        for sid, session in _auth_sessions.items()
        if now - session["created_at"] > timedelta(minutes=SESSION_EXPIRATION_MINUTES)
    ]
    for sid in expired_sessions:
        del _auth_sessions[sid]
        logger.debug(f"Cleaned up expired session: {sid[:8]}...")


@router.post("/login", response_model=LoginResponse)
async def start_login(
    request: Request,
    background_tasks: BackgroundTasks,
    region: str = Query(default=None, description="AWS region for authentication"),
    start_url: str = Query(default=None, description="SSO start URL for organization"),
) -> LoginResponse:
    """
    Start device authorization flow.

    Registers an OIDC client and starts device authorization. Returns
    verification URL and user code for the user to complete authentication
    in their browser.

    Args:
        background_tasks: FastAPI background tasks
        region: AWS region (defaults to KIRO_REGION or us-east-1)
        start_url: SSO start URL for organization (defaults to Builder ID)

    Returns:
        LoginResponse with session_id, verification URL, and user code

    Raises:
        HTTPException: On registration or authorization failure
    """
    _cleanup_expired_sessions()

    auth_region = region or REGION

    session_id = str(uuid.uuid4())

    try:
        flow = DeviceAuthFlow(region=auth_region, start_url=start_url)

        logger.info(f"[{session_id[:8]}] Registering OIDC client...")
        client_reg = await flow.register_client()
        client_id = client_reg["clientId"]
        client_secret = client_reg["clientSecret"]

        logger.info(f"[{session_id[:8]}] Starting device authorization...")
        device_auth = await flow.start_device_authorization(client_id, client_secret)

        _auth_sessions[session_id] = {
            "status": "pending",
            "message": None,
            "created_at": datetime.now(timezone.utc),
            "verification_uri": device_auth["verificationUri"],
            "verification_uri_complete": device_auth.get(
                "verificationUriComplete", device_auth["verificationUri"]
            ),
            "user_code": device_auth["userCode"],
            "device_code": device_auth["deviceCode"],
            "interval": device_auth["interval"],
            "expires_in": device_auth["expiresIn"],
            "client_id": client_id,
            "client_secret": client_secret,
            "region": auth_region,
        }

        background_tasks.add_task(
            _poll_for_token_background,
            session_id=session_id,
            flow=flow,
            client_id=client_id,
            client_secret=client_secret,
            device_code=device_auth["deviceCode"],
            interval=device_auth["interval"],
            expires_in=device_auth["expiresIn"],
            app=request.app,
        )

        logger.info(
            f"[{session_id[:8]}] Login flow started, user code: {device_auth['userCode']}"
        )

        return LoginResponse(
            session_id=session_id,
            verification_uri=device_auth["verificationUri"],
            verification_uri_complete=device_auth.get(
                "verificationUriComplete", device_auth["verificationUri"]
            ),
            user_code=device_auth["userCode"],
            expires_in=device_auth["expiresIn"],
        )

    except DeviceAuthError as e:
        logger.error(f"[{session_id[:8]}] Device auth error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"[{session_id[:8]}] Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start login: {str(e)}")


@router.get("/login/status/{session_id}", response_model=LoginStatusResponse)
async def get_login_status(session_id: str) -> LoginStatusResponse:
    """
    Get status of a pending login session.

    Args:
        session_id: Session ID from start_login response

    Returns:
        LoginStatusResponse with current status and optional message

    Raises:
        HTTPException: If session not found (404)
    """
    if session_id not in _auth_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = _auth_sessions[session_id]

    return LoginStatusResponse(
        status=session["status"],
        message=session.get("message"),
    )


@router.delete("/login/{session_id}")
async def cancel_login(session_id: str) -> dict[str, str]:
    """
    Cancel a pending login session.

    Removes the session from storage. Note that this does not stop
    the background polling task immediately, but the task will
    gracefully handle the missing session.

    Args:
        session_id: Session ID to cancel

    Returns:
        Success message

    Raises:
        HTTPException: If session not found (404)
    """
    if session_id not in _auth_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    del _auth_sessions[session_id]
    logger.info(f"[{session_id[:8]}] Login session cancelled")

    return {"message": "Login session cancelled"}
