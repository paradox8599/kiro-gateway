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
Kiro Gateway - OpenAI-compatible interface for Kiro API.

Application entry point. Creates FastAPI app and connects routes.

Usage:
    # Using default settings (host: 0.0.0.0, port: 8000)
    python main.py

    # With CLI arguments (highest priority)
    python main.py --port 9000
    python main.py --host 127.0.0.1 --port 9000

    # With environment variables (medium priority)
    SERVER_PORT=9000 python main.py

    # Using uvicorn directly (uvicorn handles its own CLI args)
    uvicorn main:app --host 0.0.0.0 --port 8000

Priority: CLI args > Environment variables > Default values
"""

import argparse
import asyncio
import json
import logging
import sys
import os
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime

import httpx
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from kiro.config import (
    APP_TITLE,
    APP_DESCRIPTION,
    APP_VERSION,
    REFRESH_TOKEN,
    PROFILE_ARN,
    REGION,
    KIRO_CREDS_FILE,
    KIRO_CLI_DB_FILE,
    PROXY_API_KEY,
    LOG_LEVEL,
    SERVER_HOST,
    SERVER_PORT,
    DEFAULT_SERVER_HOST,
    DEFAULT_SERVER_PORT,
    STREAMING_READ_TIMEOUT,
    HIDDEN_MODELS,
    MODEL_ALIASES,
    HIDDEN_FROM_LIST,
    FALLBACK_MODELS,
    VPN_PROXY_URL,
    _warn_timeout_configuration,
    gateway_credentials_exist,
    save_gateway_credentials,
    get_gateway_credentials_path,
    load_gateway_credentials,
    add_or_update_credential,
    remove_credential,
    update_credential_status,
)
from kiro.auth import KiroAuthManager, AuthType
from kiro.account_manager import AccountManager
from kiro.cache import ModelInfoCache
from kiro.model_resolver import ModelResolver
from kiro.routes_openai import router as openai_router
from kiro.routes_anthropic import router as anthropic_router
from kiro.routes_auth import router as auth_router
from kiro.routes_accounts import router as accounts_router
from kiro.exceptions import validation_exception_handler
from kiro.debug_middleware import DebugLoggerMiddleware
from kiro.device_auth import DeviceAuthFlow, DeviceAuthError


# --- Loguru Configuration ---
logger.remove()
logger.add(
    sys.stderr,
    level=LOG_LEVEL,
    colorize=True,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
)


class InterceptHandler(logging.Handler):
    """
    Intercepts logs from standard logging and redirects them to loguru.

    This allows capturing logs from uvicorn, FastAPI and other libraries
    that use standard logging instead of loguru.

    Also filters out noisy shutdown-related exceptions (CancelledError, KeyboardInterrupt)
    that are normal during Ctrl+C but uvicorn logs as ERROR.
    """

    # Exceptions that are normal during shutdown and should not be logged as errors
    SHUTDOWN_EXCEPTIONS = (
        "CancelledError",
        "KeyboardInterrupt",
        "asyncio.exceptions.CancelledError",
    )

    def emit(self, record: logging.LogRecord) -> None:
        # Filter out shutdown-related exceptions that uvicorn logs as ERROR
        # These are normal during Ctrl+C and don't need to spam the console
        if record.exc_info:
            exc_type = record.exc_info[0]
            if exc_type is not None:
                exc_name = exc_type.__name__
                if exc_name in self.SHUTDOWN_EXCEPTIONS:
                    # Suppress the full traceback, just log a simple message
                    logger.info("Server shutdown in progress...")
                    return

        # Also filter by message content for cases where exc_info is not set
        msg = record.getMessage()
        if any(exc in msg for exc in self.SHUTDOWN_EXCEPTIONS):
            return

        # Get the corresponding loguru level
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Find the caller frame for correct source display
        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def setup_logging_intercept():
    """
    Configures log interception from standard logging to loguru.

    Intercepts logs from:
    - uvicorn (access logs, error logs)
    - uvicorn.error
    - uvicorn.access
    - fastapi
    """
    # List of loggers to intercept
    loggers_to_intercept = [
        "uvicorn",
        "uvicorn.error",
        "uvicorn.access",
        "fastapi",
    ]

    for logger_name in loggers_to_intercept:
        logging_logger = logging.getLogger(logger_name)
        logging_logger.handlers = [InterceptHandler()]
        logging_logger.propagate = False


# Configure uvicorn/fastapi log interception
setup_logging_intercept()


# ==================================================================================================
# VPN/Proxy Configuration
# ==================================================================================================
# Must be set BEFORE creating any httpx clients (including in lifespan)
# httpx automatically picks up HTTP_PROXY, HTTPS_PROXY, ALL_PROXY from environment

if VPN_PROXY_URL:
    # Normalize URL - add http:// if no scheme specified
    proxy_url_with_scheme = (
        VPN_PROXY_URL if "://" in VPN_PROXY_URL else f"http://{VPN_PROXY_URL}"
    )

    # Set environment variables for httpx to pick up automatically
    os.environ["HTTP_PROXY"] = proxy_url_with_scheme
    os.environ["HTTPS_PROXY"] = proxy_url_with_scheme
    os.environ["ALL_PROXY"] = proxy_url_with_scheme

    # Exclude localhost from proxy to avoid routing local requests through it
    no_proxy_hosts = os.environ.get("NO_PROXY", "")
    local_hosts = "127.0.0.1,localhost"
    if no_proxy_hosts:
        os.environ["NO_PROXY"] = f"{no_proxy_hosts},{local_hosts}"
    else:
        os.environ["NO_PROXY"] = local_hosts

    logger.info(f"Proxy configured: {proxy_url_with_scheme}")
    logger.debug(f"NO_PROXY: {os.environ['NO_PROXY']}")


# --- Configuration Validation ---
def validate_configuration() -> None:
    """
    Validates that required configuration is present.

    Checks:
    - Either REFRESH_TOKEN, KIRO_CREDS_FILE, or KIRO_CLI_DB_FILE is configured
    - Supports both .env file (local) and environment variables (Docker)

    Raises:
        SystemExit: If critical configuration is missing
    """
    errors = []

    # Check if .env file exists (optional - can use environment variables)
    env_file = Path(".env")

    # Check for credentials (from .env or environment variables)
    has_refresh_token = bool(REFRESH_TOKEN)
    has_creds_file = bool(KIRO_CREDS_FILE)
    has_cli_db = bool(KIRO_CLI_DB_FILE)
    has_oauth_creds = gateway_credentials_exist()

    # Check if creds file actually exists
    if KIRO_CREDS_FILE:
        creds_path = Path(KIRO_CREDS_FILE).expanduser()
        if not creds_path.exists():
            has_creds_file = False
            logger.warning(f"KIRO_CREDS_FILE not found: {KIRO_CREDS_FILE}")

    # Check if CLI database file actually exists
    if KIRO_CLI_DB_FILE:
        cli_db_path = Path(KIRO_CLI_DB_FILE).expanduser()
        if not cli_db_path.exists():
            has_cli_db = False
            logger.warning(f"KIRO_CLI_DB_FILE not found: {KIRO_CLI_DB_FILE}")

    # If no credentials found, show helpful error
    if (
        not has_refresh_token
        and not has_creds_file
        and not has_cli_db
        and not has_oauth_creds
    ):
        if not env_file.exists():
            # No .env file and no environment variables
            errors.append(
                "No Kiro credentials configured!\n"
                "\n"
                "To get started:\n"
                "1. Create .env file:\n"
                "   cp .env.example .env\n"
                "\n"
                "2. Edit .env and configure your credentials:\n"
                "   2.1. Set you super-secret password as PROXY_API_KEY\n"
                "   2.2. Set your Kiro credentials:\n"
                "      - Option 0 (Easiest): Run 'python main.py login' to authenticate\n"
                "      - Option 1: KIRO_CREDS_FILE to your Kiro credentials JSON file\n"
                "      - Option 2: REFRESH_TOKEN from Kiro IDE traffic\n"
                "      - Option 3: KIRO_CLI_DB_FILE to kiro-cli SQLite database\n"
                "\n"
                "Or use environment variables (for Docker):\n"
                '   docker run -e PROXY_API_KEY="..." -e REFRESH_TOKEN="..." ...\n'
                "\n"
                "See README.md for detailed instructions."
            )
        else:
            # .env exists but no credentials configured
            errors.append(
                "No Kiro credentials configured!\n"
                "\n"
                "   Configure one of the following in your .env file:\n"
                "\n"
                "Set you super-secret password as PROXY_API_KEY\n"
                '   PROXY_API_KEY="my-super-secret-password-123"\n'
                "\n"
                "   Option 0 (Easiest): Run 'python main.py login' to authenticate\n"
                "\n"
                "   Option 1 (Recommended): JSON credentials file\n"
                '      KIRO_CREDS_FILE="path/to/your/kiro-credentials.json"\n'
                "\n"
                "   Option 2: Refresh token\n"
                '      REFRESH_TOKEN="your_refresh_token_here"\n'
                "\n"
                "   Option 3: kiro-cli SQLite database (AWS SSO)\n"
                '      KIRO_CLI_DB_FILE="~/.local/share/kiro-cli/data.sqlite3"\n'
                "\n"
                "   See README.md for how to obtain credentials."
            )

    # Print errors and exit if any
    if errors:
        logger.error("")
        logger.error("=" * 60)
        logger.error("  CONFIGURATION ERROR")
        logger.error("=" * 60)
        for error in errors:
            for line in error.split("\n"):
                logger.error(f"  {line}")
        logger.error("=" * 60)
        logger.error("")
        sys.exit(1)

    # Note: Credential loading details are logged by KiroAuthManager


# --- Lifespan Manager ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages the application lifecycle.

    Creates and initializes:
    - Shared HTTP client with connection pooling
    - KiroAuthManager for token management
    - ModelInfoCache for model caching

    The shared HTTP client is used by all requests to reduce memory usage
    and enable connection reuse. This is especially important for handling
    concurrent requests efficiently (fixes issue #24).
    """
    logger.info("Starting application... Creating state managers.")

    # Create shared HTTP client with connection pooling
    # This reduces memory usage and enables connection reuse across requests
    # Limits: max 100 total connections, max 20 keep-alive connections
    limits = httpx.Limits(
        max_connections=100,
        max_keepalive_connections=20,
        keepalive_expiry=30.0,  # Close idle connections after 30 seconds
    )
    # Timeout configuration for streaming (long read timeout for model "thinking")
    timeout = httpx.Timeout(
        connect=30.0,
        read=STREAMING_READ_TIMEOUT,  # 300 seconds for streaming
        write=30.0,
        pool=30.0,
    )
    app.state.http_client = httpx.AsyncClient(
        limits=limits, timeout=timeout, follow_redirects=True
    )
    logger.info("Shared HTTP client created with connection pooling")

    # Create AccountManager for multi-account support
    # Priority: OAuth creds (~/.kiro-gateway/) > fallback to legacy single-account
    credentials = load_gateway_credentials()
    if credentials:
        app.state.account_manager = AccountManager(credentials, region=REGION)
        enabled_count = len(app.state.account_manager.get_enabled_accounts())
        logger.info(
            f"AccountManager initialized with {len(credentials)} account(s), {enabled_count} enabled"
        )
    else:
        app.state.account_manager = None
        logger.warning("No accounts configured. Run 'python main.py login' first.")

    app.state.model_cache = ModelInfoCache()

    logger.info("Loading models from Kiro API...")

    token = None
    headers = None
    q_host = None
    params = {"origin": "AI_EDITOR"}

    if app.state.account_manager:
        enabled = app.state.account_manager.get_enabled_accounts()
        if enabled:
            account_idx, account = enabled[0]
            try:
                token = await app.state.account_manager.get_valid_token(account_idx)

                from kiro.utils import get_machine_fingerprint
                import uuid

                fingerprint = get_machine_fingerprint()
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "User-Agent": f"aws-sdk-js/1.0.27 ua/2.1 os/win32#10.0.19044 lang/js md/nodejs#22.21.1 api/codewhispererstreaming#1.0.27 m/E KiroIDE-0.7.45-{fingerprint}",
                    "x-amz-user-agent": f"aws-sdk-js/1.0.27 KiroIDE-0.7.45-{fingerprint}",
                    "x-amzn-codewhisperer-optout": "true",
                    "x-amzn-kiro-agent-mode": "vibe",
                    "amz-sdk-invocation-id": str(uuid.uuid4()),
                    "amz-sdk-request": "attempt=1; max=3",
                }

                region = account.get("region", REGION)
                q_host = f"https://q.{region}.amazonaws.com"

                logger.debug(
                    f"Using AccountManager for model loading (account {account_idx})"
                )
            except Exception as e:
                logger.warning(f"Failed to get token from AccountManager: {e}")
                token = None
        else:
            logger.warning("No enabled accounts in AccountManager")

    if not token:
        logger.debug("Falling back to legacy KiroAuthManager for model loading")

        oauth_creds_file = None
        if gateway_credentials_exist():
            oauth_creds_file = str(get_gateway_credentials_path())

        app.state.auth_manager = KiroAuthManager(
            refresh_token=REFRESH_TOKEN,
            profile_arn=PROFILE_ARN,
            region=REGION,
            creds_file=oauth_creds_file
            or (KIRO_CREDS_FILE if KIRO_CREDS_FILE else None),
            sqlite_db=KIRO_CLI_DB_FILE if KIRO_CLI_DB_FILE else None,
        )

        try:
            token = await app.state.auth_manager.get_access_token()
            from kiro.utils import get_kiro_headers
            from kiro.auth import AuthType

            headers = get_kiro_headers(app.state.auth_manager, token)
            q_host = app.state.auth_manager.q_host

            if (
                app.state.auth_manager.auth_type == AuthType.KIRO_DESKTOP
                and app.state.auth_manager.profile_arn
            ):
                params["profileArn"] = app.state.auth_manager.profile_arn
        except Exception as e:
            logger.error(f"Failed to initialize legacy auth: {e}")
            token = None

    try:
        if token and headers and q_host:
            list_models_url = f"{q_host}/ListAvailableModels"
            logger.debug(f"Fetching models from: {list_models_url}")

            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    list_models_url, headers=headers, params=params
                )

                if response.status_code == 200:
                    data = response.json()
                    models_list = data.get("models", [])
                    await app.state.model_cache.update(models_list)
                    logger.debug(
                        f"Successfully loaded {len(models_list)} models from Kiro API"
                    )
                else:
                    raise Exception(f"HTTP {response.status_code}")
        else:
            raise Exception("No valid credentials available")
    except Exception as e:
        logger.error(f"Failed to fetch models from Kiro API: {e}")
        logger.error(
            "Using pre-configured fallback models. Not all models may be available on your plan, or the list may be outdated."
        )

        # Populate cache with fallback models
        await app.state.model_cache.update(FALLBACK_MODELS)
        logger.debug(f"Loaded {len(FALLBACK_MODELS)} fallback models")

    # Add hidden models to cache (they appear in /v1/models but not in Kiro API)
    # Hidden models are added ALWAYS, regardless of API success/failure
    for display_name, internal_id in HIDDEN_MODELS.items():
        app.state.model_cache.add_hidden_model(display_name, internal_id)

    if HIDDEN_MODELS:
        logger.debug(f"Added {len(HIDDEN_MODELS)} hidden models to cache")

    # Log final cache state
    all_models = app.state.model_cache.get_all_model_ids()
    logger.info(f"Model cache ready: {len(all_models)} models total")

    # Create model resolver (uses cache + hidden models + aliases for resolution)
    app.state.model_resolver = ModelResolver(
        cache=app.state.model_cache,
        hidden_models=HIDDEN_MODELS,
        aliases=MODEL_ALIASES,
        hidden_from_list=HIDDEN_FROM_LIST,
    )
    logger.info("Model resolver initialized")

    # Log alias configuration if any
    if MODEL_ALIASES:
        logger.debug(f"Model aliases configured: {list(MODEL_ALIASES.keys())}")
    if HIDDEN_FROM_LIST:
        logger.debug(f"Models hidden from list: {HIDDEN_FROM_LIST}")

    yield

    # Graceful shutdown
    logger.info("Shutting down application...")
    try:
        await app.state.http_client.aclose()
        logger.info("Shared HTTP client closed")
    except Exception as e:
        logger.warning(f"Error closing shared HTTP client: {e}")


# --- FastAPI Application ---
app = FastAPI(
    title=APP_TITLE, description=APP_DESCRIPTION, version=APP_VERSION, lifespan=lifespan
)


# --- CORS Middleware ---
# Allow CORS for all origins to support browser clients
# and tools that send preflight OPTIONS requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, OPTIONS, etc.)
    allow_headers=["*"],  # Allow all headers
)


# --- Debug Logger Middleware ---
# Initializes debug logging BEFORE Pydantic validation
# This allows capturing validation errors (422) in debug logs
app.add_middleware(DebugLoggerMiddleware)


# --- Validation Error Handler Registration ---
app.add_exception_handler(RequestValidationError, validation_exception_handler)


# --- Route Registration ---
# OpenAI-compatible API: /v1/models, /v1/chat/completions
app.include_router(openai_router)

# Anthropic-compatible API: /v1/messages
app.include_router(anthropic_router)

app.include_router(auth_router)

app.include_router(accounts_router)


# --- Uvicorn log config ---
# Minimal configuration for redirecting uvicorn logs to loguru.
# Uses InterceptHandler which intercepts logs and passes them to loguru.
UVICORN_LOG_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "default": {
            "class": "main.InterceptHandler",
        },
    },
    "loggers": {
        "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
        "uvicorn.error": {"handlers": ["default"], "level": "INFO", "propagate": False},
        "uvicorn.access": {
            "handlers": ["default"],
            "level": "INFO",
            "propagate": False,
        },
    },
}


def parse_cli_args() -> argparse.Namespace:
    """
    Parse command-line arguments for server configuration and subcommands.

    CLI arguments have the highest priority, overriding both
    environment variables and default values.

    Returns:
        Parsed arguments namespace with host, port, and command values
    """
    parser = argparse.ArgumentParser(
        description=f"{APP_TITLE} - {APP_DESCRIPTION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Configuration Priority (highest to lowest):
  1. CLI arguments (--host, --port)
  2. Environment variables (SERVER_HOST, SERVER_PORT)
  3. Default values (0.0.0.0:8000)

Examples:
  python main.py                          # Start server (use defaults or env vars)
  python main.py --port 9000              # Start server on port 9000
  python main.py --host 127.0.0.1         # Local connections only
  python main.py -H 0.0.0.0 -p 8080       # Short form
  
  python main.py login                    # Authenticate with AWS Builder ID
  python main.py login --force            # Overwrite existing credentials
  python main.py login --region us-west-2 # Use specific region
  
  SERVER_PORT=9000 python main.py         # Via environment
  uvicorn main:app --port 9000            # Via uvicorn directly
        """,
    )

    parser.add_argument(
        "-H",
        "--host",
        type=str,
        default=None,  # None means "use env or default"
        metavar="HOST",
        help=f"Server host address (default: {DEFAULT_SERVER_HOST}, env: SERVER_HOST)",
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=None,  # None means "use env or default"
        metavar="PORT",
        help=f"Server port (default: {DEFAULT_SERVER_PORT}, env: SERVER_PORT)",
    )

    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {APP_VERSION}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    login_parser = subparsers.add_parser(
        "login",
        help="Authenticate with AWS Builder ID",
        description="Authenticate with AWS Builder ID using device code flow",
    )
    login_parser.add_argument(
        "--force", action="store_true", help="Overwrite existing credentials"
    )
    login_parser.add_argument(
        "--region", type=str, default=None, help=f"AWS region (default: {REGION})"
    )
    login_parser.add_argument(
        "--start-url",
        type=str,
        default=None,
        help="SSO start URL for organization (default: Builder ID)",
    )

    usage_parser = subparsers.add_parser(
        "usage",
        help="Check account credit usage",
        description="Display account credit usage and subscription information",
    )
    usage_parser.add_argument(
        "--region",
        type=str,
        default=None,
        help="AWS region (default: KIRO_REGION or us-east-1)",
    )
    usage_parser.add_argument("--json", action="store_true", help="Output as JSON")

    accounts_parser = subparsers.add_parser(
        "accounts",
        help="Manage OAuth accounts",
        description="Manage multiple OAuth accounts (list, enable, disable, remove)",
    )
    accounts_subparsers = accounts_parser.add_subparsers(dest="accounts_command")

    accounts_subparsers.add_parser("list", help="List all accounts")

    enable_parser = accounts_subparsers.add_parser(
        "enable", help="Enable account by index or email"
    )
    enable_parser.add_argument("identifier", help="Account index or email")

    disable_parser = accounts_subparsers.add_parser(
        "disable", help="Disable account by index or email"
    )
    disable_parser.add_argument("identifier", help="Account index or email")

    remove_parser = accounts_subparsers.add_parser(
        "remove", help="Remove account by index or email"
    )
    remove_parser.add_argument("identifier", help="Account index or email")

    return parser.parse_args()


def resolve_server_config(args: argparse.Namespace) -> tuple[str, int]:
    """
    Resolve final server configuration using priority hierarchy.

    Priority (highest to lowest):
    1. CLI arguments (--host, --port)
    2. Environment variables (SERVER_HOST, SERVER_PORT)
    3. Default values (0.0.0.0:8000)

    Args:
        args: Parsed CLI arguments

    Returns:
        Tuple of (host, port) with resolved values
    """
    # Host resolution: CLI > ENV > Default
    if args.host is not None:
        final_host = args.host
        host_source = "CLI argument"
    elif SERVER_HOST != DEFAULT_SERVER_HOST:
        final_host = SERVER_HOST
        host_source = "environment variable"
    else:
        final_host = DEFAULT_SERVER_HOST
        host_source = "default"

    # Port resolution: CLI > ENV > Default
    if args.port is not None:
        final_port = args.port
        port_source = "CLI argument"
    elif SERVER_PORT != DEFAULT_SERVER_PORT:
        final_port = SERVER_PORT
        port_source = "environment variable"
    else:
        final_port = DEFAULT_SERVER_PORT
        port_source = "default"

    # Log configuration sources for transparency
    logger.debug(f"Host: {final_host} (from {host_source})")
    logger.debug(f"Port: {final_port} (from {port_source})")

    return final_host, final_port


def print_startup_banner(host: str, port: int) -> None:
    """
    Print a startup banner with server information.

    Args:
        host: Server host address
        port: Server port
    """
    # ANSI color codes
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    # Determine display URL
    display_host = "localhost" if host == "0.0.0.0" else host
    url = f"http://{display_host}:{port}"

    print()
    print(f"  {WHITE}{BOLD}👻 {APP_TITLE} v{APP_VERSION}{RESET}")
    print()
    print(f"  {WHITE}Server running at:{RESET}")
    print(f"  {GREEN}{BOLD}➜  {url}{RESET}")
    print()
    print(f"  {DIM}API Docs:      {url}/docs{RESET}")
    print(f"  {DIM}Health Check:  {url}/health{RESET}")
    print()
    print(f"  {DIM}{'─' * 48}{RESET}")
    print(f"  {WHITE}💬 Found a bug? Need help? Have questions?{RESET}")
    print(f"  {YELLOW}➜  https://github.com/jwadow/kiro-gateway/issues{RESET}")
    print(f"  {DIM}{'─' * 48}{RESET}")
    print()


async def fetch_user_email(access_token: str, region: str) -> str:
    """
    Fetch user email by calling getUsageLimits API.

    Args:
        access_token: Valid access token
        region: AWS region

    Returns:
        User email address

    Raises:
        Exception: If API call fails or email not found
    """
    import uuid

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

    email = data.get("userInfo", {}).get("email")
    if not email:
        raise Exception("Email not found in getUsageLimits response")

    return email


async def handle_login_command(args: argparse.Namespace) -> None:
    if gateway_credentials_exist() and not args.force:
        creds_path = get_gateway_credentials_path()
        print(f"\n❌ Credentials already exist at: {creds_path}")
        print("   Use --force to overwrite existing credentials\n")
        sys.exit(1)

    region = args.region or REGION or "us-east-1"
    start_url = args.start_url if hasattr(args, "start_url") else None

    print(f"\nStarting Builder ID authentication (region: {region})...")
    if start_url:
        print(f"Using organization SSO: {start_url}")

    try:
        flow = DeviceAuthFlow(region, start_url=start_url)
        credentials = await flow.run_device_flow()

        # Fetch user email via getUsageLimits API
        email = await fetch_user_email(credentials["accessToken"], region)
        credentials["email"] = email
        credentials["enabled"] = True
        credentials["failureCount"] = 0

        # Add or update credential
        is_new = add_or_update_credential(credentials)

        if is_new:
            print(f"\n✓ Added new account: {email}")
        else:
            print(f"\n✓ Updated existing account: {email}")

        creds_path = get_gateway_credentials_path()
        print(f"  Credentials saved to: {creds_path}\n")

    except DeviceAuthError as e:
        print(f"\n❌ Authentication failed: {e}\n")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during login: {e}")
        print(f"\n❌ Unexpected error: {e}\n")
        sys.exit(1)


async def fetch_usage_data(token: str, region: str) -> dict:
    """
    Fetch usage data from Kiro API.

    Args:
        token: Valid access token
        region: AWS region

    Returns:
        Usage data dict from API

    Raises:
        httpx.HTTPStatusError: If API call fails
    """
    import uuid

    url = f"https://q.{region}.amazonaws.com/getUsageLimits"
    params = {
        "isEmailRequired": "true",
        "origin": "AI_EDITOR",
        "resourceType": "AGENTIC_REQUEST",
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "x-amz-user-agent": "kiro-gateway",
        "amz-sdk-invocation-id": str(uuid.uuid4()),
        "amz-sdk-request": "attempt=1;max=1",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, params=params, headers=headers)
        response.raise_for_status()
        return response.json()


async def handle_usage_command(args: argparse.Namespace) -> None:
    credentials = load_gateway_credentials()

    if not credentials:
        logger.error("No credentials found. Run 'python main.py login' first.")
        sys.exit(1)

    region = args.region or REGION or "us-east-1"
    account_manager = AccountManager(credentials, region=region)

    if args.json:
        results = []
        for idx, account in enumerate(credentials):
            try:
                token = await account_manager.get_valid_token(idx)
                usage_data = await fetch_usage_data(token, region)
                results.append(
                    {
                        "index": idx,
                        "email": account.get("email", "unknown"),
                        "enabled": account.get("enabled", True),
                        "failure_count": account.get("failureCount", 0),
                        "usage": usage_data,
                    }
                )
            except Exception as e:
                logger.error(f"Failed to fetch usage for account {idx}: {e}")
                results.append(
                    {
                        "index": idx,
                        "email": account.get("email", "unknown"),
                        "enabled": account.get("enabled", True),
                        "failure_count": account.get("failureCount", 0),
                        "error": str(e),
                    }
                )
        print(json.dumps({"accounts": results}, indent=2))
    else:
        print(f"\nKiro Usage - {len(credentials)} account(s)\n")

        for idx, account in enumerate(credentials):
            email = account.get("email", "unknown")
            enabled = account.get("enabled", True)
            failures = account.get("failureCount", 0)
            status = "enabled" if enabled else "disabled"

            print(f"[{idx}] {email} ({status}, {failures} failures)")

            try:
                token = await account_manager.get_valid_token(idx)
                data = await fetch_usage_data(token, region)

                sub_info = data.get("subscriptionInfo", {})
                sub_title = sub_info.get("subscriptionTitle", "Unknown")
                sub_type = sub_info.get("type", "Unknown")
                print(f"    {sub_title} ({sub_type})")

                reset_ts = data.get("nextDateReset", 0)
                if reset_ts:
                    reset_date = datetime.fromtimestamp(reset_ts).strftime("%Y-%m-%d")
                    days = data.get("daysUntilReset", 0)
                    print(f"    Resets: {reset_date} ({days} days)")

                for item in data.get("usageBreakdownList", []):
                    name = item.get("displayName", item.get("resourceType", "Unknown"))
                    current = item.get("currentUsage", 0)
                    limit = item.get("usageLimit", 0)
                    pct = (current / limit * 100) if limit > 0 else 0

                    limit_marker = (
                        "  ← LIMIT REACHED" if current >= limit and limit > 0 else ""
                    )
                    print(
                        f"      {name:<24} {current:>4} / {limit:<6} ({pct:>5.1f}%){limit_marker}"
                    )

            except Exception as e:
                logger.error(f"Failed to fetch usage for account {idx}: {e}")
                print(f"    Error: {e}")

            print()


def handle_accounts_command(args: argparse.Namespace) -> None:
    if not gateway_credentials_exist():
        print("\n❌ No accounts found. Run 'python main.py login' first.\n")
        sys.exit(1)

    credentials = load_gateway_credentials()
    command = args.accounts_command or "list"

    if command == "list":
        enabled_count = sum(1 for c in credentials if c.get("enabled", True))
        total_count = len(credentials)

        print(f"\nKiro Accounts ({total_count} total, {enabled_count} enabled)\n")
        print(f"{'#':<3}{'Email':<26}{'Status':<11}{'Failures':<10}{'Region'}")

        for i, cred in enumerate(credentials):
            email = cred.get("email", "unknown")
            status = "enabled" if cred.get("enabled", True) else "disabled"
            failures = cred.get("failureCount", 0)
            region = cred.get("region", "us-east-1")
            print(f"{i:<3}{email:<26}{status:<11}{failures:<10}{region}")

        print()

    elif command == "enable":
        identifier = args.identifier

        try:
            index = int(identifier)
            if 0 <= index < len(credentials):
                update_credential_status(index, enabled=True, failure_count=0)
                email = credentials[index].get("email", "unknown")
                print(f"\n✓ Account enabled: {email}\n")
            else:
                print(
                    f"\n❌ Invalid index: {index}. Valid range: 0-{len(credentials) - 1}\n"
                )
                sys.exit(1)
        except ValueError:
            found = False
            for i, cred in enumerate(credentials):
                if cred.get("email") == identifier:
                    update_credential_status(i, enabled=True, failure_count=0)
                    print(f"\n✓ Account enabled: {identifier}\n")
                    found = True
                    break
            if not found:
                print(f"\n❌ Account not found: {identifier}\n")
                sys.exit(1)

    elif command == "disable":
        identifier = args.identifier

        try:
            index = int(identifier)
            if 0 <= index < len(credentials):
                failures = credentials[index].get("failureCount", 0)
                update_credential_status(index, enabled=False, failure_count=failures)
                email = credentials[index].get("email", "unknown")
                print(f"\n✓ Account disabled: {email}\n")
            else:
                print(
                    f"\n❌ Invalid index: {index}. Valid range: 0-{len(credentials) - 1}\n"
                )
                sys.exit(1)
        except ValueError:
            found = False
            for i, cred in enumerate(credentials):
                if cred.get("email") == identifier:
                    failures = cred.get("failureCount", 0)
                    update_credential_status(i, enabled=False, failure_count=failures)
                    print(f"\n✓ Account disabled: {identifier}\n")
                    found = True
                    break
            if not found:
                print(f"\n❌ Account not found: {identifier}\n")
                sys.exit(1)

    elif command == "remove":
        identifier = args.identifier

        try:
            index = int(identifier)
            if 0 <= index < len(credentials):
                email = credentials[index].get("email", "unknown")
                remove_credential(index)
                print(f"\n✓ Account removed: {email}\n")
            else:
                print(
                    f"\n❌ Invalid index: {index}. Valid range: 0-{len(credentials) - 1}\n"
                )
                sys.exit(1)
        except ValueError:
            found = any(c.get("email") == identifier for c in credentials)
            if found:
                remove_credential(identifier)
                print(f"\n✓ Account removed: {identifier}\n")
            else:
                print(f"\n❌ Account not found: {identifier}\n")
                sys.exit(1)


# --- Entry Point ---
if __name__ == "__main__":
    import uvicorn

    args = parse_cli_args()

    if args.command == "login":
        asyncio.run(handle_login_command(args))
    elif args.command == "usage":
        asyncio.run(handle_usage_command(args))
    elif args.command == "accounts":
        handle_accounts_command(args)
    else:
        validate_configuration()
        _warn_timeout_configuration()

        final_host, final_port = resolve_server_config(args)

        print_startup_banner(final_host, final_port)

        logger.info(f"Starting Uvicorn server on {final_host}:{final_port}...")

        uvicorn.run(
            "main:app",
            host=final_host,
            port=final_port,
            log_config=UVICORN_LOG_CONFIG,
        )
