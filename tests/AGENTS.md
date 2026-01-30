# tests/ - AI Agent Guide

**Test suite with complete network isolation.**

## CRITICAL: NETWORK ISOLATION

**ALL tests are blocked from real network calls.**

```python
# Global fixture in conftest.py (autouse=True, scope="session")
# Any httpx.AsyncClient call raises:
# RuntimeError("🚨 CRITICAL ERROR: Real network request attempt detected!")
```

**You MUST mock all HTTP responses. No exceptions.**

## STRUCTURE

```
tests/
├── conftest.py          # 1132 lines - ALL fixtures here
├── unit/                # 29 test files, 1354 tests
│   ├── test_auth_manager.py
│   ├── test_converters_*.py
│   ├── test_streaming_*.py
│   └── ...
└── integration/         # End-to-end flows
    └── test_full_flow.py
```

## FIXTURE CATEGORIES (conftest.py)

| Category | Examples | Purpose |
|----------|----------|---------|
| **Auth** | `mock_auth_manager`, `valid_kiro_token` | Token mocking |
| **HTTP** | `mock_httpx_client`, `mock_httpx_response` | HTTP response factories |
| **Kiro API** | `mock_kiro_models_response`, `mock_kiro_streaming_chunks` | API response mocks |
| **Requests** | `sample_openai_chat_request`, `sample_tool_definition` | Request factories |
| **Credentials** | `temp_creds_file`, `temp_aws_sso_creds_file`, `temp_sqlite_db` | All 4 auth methods |
| **App** | `clean_app`, `test_client`, `async_test_client` | FastAPI test clients |

## TEST PATTERNS

### Naming
```python
class TestKiroAuthManagerTokenExpiration:  # Test<Component><Category>
    async def test_expired_token_triggers_refresh(self):  # test_<what>_<expected>
```

### Structure (Arrange-Act-Assert)
```python
@pytest.mark.asyncio
async def test_valid_bearer_token_returns_true(self):
    """
    What it does: Verifies valid Bearer token passes auth.
    Purpose: Ensure correct API keys are accepted.
    """
    # Arrange
    print("Setup: Creating valid Bearer token...")
    valid_header = f"Bearer {PROXY_API_KEY}"
    
    # Act
    print("Action: Calling verify_api_key...")
    result = await verify_api_key(valid_header)
    
    # Assert
    print(f"Comparing: Expected True, Got {result}")
    assert result is True
```

### Mocking HTTP
```python
@pytest.mark.asyncio
async def test_token_refresh(mock_httpx_response):
    mock_response = mock_httpx_response(
        status_code=200,
        json_data={"accessToken": "new_token", "expiresIn": 3600}
    )
    
    with patch('kiro.auth.httpx.AsyncClient') as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(
            return_value=mock_response
        )
        # Test code here
```

### Streaming Mocks
```python
async def mock_parse_kiro_stream(*args, **kwargs):
    yield KiroEvent(type="content", content="Hello")
    yield KiroEvent(type="content", content=" World")

with patch('kiro.streaming_openai.parse_kiro_stream', mock_parse_kiro_stream):
    # Test streaming code
```

## COMMANDS

```bash
pytest                           # All tests
pytest -v                        # Verbose
pytest tests/unit/ -v            # Unit only
pytest -x                        # Stop on first failure
pytest -l                        # Show locals on error
pytest --cov=kiro --cov-report=html  # Coverage
pytest tests/unit/test_auth_manager.py::TestKiroAuthManagerInitialization -v  # Specific
```

## CONVENTIONS

| Convention | Rule |
|------------|------|
| **Async tests** | Always use `@pytest.mark.asyncio` |
| **Print statements** | Add for debugging (4751 total in suite) |
| **Docstrings** | "What it does" + "Purpose" format |
| **Fixtures** | Use factories, not static values |
| **Edge cases** | Separate `Test*EdgeCases` classes |
| **Network** | NEVER make real calls |

## ADDING TESTS

1. **Find similar test** in existing files
2. **Use fixtures** from `conftest.py` (don't create new mocks inline)
3. **Add print statements** for debugging
4. **Include docstring** with "What it does" and "Purpose"
5. **Mock ALL HTTP** - network calls will fail

## FIXTURE FACTORIES

```python
# Use factories for customization
@pytest.fixture
def mock_kiro_token_response(valid_kiro_token):
    def _create_response(expires_in=3600, token=None):
        return {
            "accessToken": token or valid_kiro_token,
            "expiresIn": expires_in
        }
    return _create_response

# Usage in test
def test_something(mock_kiro_token_response):
    response = mock_kiro_token_response(expires_in=7200)  # Custom expiry
```

## CREDENTIAL FIXTURES

| Fixture | Auth Method |
|---------|-------------|
| `temp_creds_file` | Kiro Desktop JSON |
| `temp_aws_sso_creds_file` | AWS SSO OIDC |
| `temp_sqlite_db` | kiro-cli SQLite |
| `temp_enterprise_ide_creds_file` | Enterprise IDE |
