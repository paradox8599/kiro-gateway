# kiro/ Package - AI Agent Guide

**Core package for Kiro Gateway proxy server.**

## ARCHITECTURE

```
Layers (request flow):
  routes_*.py → converters_*.py → http_client.py → streaming_*.py → response
```

| Layer | Files | Purpose |
|-------|-------|---------|
| **Routes** | `routes_openai.py`, `routes_anthropic.py`, `routes_auth.py`, `routes_accounts.py` | FastAPI endpoints, auth validation |
| **Converters** | `converters_core.py`, `converters_openai.py`, `converters_anthropic.py` | Format translation (OpenAI/Anthropic → Kiro) |
| **Streaming** | `streaming_core.py`, `streaming_openai.py`, `streaming_anthropic.py` | SSE processing (Kiro → client format) |
| **Core** | `auth.py`, `account_manager.py`, `http_client.py`, `model_resolver.py`, `cache.py` | Auth, HTTP, model resolution |
| **Parsers** | `parsers.py`, `thinking_parser.py` | AWS event stream, thinking block FSM |
| **Models** | `models_openai.py`, `models_anthropic.py` | Pydantic request/response schemas |

## CRITICAL PATTERNS

### 1. Per-Request HTTP Clients for Streaming
```python
# ✅ CORRECT: Per-request client prevents CLOSE_WAIT leaks
async with httpx.AsyncClient(timeout=timeout) as client:
    async with client.stream("POST", url, json=payload) as response:
        async for line in response.aiter_lines():
            yield line

# ❌ WRONG: Shared client for streaming causes socket leaks
```

### 2. Model Family Isolation
- Opus → NEVER becomes Sonnet/Haiku
- Sonnet → NEVER becomes Opus/Haiku
- Haiku → NEVER becomes Opus/Sonnet
- Aliases MUST NOT cross family boundaries

### 3. Image Placement
```python
# ✅ CORRECT: Images in userInputMessage.images
payload["userInputMessage"]["images"] = [...]

# ❌ WRONG: Images in userInputMessageContext.images (causes API errors)
```

### 4. AWS SSO OIDC Format
```python
# ✅ CORRECT: JSON payload with camelCase
payload = {"clientId": "...", "clientSecret": "...", "grantType": "refresh_token"}

# ❌ WRONG: Form-urlencoded or snake_case
```

## WHERE TO LOOK

| Task | File | Notes |
|------|------|-------|
| Add OpenAI endpoint | `routes_openai.py` | Follow existing pattern |
| Add Anthropic endpoint | `routes_anthropic.py` | Uses `x-api-key` header |
| Convert request format | `converters_*.py` | Core logic in `converters_core.py` |
| Handle streaming | `streaming_*.py` | Per-request client required |
| Add model alias | `model_resolver.py` | Check family isolation |
| Token refresh | `auth.py` | Auto-detects auth type |
| Multi-account | `account_manager.py` | Round-robin, failure tracking |
| Parse AWS events | `parsers.py` | Handles bracket format `[{...}]` |
| Extract thinking | `thinking_parser.py` | FSM-based extraction |

## KEY CLASSES

| Class | File | Purpose |
|-------|------|---------|
| `KiroAuthManager` | `auth.py` | Token lifecycle, 4 auth methods |
| `AccountManager` | `account_manager.py` | Multi-account load balancing |
| `KiroHttpClient` | `http_client.py` | Retry logic (403, 429, 5xx) |
| `ModelResolver` | `model_resolver.py` | 4-layer resolution pipeline |
| `ModelInfoCache` | `cache.py` | Model metadata caching |
| `AwsEventStreamParser` | `parsers.py` | AWS SSE parsing |
| `ThinkingParser` | `thinking_parser.py` | FSM for `<thinking>` blocks |

## ANTI-PATTERNS

| Pattern | Why Bad |
|---------|---------|
| Shared client for streaming | CLOSE_WAIT socket leaks |
| Cross-family model aliases | Security/pricing tier violation |
| Images in `userInputMessageContext` | API errors |
| Form-urlencoded for AWS SSO | API errors |
| `as any`, `@ts-ignore` | N/A (Python project) |
| Empty `except:` blocks | Swallows errors silently |

## ADDING NEW FUNCTIONALITY

### New Endpoint
1. Define Pydantic models in `models_*.py`
2. Add route in `routes_*.py`
3. Add converter in `converters_*.py` (if format translation needed)
4. Add streaming in `streaming_*.py` (if streaming needed)
5. Write tests in `tests/unit/test_routes_*.py`

### New Model
```python
# In config.py - add to HIDDEN_MODELS for undocumented models
HIDDEN_MODELS = ["claude-new-model-1.0"]
```

### New Auth Method
1. Add detection logic in `auth.py` `_detect_auth_type()`
2. Add refresh logic in `_refresh_token_*()` method
3. Add tests for new auth type
