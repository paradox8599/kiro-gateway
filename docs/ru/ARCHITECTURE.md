# Архитектурный Обзор: Kiro OpenAI Gateway

## 1. Назначение и Цели Системы

Проект представляет собой высокоуровневый прокси-шлюз, реализующий структурный паттерн проектирования **"Адаптер" (Adapter)**.

Основная цель системы — обеспечить прозрачную совместимость между двумя гетерогенными интерфейсами:
1.  **Target Interface (Клиент):** Стандартный протокол OpenAI API (эндпоинты `/v1/models`, `/v1/chat/completions`).
2.  **Adaptee (Поставщик):** Внутренний API Kiro IDE (AWS CodeWhisperer), обнаруженный в экосистеме Amazon Kiro.

Система выступает в роли "переводчика", позволяя использовать любые инструменты, библиотеки и IDE-плагины, разработанные для экосистемы OpenAI, с моделями Claude через Kiro API.

## 2. Структура Проекта

Проект организован в виде модульного Python-пакета `kiro_gateway/`:

```
kiro-openai-gateway/
├── main.py                    # Точка входа, создание FastAPI приложения
├── requirements.txt           # Зависимости Python
├── .env.example               # Пример конфигурации окружения
│
├── kiro_gateway/              # Основной пакет
│   ├── __init__.py            # Экспорты пакета, версия
│   ├── config.py              # Конфигурация и константы
│   ├── models.py              # Pydantic модели OpenAI API
│   ├── auth.py                # KiroAuthManager - управление токенами
│   ├── cache.py               # ModelInfoCache - кэш моделей
│   ├── utils.py               # Вспомогательные утилиты
│   ├── converters.py          # Конвертация OpenAI <-> Kiro
│   ├── parsers.py             # Парсеры AWS SSE потоков
│   ├── streaming.py           # Логика стриминга ответов
│   ├── http_client.py         # HTTP клиент с retry логикой
│   ├── routes.py              # FastAPI роуты
│   ├── debug_logger.py        # Отладочное логирование запросов
│   ├── tokenizer.py           # Подсчёт токенов (tiktoken)
│   └── exceptions.py          # Обработчики исключений
│
├── tests/                     # Тесты
│   ├── conftest.py            # Pytest fixtures
│   ├── unit/                  # Юнит-тесты
│   └── integration/           # Интеграционные тесты
│
├── docs/                      # Документация
│   ├── ru/                    # Русская версия
│   └── en/                    # Английская версия
│
└── debug_logs/                # Отладочные логи (генерируются при DEBUG_LAST_REQUEST=true)
```

## 3. Архитектурная Топология и Компоненты

Система построена на базе асинхронного фреймворка `FastAPI` и использует событийную модель управления жизненным циклом (`Lifespan Events`).

### 3.1. Точка входа (`main.py`)

Файл `main.py` отвечает за:

1. **Конфигурацию логирования** — настройка Loguru с цветным выводом
2. **Валидацию конфигурации** — функция `validate_configuration()` проверяет:
   - Наличие файла `.env`
   - Наличие credentials (REFRESH_TOKEN или KIRO_CREDS_FILE)
3. **Lifespan Manager** — создание и инициализация:
   - `KiroAuthManager` для управления токенами
   - `ModelInfoCache` для кэширования моделей
4. **Регистрация обработчиков ошибок** — `validation_exception_handler` для ошибок 422
5. **Подключение роутов** — `app.include_router(router)`

### 3.2. Модуль конфигурации (`kiro_gateway/config.py`)

Централизованное хранение всех настроек:

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `PROXY_API_KEY` | API ключ для доступа к прокси | `changeme_proxy_secret` |
| `REFRESH_TOKEN` | Refresh token Kiro | из `.env` |
| `PROFILE_ARN` | ARN профиля AWS CodeWhisperer | из `.env` |
| `REGION` | Регион AWS | `us-east-1` |
| `KIRO_CREDS_FILE` | Путь к JSON файлу credentials | из `.env` |
| `TOKEN_REFRESH_THRESHOLD` | Время до обновления токена | 600 сек (10 мин) |
| `MAX_RETRIES` | Макс. количество повторов | 3 |
| `BASE_RETRY_DELAY` | Базовая задержка retry | 1.0 сек |
| `MODEL_CACHE_TTL` | TTL кэша моделей | 3600 сек (1 час) |
| `DEFAULT_MAX_INPUT_TOKENS` | Макс. input токенов по умолчанию | 200000 |
| `TOOL_DESCRIPTION_MAX_LENGTH` | Макс. длина описания tool | 10000 символов |
| `DEBUG_LAST_REQUEST` | Включить отладочное логирование | `false` |
| `DEBUG_DIR` | Директория для debug логов | `debug_logs` |
| `APP_VERSION` | Версия приложения | `0.0.0` |

**Вспомогательные функции:**
- `get_kiro_refresh_url(region)` — URL для обновления токена
- `get_kiro_api_host(region)` — хост основного API
- `get_kiro_q_host(region)` — хост Q API
- `get_internal_model_id(external_model)` — конвертация имени модели

### 3.3. Pydantic Модели (`kiro_gateway/models.py`)

#### Модели для `/v1/models`

| Модель | Описание |
|--------|----------|
| `OpenAIModel` | Описание AI модели (id, object, created, owned_by) |
| `ModelList` | Список моделей для ответа endpoint |

#### Модели для `/v1/chat/completions`

| Модель | Описание |
|--------|----------|
| `ChatMessage` | Сообщение чата (role, content, tool_calls, tool_call_id) |
| `ToolFunction` | Описание функции инструмента (name, description, parameters) |
| `Tool` | Инструмент OpenAI формата (type, function) |
| `ChatCompletionRequest` | Запрос на генерацию (model, messages, stream, tools, ...) |

#### Модели ответов

| Модель | Описание |
|--------|----------|
| `ChatCompletionChoice` | Один вариант ответа |
| `ChatCompletionUsage` | Информация о токенах (prompt_tokens, completion_tokens, credits_used) |
| `ChatCompletionResponse` | Полный ответ (non-streaming) |
| `ChatCompletionChunk` | Streaming chunk |
| `ChatCompletionChunkDelta` | Дельта изменений в chunk |
| `ChatCompletionChunkChoice` | Вариант в streaming chunk |

### 3.4. Управление Состоянием (State Management Layer)

#### KiroAuthManager (`kiro_gateway/auth.py`)

**Роль:** Stateful-синглтон, инкапсулирующий логику управления токенами Kiro.

**Возможности:**
- Загрузка credentials из `.env` или JSON файла
- Поддержка `expiresAt` для проверки времени истечения токена
- Автоматическое обновление токена за 10 минут до истечения
- Сохранение обновлённых токенов обратно в JSON файл
- Поддержка разных регионов AWS
- Генерация уникального fingerprint для User-Agent

**Concurrency Control:** Использует `asyncio.Lock` для защиты от состояния гонки.

**Основные методы:**
- `get_access_token()` — возвращает действительный токен, обновляя при необходимости
- `force_refresh()` — принудительное обновление токена (при 403)
- `is_token_expiring_soon()` — проверка времени истечения

**Properties:**
- `profile_arn` — ARN профиля
- `region` — регион AWS
- `api_host` — хост API для региона
- `q_host` — хост Q API для региона
- `fingerprint` — уникальный fingerprint машины

```python
# Пример использования
auth_manager = KiroAuthManager(
    refresh_token="your_token",
    region="us-east-1",
    creds_file="~/.aws/sso/cache/kiro-auth-token.json"
)
token = await auth_manager.get_access_token()
```

#### ModelInfoCache (`kiro_gateway/cache.py`)

**Роль:** Потокобезопасное хранилище конфигураций моделей.

**Стратегия Заполнения:** 
- Lazy Loading через `/ListAvailableModels`
- TTL кэша: 1 час
- Fallback на статический список моделей

**Основные методы:**
- `update(models_data)` — обновление кэша
- `get(model_id)` — получение информации о модели
- `get_max_input_tokens(model_id)` — получение лимита токенов
- `is_empty()` / `is_stale()` — проверка состояния кэша
- `get_all_model_ids()` — список всех ID моделей

### 3.5. Вспомогательные Утилиты (`kiro_gateway/utils.py`)

| Функция | Описание |
|---------|----------|
| `get_machine_fingerprint()` | SHA256 хеш `{hostname}-{username}-kiro-gateway` |
| `get_kiro_headers(auth_manager, token)` | Формирование заголовков для Kiro API |
| `generate_completion_id()` | ID в формате `chatcmpl-{uuid_hex}` |
| `generate_conversation_id()` | UUID для разговора |
| `generate_tool_call_id()` | ID в формате `call_{uuid_hex[:8]}` |

### 3.6. Слой Конвертации (`kiro_gateway/converters.py`)

#### Конвертация сообщений

OpenAI messages преобразуются в Kiro conversationState:

1. **System prompt** — добавляется к первому user сообщению
2. **История сообщений** — полностью передаётся в `history` array
3. **Объединение соседних сообщений** — сообщения с одинаковой ролью мерджатся
4. **Tool calls** — поддержка OpenAI tools формата
5. **Tool results** — корректная передача результатов вызова инструментов

#### Обработка длинных описаний Tools

**Проблема:** Kiro API возвращает ошибку 400 при слишком длинных описаниях в `toolSpecification.description`.

**Решение:** Tool Documentation Reference Pattern
- Если `description ≤ TOOL_DESCRIPTION_MAX_LENGTH` → оставляем как есть
- Если `description > TOOL_DESCRIPTION_MAX_LENGTH`:
  * В `toolSpecification.description` → ссылка: `"[Full documentation in system prompt under '## Tool: {name}']"`
  * В system prompt добавляется секция `"## Tool: {name}"` с полным описанием

**Функция:** `process_tools_with_long_descriptions(tools)` → `(processed_tools, tool_documentation)`

#### Основные функции

| Функция | Описание |
|---------|----------|
| `extract_text_content(content)` | Извлечение текста из различных форматов |
| `merge_adjacent_messages(messages)` | Объединение соседних сообщений с одной ролью |
| `build_kiro_history(messages, model_id)` | Построение массива history для Kiro |
| `build_kiro_payload(request_data, conversation_id, profile_arn)` | Полный payload для запроса |

#### Маппинг моделей

Внешние имена моделей преобразуются во внутренние ID Kiro:

| Внешнее имя | Внутренний ID Kiro |
|-------------|-------------------|
| `claude-opus-4-5` | `claude-opus-4.5` |
| `claude-opus-4-5-20251101` | `claude-opus-4.5` |
| `claude-haiku-4-5` | `claude-haiku-4.5` |
| `claude-haiku-4.5` | `claude-haiku-4.5` (прямой проброс) |
| `claude-sonnet-4-5` | `CLAUDE_SONNET_4_5_20250929_V1_0` |
| `claude-sonnet-4-5-20250929` | `CLAUDE_SONNET_4_5_20250929_V1_0` |
| `claude-sonnet-4` | `CLAUDE_SONNET_4_20250514_V1_0` |
| `claude-sonnet-4-20250514` | `CLAUDE_SONNET_4_20250514_V1_0` |
| `claude-3-7-sonnet-20250219` | `CLAUDE_3_7_SONNET_20250219_V1_0` |
| `auto` | `claude-sonnet-4.5` (алиас) |

### 3.7. Слой Парсинга (`kiro_gateway/parsers.py`)

#### AwsEventStreamParser

Продвинутый парсер AWS SSE формата с поддержкой:

- **Bracket counting** — корректный парсинг вложенных JSON объектов
- **Дедупликация контента** — фильтрация повторяющихся событий
- **Tool calls** — парсинг структурированных и bracket-style tool calls
- **Escape-последовательности** — декодирование `\n` и других

#### Типы событий

| Событие | Описание |
|---------|----------|
| `content` | Текстовый контент ответа |
| `tool_start` | Начало tool call (name, toolUseId) |
| `tool_input` | Продолжение input для tool call |
| `tool_stop` | Завершение tool call |
| `usage` | Информация о потреблении кредитов |
| `context_usage` | Процент использования контекста |

#### Вспомогательные функции

| Функция | Описание |
|---------|----------|
| `find_matching_brace(text, start_pos)` | Поиск закрывающей скобки с учётом вложенности |
| `parse_bracket_tool_calls(response_text)` | Парсинг `[Called func with args: {...}]` |
| `deduplicate_tool_calls(tool_calls)` | Удаление дубликатов tool calls |

### 3.8. Streaming (`kiro_gateway/streaming.py`)

#### stream_kiro_to_openai

Асинхронный генератор для преобразования потока Kiro в OpenAI формат.

**Функциональность:**
- Парсинг AWS SSE stream через `AwsEventStreamParser`
- Формирование OpenAI `chat.completion.chunk`
- Обработка tool calls (структурированных и bracket-style)
- Вычисление usage на основе `contextUsagePercentage`
- Отладочное логирование через `debug_logger`

#### collect_stream_response

Собирает полный ответ из streaming потока для non-streaming режима.

### 3.9. HTTP Клиент (`kiro_gateway/http_client.py`)

#### KiroHttpClient

Автоматическая обработка ошибок с exponential backoff:

| Код ошибки | Действие |
|------------|----------|
| `403` | Refresh токена через `force_refresh()` + повтор |
| `429` | Exponential backoff: `BASE_RETRY_DELAY * (2 ** attempt)` |
| `5xx` | Exponential backoff (до MAX_RETRIES попыток) |
| Timeout | Exponential backoff |

**Формула задержки:** `1s, 2s, 4s` (при `BASE_RETRY_DELAY=1.0`)

**Методы:**
- `request_with_retry(method, url, json_data, stream)` — запрос с retry
- `close()` — закрытие клиента

Поддерживает async context manager (`async with`).

### 3.10. Роуты (`kiro_gateway/routes.py`)

| Endpoint | Метод | Описание |
|----------|-------|----------|
| `/` | GET | Health check (status, message, version) |
| `/health` | GET | Детальный health check (status, timestamp, version) |
| `/v1/models` | GET | Список доступных моделей (требует API key) |
| `/v1/chat/completions` | POST | Chat completions (требует API key) |

**Аутентификация:** Bearer token в заголовке `Authorization`

### 3.11. Обработка Исключений (`kiro_gateway/exceptions.py`)

| Функция | Описание |
|---------|----------|
| `sanitize_validation_errors(errors)` | Конвертация bytes в строки для JSON-сериализации |
| `validation_exception_handler(request, exc)` | Обработчик ошибок валидации Pydantic (422) |

### 3.12. Отладочное Логирование (`kiro_gateway/debug_logger.py`)

**Класс:** `DebugLogger` (синглтон)

**Активация:** `DEBUG_LAST_REQUEST=true` в `.env`

**Методы:**
| Метод | Описание |
|-------|----------|
| `prepare_new_request()` | Очистка директории для нового запроса |
| `log_request_body(body)` | Сохранение входящего запроса |
| `log_kiro_request_body(body)` | Сохранение запроса к Kiro API |
| `log_raw_chunk(chunk)` | Дописывание сырого chunk от Kiro |
| `log_modified_chunk(chunk)` | Дописывание преобразованного chunk |

**Файлы в `debug_logs/`:**
- `request_body.json` — входящий запрос (OpenAI формат)
- `kiro_request_body.json` — запрос к Kiro API
- `response_stream_raw.txt` — сырой поток от Kiro
- `response_stream_modified.txt` — преобразованный поток (OpenAI формат)

### 3.13. Токенизатор (`kiro_gateway/tokenizer.py`)

**Проблема:** Kiro API не возвращает напрямую количество токенов. Вместо этого API предоставляет только `context_usage_percentage` — процент использования контекста модели.

**Решение:** Модуль токенизатора на базе `tiktoken` (библиотека OpenAI на Rust) для быстрого подсчёта токенов.

**Особенности:**
- Использует кодировку `cl100k_base` (GPT-4), близкую к токенизации Claude
- Коэффициент коррекции `CLAUDE_CORRECTION_FACTOR = 1.15` для повышения точности
- Ленивая инициализация для ускорения импорта
- Fallback на грубую оценку если tiktoken недоступен

**Формула расчёта токенов в ответе:**
```
total_tokens = context_usage_percentage × max_input_tokens  (от API Kiro)
completion_tokens = tiktoken(ответ)                         (наш подсчёт)
prompt_tokens = total_tokens - completion_tokens            (вычитание)
```

**Основные функции:**

| Функция | Описание |
|---------|----------|
| `count_tokens(text)` | Подсчёт токенов в тексте |
| `count_message_tokens(messages)` | Подсчёт токенов в списке сообщений |
| `count_tools_tokens(tools)` | Подсчёт токенов в определениях инструментов |
| `estimate_request_tokens(messages, tools)` | Полная оценка токенов запроса |

**Дебаг-лог:**
```
[Usage] claude-opus-4-5: prompt_tokens=142211 (subtraction), completion_tokens=769 (tiktoken), total_tokens=142980 (API Kiro)
```

**Точность:** ~97-99.7% по сравнению с данными от API.

### 3.14. Kiro API Endpoints

Все URL динамически формируются на основе региона:

*   **Token Refresh:** `POST https://prod.{region}.auth.desktop.kiro.dev/refreshToken`
*   **List Models:** `GET https://q.{region}.amazonaws.com/ListAvailableModels`
*   **Generate Response:** `POST https://codewhisperer.{region}.amazonaws.com/generateAssistantResponse`

## 4. Детальный Поток Данных

```
┌─────────────────┐
│  OpenAI Client  │
└────────┬────────┘
         │ POST /v1/chat/completions
         ▼
┌─────────────────┐
│  Security Gate  │ ◄── Проверка Bearer токена прокси
│  (routes.py)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ KiroAuthManager │ ◄── Получение/обновление accessToken
│   (auth.py)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Payload Builder │ ◄── Конвертация OpenAI → Kiro формат
│ (converters.py) │     (история, system prompt, tools)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ KiroHttpClient  │ ◄── Retry логика (403, 429, 5xx)
│ (http_client.py)│
└────────┬────────┘
         │ POST /generateAssistantResponse
         ▼
┌─────────────────┐
│   Kiro API      │
└────────┬────────┘
         │ AWS SSE Stream
         ▼
┌─────────────────┐
│ SSE Parser      │ ◄── Парсинг событий, tool calls
│  (parsers.py)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ OpenAI Format   │ ◄── Конвертация в OpenAI SSE
│ (streaming.py)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  OpenAI Client  │
└─────────────────┘
```

## 5. Доступные Модели

| Модель | Описание | Credits |
|--------|----------|---------|
| `claude-opus-4-5` | Топовая модель | ~2.2 |
| `claude-opus-4-5-20251101` | Топовая модель (версия) | ~2.2 |
| `claude-sonnet-4-5` | Улучшенная модель | ~1.3 |
| `claude-sonnet-4-5-20250929` | Улучшенная модель (версия) | ~1.3 |
| `claude-sonnet-4` | Сбалансированная модель | ~1.3 |
| `claude-sonnet-4-20250514` | Сбалансированная (версия) | ~1.3 |
| `claude-haiku-4-5` | Быстрая модель | ~0.4 |
| `claude-3-7-sonnet-20250219` | Legacy модель | ~1.0 |

## 6. Конфигурация

### Переменные окружения (.env)

```env
# Обязательные
REFRESH_TOKEN="your_kiro_refresh_token"
PROXY_API_KEY="your_proxy_secret"

# Опциональные
PROFILE_ARN="arn:aws:codewhisperer:..."
KIRO_REGION="us-east-1"
KIRO_CREDS_FILE="~/.aws/sso/cache/kiro-auth-token.json"

# Отладка
DEBUG_LAST_REQUEST="false"
DEBUG_DIR="debug_logs"

# Лимиты
TOOL_DESCRIPTION_MAX_LENGTH="10000"
```

### JSON файл credentials (опционально)

```json
{
  "accessToken": "eyJ...",
  "refreshToken": "eyJ...",
  "expiresAt": "2025-01-12T23:00:00.000Z",
  "profileArn": "arn:aws:codewhisperer:us-east-1:...",
  "region": "us-east-1"
}
```

## 7. API Endpoints

| Endpoint | Метод | Описание |
|----------|-------|----------|
| `/` | GET | Health check |
| `/health` | GET | Детальный health check |
| `/v1/models` | GET | Список доступных моделей |
| `/v1/chat/completions` | POST | Chat completions (streaming/non-streaming) |

## 8. Особенности Реализации

### Tool Calling

Поддержка OpenAI-совместимого формата tools:

```json
{
  "tools": [{
    "type": "function",
    "function": {
      "name": "get_weather",
      "description": "Get weather for a location",
      "parameters": {
        "type": "object",
        "properties": {
          "location": {"type": "string"}
        }
      }
    }
  }]
}
```

### Streaming

Полная поддержка SSE streaming с корректным форматом OpenAI:

```
data: {"id":"chatcmpl-...","object":"chat.completion.chunk",...}

data: [DONE]
```

### Отладка

При `DEBUG_LAST_REQUEST=true` все запросы и ответы логируются в `debug_logs/`:
- `request_body.json` — входящий запрос
- `kiro_request_body.json` — запрос к Kiro API
- `response_stream_raw.txt` — сырой поток от Kiro
- `response_stream_modified.txt` — преобразованный поток

## 9. Расширяемость

### Добавление нового провайдера

Модульная архитектура позволяет легко добавить поддержку других провайдеров:

1. Создать новый модуль `kiro_gateway/providers/new_provider.py`
2. Реализовать классы:
   - `NewProviderAuthManager` — управление токенами
   - `NewProviderConverter` — конвертация форматов
   - `NewProviderParser` — парсинг ответов
3. Добавить роуты в `routes.py` или создать отдельный роутер

### Пример структуры для нового провайдера

```python
# kiro_gateway/providers/gemini.py

class GeminiAuthManager:
    """Управление API ключами Gemini."""
    pass

class GeminiConverter:
    """Конвертация OpenAI -> Gemini формат."""
    pass

class GeminiParser:
    """Парсинг SSE потока Gemini."""
    pass
```

## 10. Зависимости

Основные зависимости проекта (из `requirements.txt`):

| Пакет | Назначение |
|-------|------------|
| `fastapi` | Асинхронный веб-фреймворк |
| `uvicorn` | ASGI сервер |
| `httpx` | Асинхронный HTTP клиент |
| `pydantic` | Валидация данных и модели |
| `python-dotenv` | Загрузка переменных окружения |
| `loguru` | Продвинутое логирование |
| `tiktoken` | Быстрый подсчёт токенов |
