# -*- coding: utf-8 -*-

# Kiro OpenAI Gateway
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
Streaming логика для преобразования потока Kiro в OpenAI формат.

Содержит генераторы для:
- Преобразования AWS SSE в OpenAI SSE
- Формирования streaming chunks
- Обработки tool calls в потоке
"""

import asyncio
import json
import time
from typing import TYPE_CHECKING, AsyncGenerator, Callable, Awaitable, Optional

import httpx
from fastapi import HTTPException
from loguru import logger

from kiro_gateway.parsers import AwsEventStreamParser, parse_bracket_tool_calls, deduplicate_tool_calls
from kiro_gateway.utils import generate_completion_id
from kiro_gateway.config import FIRST_TOKEN_TIMEOUT, FIRST_TOKEN_MAX_RETRIES
from kiro_gateway.tokenizer import count_tokens

if TYPE_CHECKING:
    from kiro_gateway.auth import KiroAuthManager
    from kiro_gateway.cache import ModelInfoCache

# Импортируем debug_logger для логирования
try:
    from kiro_gateway.debug_logger import debug_logger
except ImportError:
    debug_logger = None


class FirstTokenTimeoutError(Exception):
    """Исключение при таймауте ожидания первого токена."""
    pass


async def stream_kiro_to_openai_internal(
    client: httpx.AsyncClient,
    response: httpx.Response,
    model: str,
    model_cache: "ModelInfoCache",
    auth_manager: "KiroAuthManager",
    first_token_timeout: float = FIRST_TOKEN_TIMEOUT
) -> AsyncGenerator[str, None]:
    """
    Внутренний генератор для преобразования потока Kiro в OpenAI формат.
    
    Парсит AWS SSE stream и конвертирует события в OpenAI chat.completion.chunk.
    Поддерживает tool calls и вычисление usage.
    
    ВАЖНО: Эта функция выбрасывает FirstTokenTimeoutError если первый токен
    не получен в течение first_token_timeout секунд.
    
    Args:
        client: HTTP клиент (для управления соединением)
        response: HTTP ответ с потоком данных
        model: Имя модели для включения в ответ
        model_cache: Кэш моделей для получения лимитов токенов
        auth_manager: Менеджер аутентификации
        first_token_timeout: Таймаут ожидания первого токена (секунды)
    
    Yields:
        Строки в формате SSE: "data: {...}\\n\\n" или "data: [DONE]\\n\\n"
    
    Raises:
        FirstTokenTimeoutError: Если первый токен не получен в течение таймаута
    
    Example:
        >>> async for chunk in stream_kiro_to_openai_internal(client, response, "claude-sonnet-4", cache, auth):
        ...     print(chunk)
        data: {"id":"chatcmpl-...","object":"chat.completion.chunk",...}
        
        data: [DONE]
    """
    completion_id = generate_completion_id()
    created_time = int(time.time())
    first_chunk = True
    first_token_received = False
    
    parser = AwsEventStreamParser()
    metering_data = None
    context_usage_percentage = None
    full_content = ""
    
    try:
        # Создаём итератор для чтения байтов
        byte_iterator = response.aiter_bytes()
        
        # Ожидаем первый chunk с таймаутом
        try:
            first_byte_chunk = await asyncio.wait_for(
                byte_iterator.__anext__(),
                timeout=first_token_timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"First token timeout after {first_token_timeout}s")
            raise FirstTokenTimeoutError(f"No response within {first_token_timeout} seconds")
        except StopAsyncIteration:
            # Пустой ответ - это нормально, просто завершаем
            logger.debug("Empty response from Kiro API")
            yield "data: [DONE]\n\n"
            return
        
        # Обрабатываем первый chunk
        if debug_logger:
            debug_logger.log_raw_chunk(first_byte_chunk)
        
        events = parser.feed(first_byte_chunk)
        for event in events:
            if event["type"] == "content":
                first_token_received = True
                content = event["data"]
                full_content += content
                
                delta = {"content": content}
                if first_chunk:
                    delta["role"] = "assistant"
                    first_chunk = False
                
                openai_chunk = {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": created_time,
                    "model": model,
                    "choices": [{"index": 0, "delta": delta, "finish_reason": None}]
                }
                
                chunk_text = f"data: {json.dumps(openai_chunk, ensure_ascii=False)}\n\n"
                
                if debug_logger:
                    debug_logger.log_modified_chunk(chunk_text.encode('utf-8'))
                
                yield chunk_text
            
            elif event["type"] == "usage":
                metering_data = event["data"]
            
            elif event["type"] == "context_usage":
                context_usage_percentage = event["data"]
        
        # Продолжаем читать остальные chunks (уже без таймаута на первый токен)
        async for chunk in byte_iterator:
            # Логируем сырой chunk
            if debug_logger:
                debug_logger.log_raw_chunk(chunk)
            
            events = parser.feed(chunk)
            
            for event in events:
                if event["type"] == "content":
                    content = event["data"]
                    full_content += content
                    
                    # Формируем delta
                    delta = {"content": content}
                    if first_chunk:
                        delta["role"] = "assistant"
                        first_chunk = False
                    
                    # Формируем OpenAI chunk
                    openai_chunk = {
                        "id": completion_id,
                        "object": "chat.completion.chunk",
                        "created": created_time,
                        "model": model,
                        "choices": [{"index": 0, "delta": delta, "finish_reason": None}]
                    }
                    
                    chunk_text = f"data: {json.dumps(openai_chunk, ensure_ascii=False)}\n\n"
                    
                    # Логируем модифицированный chunk
                    if debug_logger:
                        debug_logger.log_modified_chunk(chunk_text.encode('utf-8'))
                    
                    yield chunk_text
                
                elif event["type"] == "usage":
                    metering_data = event["data"]
                
                elif event["type"] == "context_usage":
                    context_usage_percentage = event["data"]
        
        # Проверяем bracket-style tool calls в полном контенте
        bracket_tool_calls = parse_bracket_tool_calls(full_content)
        all_tool_calls = parser.get_tool_calls() + bracket_tool_calls
        all_tool_calls = deduplicate_tool_calls(all_tool_calls)
        
        # Определяем finish_reason
        finish_reason = "tool_calls" if all_tool_calls else "stop"
        
        # Вычисляем total_tokens на основе context_usage_percentage
        # context_usage показывает ОБЩИЙ процент использования контекста (input + output)
        total_tokens_from_api = 0
        if context_usage_percentage is not None:
            max_input_tokens = model_cache.get_max_input_tokens(model)
            total_tokens_from_api = int((context_usage_percentage / 100) * max_input_tokens)
        
        # Подсчитываем completion_tokens (output) с помощью tiktoken
        completion_tokens = count_tokens(full_content)
        
        # prompt_tokens (input) = total_tokens - completion_tokens
        # Это логично: общее использование контекста минус токены ответа = токены запроса
        prompt_tokens = max(0, total_tokens_from_api - completion_tokens)
        total_tokens = total_tokens_from_api
        
        # Отправляем tool calls если есть
        if all_tool_calls:
            logger.debug(f"Processing {len(all_tool_calls)} tool calls for streaming response")
            
            # Добавляем обязательное поле index к каждому tool_call
            # согласно спецификации OpenAI API для streaming
            indexed_tool_calls = []
            for idx, tc in enumerate(all_tool_calls):
                # Извлекаем function с защитой от None
                func = tc.get("function") or {}
                # Используем "or" для защиты от явного None в значениях
                tool_name = func.get("name") or ""
                tool_args = func.get("arguments") or "{}"
                
                logger.debug(f"Tool call [{idx}] '{tool_name}': id={tc.get('id')}, args_length={len(tool_args)}")
                
                indexed_tc = {
                    "index": idx,
                    "id": tc.get("id"),
                    "type": tc.get("type", "function"),
                    "function": {
                        "name": tool_name,
                        "arguments": tool_args
                    }
                }
                indexed_tool_calls.append(indexed_tc)
            
            tool_calls_chunk = {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": created_time,
                "model": model,
                "choices": [{
                    "index": 0,
                    "delta": {"tool_calls": indexed_tool_calls},
                    "finish_reason": None
                }]
            }
            yield f"data: {json.dumps(tool_calls_chunk, ensure_ascii=False)}\n\n"
        
        # Финальный чанк с usage
        final_chunk = {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": created_time,
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            }
        }
        
        if metering_data:
            final_chunk["usage"]["credits_used"] = metering_data
        
        # Логируем финальные значения токенов которые отправляются клиенту
        logger.debug(
            f"[Usage] {model}: "
            f"prompt_tokens={prompt_tokens} (subtraction), "
            f"completion_tokens={completion_tokens} (tiktoken), "
            f"total_tokens={total_tokens} (API Kiro)"
        )
        
        yield f"data: {json.dumps(final_chunk, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"
        
    except FirstTokenTimeoutError:
        # Пробрасываем таймаут наверх для retry
        raise
    except Exception as e:
        logger.error(f"Error during streaming: {e}", exc_info=True)
    finally:
        await response.aclose()
        logger.debug("Streaming completed")


async def stream_kiro_to_openai(
    client: httpx.AsyncClient,
    response: httpx.Response,
    model: str,
    model_cache: "ModelInfoCache",
    auth_manager: "KiroAuthManager"
) -> AsyncGenerator[str, None]:
    """
    Генератор для преобразования потока Kiro в OpenAI формат.
    
    Это wrapper над stream_kiro_to_openai_internal, который НЕ делает retry.
    Retry логика реализована в stream_with_first_token_retry.
    
    Args:
        client: HTTP клиент (для управления соединением)
        response: HTTP ответ с потоком данных
        model: Имя модели для включения в ответ
        model_cache: Кэш моделей для получения лимитов токенов
        auth_manager: Менеджер аутентификации
    
    Yields:
        Строки в формате SSE: "data: {...}\\n\\n" или "data: [DONE]\\n\\n"
    """
    async for chunk in stream_kiro_to_openai_internal(
        client, response, model, model_cache, auth_manager
    ):
        yield chunk


async def stream_with_first_token_retry(
    make_request: Callable[[], Awaitable[httpx.Response]],
    client: httpx.AsyncClient,
    model: str,
    model_cache: "ModelInfoCache",
    auth_manager: "KiroAuthManager",
    max_retries: int = FIRST_TOKEN_MAX_RETRIES,
    first_token_timeout: float = FIRST_TOKEN_TIMEOUT
) -> AsyncGenerator[str, None]:
    """
    Streaming с автоматическим retry при таймауте первого токена.
    
    Если модель не отвечает в течение first_token_timeout секунд,
    запрос отменяется и делается новый. Максимум max_retries попыток.
    
    Это seamless для пользователя - он просто видит задержку,
    но в итоге получает ответ (или ошибку после всех попыток).
    
    Args:
        make_request: Функция для создания нового HTTP запроса
        client: HTTP клиент
        model: Имя модели
        model_cache: Кэш моделей
        auth_manager: Менеджер аутентификации
        max_retries: Максимальное количество попыток
        first_token_timeout: Таймаут ожидания первого токена (секунды)
    
    Yields:
        Строки в формате SSE
    
    Raises:
        HTTPException: После исчерпания всех попыток
    
    Example:
        >>> async def make_req():
        ...     return await http_client.request_with_retry("POST", url, payload, stream=True)
        >>> async for chunk in stream_with_first_token_retry(make_req, client, model, cache, auth):
        ...     print(chunk)
    """
    last_error: Optional[Exception] = None
    
    for attempt in range(max_retries):
        response: Optional[httpx.Response] = None
        try:
            # Делаем запрос
            if attempt > 0:
                logger.warning(f"Retry attempt {attempt + 1}/{max_retries} after first token timeout")
            
            response = await make_request()
            
            if response.status_code != 200:
                # Ошибка от API - закрываем response и выбрасываем исключение
                try:
                    error_content = await response.aread()
                    error_text = error_content.decode('utf-8', errors='replace')
                except Exception:
                    error_text = "Unknown error"
                
                try:
                    await response.aclose()
                except Exception:
                    pass
                
                logger.error(f"Error from Kiro API: {response.status_code} - {error_text}")
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Upstream API error: {error_text}"
                )
            
            # Пытаемся стримить с таймаутом на первый токен
            async for chunk in stream_kiro_to_openai_internal(
                client,
                response,
                model,
                model_cache,
                auth_manager,
                first_token_timeout=first_token_timeout
            ):
                yield chunk
            
            # Успешно завершили - выходим
            return
            
        except FirstTokenTimeoutError as e:
            last_error = e
            logger.warning(f"First token timeout on attempt {attempt + 1}/{max_retries}")
            
            # Закрываем текущий response если он открыт
            if response:
                try:
                    await response.aclose()
                except Exception:
                    pass
            
            # Продолжаем к следующей попытке
            continue
            
        except Exception as e:
            # Другие ошибки - не retry, пробрасываем
            logger.error(f"Unexpected error during streaming: {e}", exc_info=True)
            if response:
                try:
                    await response.aclose()
                except Exception:
                    pass
            raise
    
    # Все попытки исчерпаны - выбрасываем HTTP ошибку
    logger.error(f"All {max_retries} attempts failed due to first token timeout")
    raise HTTPException(
        status_code=504,
        detail=f"Model did not respond within {first_token_timeout}s after {max_retries} attempts. Please try again."
    )


async def collect_stream_response(
    client: httpx.AsyncClient,
    response: httpx.Response,
    model: str,
    model_cache: "ModelInfoCache",
    auth_manager: "KiroAuthManager"
) -> dict:
    """
    Собирает полный ответ из streaming потока.
    
    Используется для non-streaming режима - собирает все chunks
    и формирует единый ответ.
    
    Args:
        client: HTTP клиент
        response: HTTP ответ с потоком
        model: Имя модели
        model_cache: Кэш моделей
        auth_manager: Менеджер аутентификации
    
    Returns:
        Словарь с полным ответом в формате OpenAI chat.completion
    """
    full_content = ""
    final_usage = None
    tool_calls = []
    completion_id = generate_completion_id()
    
    async for chunk_str in stream_kiro_to_openai(
        client,
        response,
        model,
        model_cache,
        auth_manager
    ):
        if not chunk_str.startswith("data:"):
            continue
        
        data_str = chunk_str[len("data:"):].strip()
        if not data_str or data_str == "[DONE]":
            continue
        
        try:
            chunk_data = json.loads(data_str)
            
            # Извлекаем данные из chunk
            delta = chunk_data.get("choices", [{}])[0].get("delta", {})
            if "content" in delta:
                full_content += delta["content"]
            if "tool_calls" in delta:
                tool_calls.extend(delta["tool_calls"])
            
            # Сохраняем usage из последнего chunk
            if "usage" in chunk_data:
                final_usage = chunk_data["usage"]
                
        except (json.JSONDecodeError, IndexError):
            continue
    
    # Формируем финальный ответ
    message = {"role": "assistant", "content": full_content}
    if tool_calls:
        # Для non-streaming ответа удаляем поле index из tool_calls,
        # так как оно требуется только для streaming chunks
        cleaned_tool_calls = []
        for tc in tool_calls:
            # Извлекаем function с защитой от None
            func = tc.get("function") or {}
            cleaned_tc = {
                "id": tc.get("id"),
                "type": tc.get("type", "function"),
                "function": {
                    "name": func.get("name", ""),
                    "arguments": func.get("arguments", "{}")
                }
            }
            cleaned_tool_calls.append(cleaned_tc)
        message["tool_calls"] = cleaned_tool_calls
    
    finish_reason = "tool_calls" if tool_calls else "stop"
    
    # Формируем usage для ответа
    usage = final_usage or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    
    # Логируем информацию о токенах для отладки (non-streaming использует те же логи из streaming)
    
    return {
        "id": completion_id,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": finish_reason
        }],
        "usage": usage
    }