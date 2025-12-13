# -*- coding: utf-8 -*-

"""
Unit-тесты для streaming модуля.
Проверяет логику добавления index к tool_calls и защиту от None значений.
"""

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch

from kiro_gateway.streaming import (
    stream_kiro_to_openai,
    collect_stream_response
)


@pytest.fixture
def mock_model_cache():
    """Мок для ModelInfoCache."""
    cache = MagicMock()
    cache.get_max_input_tokens.return_value = 200000
    return cache


@pytest.fixture
def mock_auth_manager():
    """Мок для KiroAuthManager."""
    manager = MagicMock()
    return manager


@pytest.fixture
def mock_http_client():
    """Мок для httpx.AsyncClient."""
    client = AsyncMock()
    return client


class TestStreamingToolCallsIndex:
    """Тесты для добавления index к tool_calls в streaming ответах."""
    
    @pytest.mark.asyncio
    async def test_tool_calls_have_index_field(self, mock_http_client, mock_model_cache, mock_auth_manager):
        """
        Что он делает: Проверяет, что tool_calls в streaming ответе содержат поле index.
        Цель: Убедиться, что OpenAI API spec соблюдается для streaming tool calls.
        """
        print("Настройка: Мок tool calls без index...")
        tool_calls = [
            {
                "id": "call_123",
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "arguments": '{"location": "Moscow"}'
                }
            }
        ]
        
        print("Настройка: Мок парсера...")
        mock_parser = MagicMock()
        mock_parser.feed.return_value = []
        mock_parser.get_tool_calls.return_value = tool_calls
        
        print("Настройка: Мок response...")
        mock_response = AsyncMock()
        mock_response.status_code = 200
        
        async def mock_aiter_bytes():
            yield b'{"content":"test"}'
        
        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.aclose = AsyncMock()
        
        print("Действие: Сбор streaming chunks...")
        chunks = []
        
        with patch('kiro_gateway.streaming.AwsEventStreamParser', return_value=mock_parser):
            with patch('kiro_gateway.streaming.parse_bracket_tool_calls', return_value=[]):
                async for chunk in stream_kiro_to_openai(
                    mock_http_client, mock_response, "test-model", 
                    mock_model_cache, mock_auth_manager
                ):
                    chunks.append(chunk)
        
        print(f"Получено chunks: {len(chunks)}")
        
        # Ищем chunk с tool_calls
        tool_calls_found = False
        for chunk in chunks:
            if isinstance(chunk, str) and "tool_calls" in chunk:
                if chunk.startswith("data: "):
                    json_str = chunk[6:].strip()
                    if json_str != "[DONE]":
                        data = json.loads(json_str)
                        if "choices" in data and data["choices"]:
                            delta = data["choices"][0].get("delta", {})
                            if "tool_calls" in delta:
                                print(f"Tool calls в delta: {delta['tool_calls']}")
                                for tc in delta["tool_calls"]:
                                    print(f"Проверяем index в tool call: {tc}")
                                    assert "index" in tc, "Tool call должен содержать поле index"
                                    tool_calls_found = True
        
        assert tool_calls_found, "Tool calls chunk не найден"
    
    @pytest.mark.asyncio
    async def test_multiple_tool_calls_have_sequential_indices(self, mock_http_client, mock_model_cache, mock_auth_manager):
        """
        Что он делает: Проверяет, что несколько tool_calls имеют последовательные индексы.
        Цель: Убедиться, что индексы начинаются с 0 и идут последовательно.
        """
        print("Настройка: Несколько tool calls...")
        tool_calls = [
            {"id": "call_1", "type": "function", "function": {"name": "func1", "arguments": "{}"}},
            {"id": "call_2", "type": "function", "function": {"name": "func2", "arguments": "{}"}},
            {"id": "call_3", "type": "function", "function": {"name": "func3", "arguments": "{}"}}
        ]
        
        print("Настройка: Мок парсера...")
        mock_parser = MagicMock()
        mock_parser.feed.return_value = []
        mock_parser.get_tool_calls.return_value = tool_calls
        
        print("Настройка: Мок response...")
        mock_response = AsyncMock()
        mock_response.status_code = 200
        
        async def mock_aiter_bytes():
            yield b'{"content":"test"}'
        
        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.aclose = AsyncMock()
        
        print("Действие: Сбор streaming chunks...")
        chunks = []
        
        with patch('kiro_gateway.streaming.AwsEventStreamParser', return_value=mock_parser):
            with patch('kiro_gateway.streaming.parse_bracket_tool_calls', return_value=[]):
                async for chunk in stream_kiro_to_openai(
                    mock_http_client, mock_response, "test-model",
                    mock_model_cache, mock_auth_manager
                ):
                    chunks.append(chunk)
        
        # Ищем chunk с tool_calls
        for chunk in chunks:
            if isinstance(chunk, str) and "tool_calls" in chunk:
                if chunk.startswith("data: "):
                    json_str = chunk[6:].strip()
                    if json_str != "[DONE]":
                        data = json.loads(json_str)
                        if "choices" in data and data["choices"]:
                            delta = data["choices"][0].get("delta", {})
                            if "tool_calls" in delta:
                                indices = [tc["index"] for tc in delta["tool_calls"]]
                                print(f"Индексы: {indices}")
                                assert indices == [0, 1, 2], f"Индексы должны быть [0, 1, 2], получено {indices}"


class TestStreamingToolCallsNoneProtection:
    """Тесты для защиты от None значений в tool_calls."""
    
    @pytest.mark.asyncio
    async def test_handles_none_function_name(self, mock_http_client, mock_model_cache, mock_auth_manager):
        """
        Что он делает: Проверяет обработку None в function.name.
        Цель: Убедиться, что None заменяется на пустую строку.
        """
        print("Настройка: Tool call с None name...")
        tool_calls = [
            {
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": None,
                    "arguments": '{"a": 1}'
                }
            }
        ]
        
        mock_parser = MagicMock()
        mock_parser.feed.return_value = []
        mock_parser.get_tool_calls.return_value = tool_calls
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        
        async def mock_aiter_bytes():
            yield b'{"content":"test"}'
        
        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.aclose = AsyncMock()
        
        print("Действие: Сбор streaming chunks...")
        chunks = []
        
        with patch('kiro_gateway.streaming.AwsEventStreamParser', return_value=mock_parser):
            with patch('kiro_gateway.streaming.parse_bracket_tool_calls', return_value=[]):
                async for chunk in stream_kiro_to_openai(
                    mock_http_client, mock_response, "test-model",
                    mock_model_cache, mock_auth_manager
                ):
                    chunks.append(chunk)
        
        # Проверяем, что не было исключений и chunks собраны
        print(f"Получено chunks: {len(chunks)}")
        assert len(chunks) > 0
        
        # Проверяем, что name заменён на пустую строку
        for chunk in chunks:
            if isinstance(chunk, str) and "tool_calls" in chunk:
                if chunk.startswith("data: "):
                    json_str = chunk[6:].strip()
                    if json_str != "[DONE]":
                        data = json.loads(json_str)
                        if "choices" in data and data["choices"]:
                            delta = data["choices"][0].get("delta", {})
                            if "tool_calls" in delta:
                                for tc in delta["tool_calls"]:
                                    assert tc["function"]["name"] == "", "None name должен быть заменён на пустую строку"
    
    @pytest.mark.asyncio
    async def test_handles_none_function_arguments(self, mock_http_client, mock_model_cache, mock_auth_manager):
        """
        Что он делает: Проверяет обработку None в function.arguments.
        Цель: Убедиться, что None заменяется на "{}".
        """
        print("Настройка: Tool call с None arguments...")
        tool_calls = [
            {
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "test_func",
                    "arguments": None
                }
            }
        ]
        
        mock_parser = MagicMock()
        mock_parser.feed.return_value = []
        mock_parser.get_tool_calls.return_value = tool_calls
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        
        async def mock_aiter_bytes():
            yield b'{"content":"test"}'
        
        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.aclose = AsyncMock()
        
        print("Действие: Сбор streaming chunks...")
        chunks = []
        
        with patch('kiro_gateway.streaming.AwsEventStreamParser', return_value=mock_parser):
            with patch('kiro_gateway.streaming.parse_bracket_tool_calls', return_value=[]):
                async for chunk in stream_kiro_to_openai(
                    mock_http_client, mock_response, "test-model",
                    mock_model_cache, mock_auth_manager
                ):
                    chunks.append(chunk)
        
        print(f"Получено chunks: {len(chunks)}")
        assert len(chunks) > 0
        
        # Проверяем, что arguments заменён на "{}"
        for chunk in chunks:
            if isinstance(chunk, str) and "tool_calls" in chunk:
                if chunk.startswith("data: "):
                    json_str = chunk[6:].strip()
                    if json_str != "[DONE]":
                        data = json.loads(json_str)
                        if "choices" in data and data["choices"]:
                            delta = data["choices"][0].get("delta", {})
                            if "tool_calls" in delta:
                                for tc in delta["tool_calls"]:
                                    # None должен быть заменён на "{}" или пустую строку
                                    assert tc["function"]["arguments"] is not None
    
    @pytest.mark.asyncio
    async def test_handles_none_function_object(self, mock_http_client, mock_model_cache, mock_auth_manager):
        """
        Что он делает: Проверяет обработку None вместо function объекта.
        Цель: Убедиться, что None function обрабатывается без ошибок.
        """
        print("Настройка: Tool call с None function...")
        tool_calls = [
            {
                "id": "call_1",
                "type": "function",
                "function": None
            }
        ]
        
        mock_parser = MagicMock()
        mock_parser.feed.return_value = []
        mock_parser.get_tool_calls.return_value = tool_calls
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        
        async def mock_aiter_bytes():
            yield b'{"content":"test"}'
        
        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.aclose = AsyncMock()
        
        print("Действие: Сбор streaming chunks...")
        chunks = []
        
        with patch('kiro_gateway.streaming.AwsEventStreamParser', return_value=mock_parser):
            with patch('kiro_gateway.streaming.parse_bracket_tool_calls', return_value=[]):
                async for chunk in stream_kiro_to_openai(
                    mock_http_client, mock_response, "test-model",
                    mock_model_cache, mock_auth_manager
                ):
                    chunks.append(chunk)
        
        print(f"Получено chunks: {len(chunks)}")
        assert len(chunks) > 0


class TestCollectStreamResponseToolCalls:
    """Тесты для collect_stream_response с tool_calls."""
    
    @pytest.mark.asyncio
    async def test_collected_tool_calls_have_no_index(self, mock_http_client, mock_model_cache, mock_auth_manager):
        """
        Что он делает: Проверяет, что собранные tool_calls не содержат поле index.
        Цель: Убедиться, что для non-streaming ответа index удаляется.
        """
        print("Настройка: Tool calls...")
        tool_calls = [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "func1", "arguments": '{"a": 1}'}
            }
        ]
        
        mock_parser = MagicMock()
        mock_parser.feed.return_value = []
        mock_parser.get_tool_calls.return_value = tool_calls
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        
        async def mock_aiter_bytes():
            yield b'{"content":"Hello"}'
        
        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.aclose = AsyncMock()
        
        print("Действие: Сбор полного ответа...")
        
        with patch('kiro_gateway.streaming.AwsEventStreamParser', return_value=mock_parser):
            with patch('kiro_gateway.streaming.parse_bracket_tool_calls', return_value=[]):
                result = await collect_stream_response(
                    mock_http_client, mock_response, "test-model",
                    mock_model_cache, mock_auth_manager
                )
        
        print(f"Результат: {result}")
        
        if "choices" in result and result["choices"]:
            message = result["choices"][0].get("message", {})
            if "tool_calls" in message:
                for tc in message["tool_calls"]:
                    print(f"Tool call: {tc}")
                    assert "index" not in tc, "Non-streaming tool_calls не должны содержать index"
    
    @pytest.mark.asyncio
    async def test_collected_tool_calls_have_required_fields(self, mock_http_client, mock_model_cache, mock_auth_manager):
        """
        Что он делает: Проверяет, что собранные tool_calls содержат все обязательные поля.
        Цель: Убедиться, что id, type, function присутствуют.
        """
        print("Настройка: Tool calls...")
        tool_calls = [
            {
                "id": "call_abc",
                "type": "function",
                "function": {"name": "get_weather", "arguments": '{"city": "Moscow"}'}
            }
        ]
        
        mock_parser = MagicMock()
        mock_parser.feed.return_value = []
        mock_parser.get_tool_calls.return_value = tool_calls
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        
        async def mock_aiter_bytes():
            yield b'{"content":""}'
        
        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.aclose = AsyncMock()
        
        print("Действие: Сбор полного ответа...")
        
        with patch('kiro_gateway.streaming.AwsEventStreamParser', return_value=mock_parser):
            with patch('kiro_gateway.streaming.parse_bracket_tool_calls', return_value=[]):
                result = await collect_stream_response(
                    mock_http_client, mock_response, "test-model",
                    mock_model_cache, mock_auth_manager
                )
        
        print(f"Результат: {result}")
        
        if "choices" in result and result["choices"]:
            message = result["choices"][0].get("message", {})
            if "tool_calls" in message:
                for tc in message["tool_calls"]:
                    print(f"Проверяем tool call: {tc}")
                    assert "id" in tc, "Tool call должен содержать id"
                    assert "type" in tc, "Tool call должен содержать type"
                    assert "function" in tc, "Tool call должен содержать function"
                    assert "name" in tc["function"], "Function должен содержать name"
                    assert "arguments" in tc["function"], "Function должен содержать arguments"
    
    @pytest.mark.asyncio
    async def test_handles_none_in_collected_tool_calls(self, mock_http_client, mock_model_cache, mock_auth_manager):
        """
        Что он делает: Проверяет обработку None значений в собранных tool_calls.
        Цель: Убедиться, что None заменяются на дефолтные значения.
        """
        print("Настройка: Tool calls с None значениями...")
        tool_calls = [
            {
                "id": "call_1",
                "type": "function",
                "function": None
            }
        ]
        
        mock_parser = MagicMock()
        mock_parser.feed.return_value = []
        mock_parser.get_tool_calls.return_value = tool_calls
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        
        async def mock_aiter_bytes():
            yield b'{"content":""}'
        
        mock_response.aiter_bytes = mock_aiter_bytes
        mock_response.aclose = AsyncMock()
        
        print("Действие: Сбор полного ответа...")
        
        with patch('kiro_gateway.streaming.AwsEventStreamParser', return_value=mock_parser):
            with patch('kiro_gateway.streaming.parse_bracket_tool_calls', return_value=[]):
                result = await collect_stream_response(
                    mock_http_client, mock_response, "test-model",
                    mock_model_cache, mock_auth_manager
                )
        
        print(f"Результат: {result}")
        
        # Проверяем, что не было исключений
        assert "choices" in result