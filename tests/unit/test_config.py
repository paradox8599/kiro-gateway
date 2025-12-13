# -*- coding: utf-8 -*-

"""
Unit-тесты для модуля конфигурации.
Проверяет загрузку настроек из переменных окружения.
"""

import pytest
import os
from unittest.mock import patch


class TestLogLevelConfig:
    """Тесты для настройки LOG_LEVEL."""
    
    def test_default_log_level_is_info(self):
        """
        Что он делает: Проверяет, что LOG_LEVEL по умолчанию равен INFO.
        Цель: Убедиться, что без переменной окружения используется INFO.
        """
        print("Настройка: Удаляем LOG_LEVEL из окружения...")
        
        with patch.dict(os.environ, {}, clear=False):
            # Удаляем LOG_LEVEL если есть
            if "LOG_LEVEL" in os.environ:
                del os.environ["LOG_LEVEL"]
            
            # Перезагружаем модуль config
            import importlib
            import kiro_gateway.config as config_module
            importlib.reload(config_module)
            
            print(f"LOG_LEVEL: {config_module.LOG_LEVEL}")
            print(f"Сравниваем: Ожидалось 'INFO', Получено '{config_module.LOG_LEVEL}'")
            assert config_module.LOG_LEVEL == "INFO"
    
    def test_log_level_from_environment(self):
        """
        Что он делает: Проверяет загрузку LOG_LEVEL из переменной окружения.
        Цель: Убедиться, что значение из окружения используется.
        """
        print("Настройка: Устанавливаем LOG_LEVEL=DEBUG...")
        
        with patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"}):
            import importlib
            import kiro_gateway.config as config_module
            importlib.reload(config_module)
            
            print(f"LOG_LEVEL: {config_module.LOG_LEVEL}")
            print(f"Сравниваем: Ожидалось 'DEBUG', Получено '{config_module.LOG_LEVEL}'")
            assert config_module.LOG_LEVEL == "DEBUG"
    
    def test_log_level_uppercase_conversion(self):
        """
        Что он делает: Проверяет преобразование LOG_LEVEL в верхний регистр.
        Цель: Убедиться, что lowercase значение преобразуется в uppercase.
        """
        print("Настройка: Устанавливаем LOG_LEVEL=warning (lowercase)...")
        
        with patch.dict(os.environ, {"LOG_LEVEL": "warning"}):
            import importlib
            import kiro_gateway.config as config_module
            importlib.reload(config_module)
            
            print(f"LOG_LEVEL: {config_module.LOG_LEVEL}")
            print(f"Сравниваем: Ожидалось 'WARNING', Получено '{config_module.LOG_LEVEL}'")
            assert config_module.LOG_LEVEL == "WARNING"
    
    def test_log_level_trace(self):
        """
        Что он делает: Проверяет установку LOG_LEVEL=TRACE.
        Цель: Убедиться, что TRACE уровень поддерживается.
        """
        print("Настройка: Устанавливаем LOG_LEVEL=TRACE...")
        
        with patch.dict(os.environ, {"LOG_LEVEL": "TRACE"}):
            import importlib
            import kiro_gateway.config as config_module
            importlib.reload(config_module)
            
            print(f"LOG_LEVEL: {config_module.LOG_LEVEL}")
            assert config_module.LOG_LEVEL == "TRACE"
    
    def test_log_level_error(self):
        """
        Что он делает: Проверяет установку LOG_LEVEL=ERROR.
        Цель: Убедиться, что ERROR уровень поддерживается.
        """
        print("Настройка: Устанавливаем LOG_LEVEL=ERROR...")
        
        with patch.dict(os.environ, {"LOG_LEVEL": "ERROR"}):
            import importlib
            import kiro_gateway.config as config_module
            importlib.reload(config_module)
            
            print(f"LOG_LEVEL: {config_module.LOG_LEVEL}")
            assert config_module.LOG_LEVEL == "ERROR"
    
    def test_log_level_critical(self):
        """
        Что он делает: Проверяет установку LOG_LEVEL=CRITICAL.
        Цель: Убедиться, что CRITICAL уровень поддерживается.
        """
        print("Настройка: Устанавливаем LOG_LEVEL=CRITICAL...")
        
        with patch.dict(os.environ, {"LOG_LEVEL": "CRITICAL"}):
            import importlib
            import kiro_gateway.config as config_module
            importlib.reload(config_module)
            
            print(f"LOG_LEVEL: {config_module.LOG_LEVEL}")
            assert config_module.LOG_LEVEL == "CRITICAL"


class TestToolDescriptionMaxLengthConfig:
    """Тесты для настройки TOOL_DESCRIPTION_MAX_LENGTH."""
    
    def test_default_tool_description_max_length(self):
        """
        Что он делает: Проверяет значение по умолчанию для TOOL_DESCRIPTION_MAX_LENGTH.
        Цель: Убедиться, что по умолчанию используется 10000.
        """
        print("Настройка: Удаляем TOOL_DESCRIPTION_MAX_LENGTH из окружения...")
        
        with patch.dict(os.environ, {}, clear=False):
            if "TOOL_DESCRIPTION_MAX_LENGTH" in os.environ:
                del os.environ["TOOL_DESCRIPTION_MAX_LENGTH"]
            
            import importlib
            import kiro_gateway.config as config_module
            importlib.reload(config_module)
            
            print(f"TOOL_DESCRIPTION_MAX_LENGTH: {config_module.TOOL_DESCRIPTION_MAX_LENGTH}")
            assert config_module.TOOL_DESCRIPTION_MAX_LENGTH == 10000
    
    def test_tool_description_max_length_from_environment(self):
        """
        Что он делает: Проверяет загрузку TOOL_DESCRIPTION_MAX_LENGTH из окружения.
        Цель: Убедиться, что значение из окружения используется.
        """
        print("Настройка: Устанавливаем TOOL_DESCRIPTION_MAX_LENGTH=5000...")
        
        with patch.dict(os.environ, {"TOOL_DESCRIPTION_MAX_LENGTH": "5000"}):
            import importlib
            import kiro_gateway.config as config_module
            importlib.reload(config_module)
            
            print(f"TOOL_DESCRIPTION_MAX_LENGTH: {config_module.TOOL_DESCRIPTION_MAX_LENGTH}")
            assert config_module.TOOL_DESCRIPTION_MAX_LENGTH == 5000
    
    def test_tool_description_max_length_zero_disables(self):
        """
        Что он делает: Проверяет, что 0 отключает функцию.
        Цель: Убедиться, что TOOL_DESCRIPTION_MAX_LENGTH=0 работает.
        """
        print("Настройка: Устанавливаем TOOL_DESCRIPTION_MAX_LENGTH=0...")
        
        with patch.dict(os.environ, {"TOOL_DESCRIPTION_MAX_LENGTH": "0"}):
            import importlib
            import kiro_gateway.config as config_module
            importlib.reload(config_module)
            
            print(f"TOOL_DESCRIPTION_MAX_LENGTH: {config_module.TOOL_DESCRIPTION_MAX_LENGTH}")
            assert config_module.TOOL_DESCRIPTION_MAX_LENGTH == 0