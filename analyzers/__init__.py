"""
Analyzers module for Crypto Hunter.
"""

import importlib
from typing import Dict, Callable

# Lazy import to avoid circular dependencies
_analyzer_modules = {
    'text_analyzer': 'analyzers.text_analyzer',
    'binary_analyzer': 'analyzers.binary_analyzer',
    'cipher_analyzer': 'analyzers.cipher_analyzer',
    'encoding_analyzer': 'analyzers.encoding_analyzer',
    'image_analyzer': 'analyzers.image_analyzer',
    'vision_analyzer': 'analyzers.vision_analyzer',
    'web_analyzer': 'analyzers.web_analyzer',
    'code_analyzer': 'analyzers.code_analyzer',
    'crypto_analyzer': 'analyzers.crypto_analyzer'
}

def _ensure_modules_loaded():
    """Ensure all analyzer modules are loaded"""
    for module_name in _analyzer_modules.values():
        try:
            importlib.import_module(module_name)
        except ImportError as e:
            print(f"Warning: Could not load {module_name}: {e}")

# Import base functionality
from analyzers.base import (
    register_analyzer,
    analyzer_compatibility,
    get_analyzer,
    get_all_analyzers,
    get_compatible_analyzers
)

# Ensure modules are loaded when this package is imported
_ensure_modules_loaded()