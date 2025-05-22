"""
Configuration settings for Crypto Hunter
"""
import os
from typing import Dict, List, Any
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# General settings
PROJECT_NAME = "Crypto Hunter"
VERSION = "1.0.0"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB max file size
CACHE_DIR = ".cache"
DEFAULT_RESULTS_DIR = "results"

# API keys (loaded from environment variables)
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

# LLM configuration
LLM_CONFIG = {
    "anthropic": {
        "model": "claude-3-5-sonnet-20240620",
        "temperature": 0.3,
        "max_tokens": 4000,
    },
    "openai": {
        "model": "gpt-4o-2024-05-13",
        "temperature": 0.3,
        "max_tokens": 4000,
    },
}

# Analyzer settings
ANALYZER_CONFIG = {
    "text_analyzer": {
        "enabled": True,
        "priority": 10,
        "max_text_length": 100000,
    },
    "binary_analyzer": {
        "enabled": True,
        "priority": 20,
        "max_file_size": 5 * 1024 * 1024,  # 5MB
    },
    "image_analyzer": {
        "enabled": True,
        "priority": 30,
        "supported_formats": ["png", "jpg", "jpeg", "gif", "bmp"],
    },
    "blockchain_analyzer": {
        "enabled": True,
        "priority": 40,
        "supported_chains": ["ethereum", "bitcoin"],
    },
    "cipher_analyzer": {
        "enabled": True,
        "priority": 50,
        "supported_ciphers": [
            "caesar",
            "vigenere",
            "substitution",
            "transposition",
            "xor",
            "aes",
            "rsa",
        ],
    },
    "encoding_analyzer": {
        "enabled": True,
        "priority": 60,
        "supported_encodings": [
            "base64",
            "base32",
            "hex",
            "ascii85",
            "url",
            "rot13",
        ],
    },
}

# Logging configuration
LOGGING_CONFIG = {
    "version": 1,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "standard",
            "stream": "ext://sys.stdout",
        },
        "file": {
            "class": "logging.FileHandler",
            "level": "DEBUG",
            "formatter": "standard",
            "filename": "crypto_hunter.log",
            "mode": "a",
        },
    },
    "loggers": {
        "": {  # root logger
            "handlers": ["console", "file"],
            "level": "INFO",
        },
        "crypto_hunter": {
            "handlers": ["console", "file"],
            "level": "DEBUG",
            "propagate": False,
        },
    },
}

# Interactive mode settings
INTERACTIVE_CONFIG = {
    "prompt": "crypto-hunter> ",
    "intro_text": f"""
Welcome to {PROJECT_NAME} v{VERSION} Interactive Mode!
Type 'help' for a list of commands, or 'exit' to quit.
    """,
    "history_file": ".crypto_hunter_history",
}

# Dictionary of known file signatures for binary analyzer
FILE_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "PNG": {
        "hex_signature": "89504E470D0A1A0A",
        "offset": 0,
        "description": "PNG image",
    },
    "JPEG": {
        "hex_signature": "FFD8FF",
        "offset": 0,
        "description": "JPEG image",
    },
    "GIF": {
        "hex_signature": "474946383961",
        "offset": 0,
        "description": "GIF image (GIF89a)",
    },
    "ZIP": {
        "hex_signature": "504B0304",
        "offset": 0,
        "description": "ZIP archive",
    },
    "PDF": {
        "hex_signature": "25504446",
        "offset": 0,
        "description": "PDF document",
    },
    "ELF": {
        "hex_signature": "7F454C46",
        "offset": 0,
        "description": "ELF executable",
    },
    "PE": {
        "hex_signature": "4D5A",
        "offset": 0,
        "description": "Windows PE executable",
    },
}

# Regular expressions for detecting patterns in text
PATTERN_REGEXES = {
    "ethereum_address": r"0x[a-fA-F0-9]{40}",
    "bitcoin_address": r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
    "ipfs_hash": r"Qm[1-9A-HJ-NP-Za-km-z]{44}",
    "url": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
    "base64": r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    "hex_string": r"^[0-9a-fA-F]+$",
}

# Mapping of common cryptographic tools and algorithms
CRYPTO_TOOLS = {
    "common_ciphers": [
        "Caesar",
        "Vigenère",
        "Substitution",
        "Transposition",
        "XOR",
        "AES",
        "RSA",
        "Atbash",
        "Railfence",
        "Playfair",
    ],
    "encodings": [
        "Base64",
        "Base32",
        "Hex",
        "ASCII85",
        "URL",
        "ROT13",
        "Binary",
    ],
    "steganography_tools": [
        "LSB Steganography",
        "DCT Steganography",
        "Echo Hiding",
        "Metadata",
        "Whitespace",
    ],
    "hash_functions": [
        "MD5",
        "SHA-1",
        "SHA-256",
        "SHA-512",
        "RIPEMD-160",
        "Keccak-256",
    ],
}

# Dictionary of common crypto challenge patterns to detect
CHALLENGE_PATTERNS = {
    "ctf_flags": [
        r"flag{.*}",
        r"FLAG{.*}",
        r"ctf{.*}",
        r"CTF{.*}",
    ],
    "encoded_keywords": [
        "secret",
        "password",
        "key",
        "flag",
        "hidden",
        "decrypt",
        "solve",
    ],
}
