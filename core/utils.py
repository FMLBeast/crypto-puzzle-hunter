"""
Utilities module for Crypto Hunter

This module provides various utility functions used throughout the application.
"""
import os
import re
import logging
import hashlib
import binascii
from typing import Dict, List, Any, Optional, Tuple, Union, BinaryIO
from pathlib import Path

logger = logging.getLogger(__name__)


def file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Generate hash of a file.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use
        
    Returns:
        Hex digest of the hash
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    hash_obj = getattr(hashlib, algorithm)()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_obj.update(chunk)
    
    return hash_obj.hexdigest()


def bytes_to_hex(data: bytes) -> str:
    """
    Convert bytes to hex string.
    
    Args:
        data: Bytes to convert
        
    Returns:
        Hex string
    """
    return binascii.hexlify(data).decode('utf-8')


def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert hex string to bytes.
    
    Args:
        hex_str: Hex string to convert
        
    Returns:
        Bytes
    """
    # Remove any non-hex characters
    clean_hex = re.sub(r'[^0-9a-fA-F]', '', hex_str)
    
    # Ensure even length
    if len(clean_hex) % 2 != 0:
        clean_hex = '0' + clean_hex
    
    return binascii.unhexlify(clean_hex)


def is_text_file(file_path: str, threshold: float = 0.8) -> bool:
    """
    Check if a file is likely a text file.
    
    Args:
        file_path: Path to the file
        threshold: Minimum ratio of printable characters
        
    Returns:
        True if likely text, False otherwise
    """
    # Read first 1024 bytes
    with open(file_path, 'rb') as f:
        data = f.read(1024)
    
    if not data:
        return False
    
    # Count printable ASCII and common whitespace characters
    printable_count = sum(32 <= b <= 126 or b in (9, 10, 13) for b in data)
    
    # Calculate ratio
    ratio = printable_count / len(data)
    
    return ratio >= threshold


def read_file_safely(file_path: str, max_size: int = None) -> bytes:
    """
    Read a file with size checks.
    
    Args:
        file_path: Path to the file
        max_size: Maximum size to read (in bytes)
        
    Returns:
        File contents as bytes
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Check file size
    file_size = os.path.getsize(file_path)
    if max_size and file_size > max_size:
        logger.warning(
            f"File size ({file_size} bytes) exceeds maximum allowed size "
            f"({max_size} bytes). Reading first {max_size} bytes only."
        )
        
        with open(file_path, 'rb') as f:
            return f.read(max_size)
    else:
        with open(file_path, 'rb') as f:
            return f.read()


def get_file_extension(file_path: str) -> str:
    """
    Get the file extension.
    
    Args:
        file_path: Path to the file
        
    Returns:
        File extension (without the dot)
    """
    return os.path.splitext(file_path)[1].lstrip('.').lower()


def create_directory(directory: str) -> None:
    """
    Create directory if it doesn't exist.
    
    Args:
        directory: Directory path
    """
    os.makedirs(directory, exist_ok=True)


def list_files(directory: str, pattern: str = None) -> List[str]:
    """
    List files in a directory, optionally matching a pattern.
    
    Args:
        directory: Directory path
        pattern: Optional glob pattern
        
    Returns:
        List of file paths
    """
    if pattern:
        return [str(p) for p in Path(directory).glob(pattern)]
    else:
        return [str(p) for p in Path(directory).iterdir() if p.is_file()]


def bytes_to_printable(data: bytes, max_length: int = None) -> str:
    """
    Convert bytes to a printable string representation.
    
    Args:
        data: Bytes to convert
        max_length: Maximum length of output
        
    Returns:
        Printable string
    """
    if max_length and len(data) > max_length:
        data = data[:max_length] + b'... (truncated)'
    
    # Try to decode as UTF-8
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        # If that fails, use a hex representation
        return bytes_to_hex(data)


def detect_file_type(data: bytes) -> str:
    """
    Detect file type from binary data.
    
    Args:
        data: File data
        
    Returns:
        Detected file type or 'unknown'
    """
    if not data:
        return 'unknown'
    
    # Check for common file signatures
    signatures = {
        b'\x89PNG\r\n\x1a\n': 'png',
        b'\xff\xd8\xff': 'jpg',
        b'GIF8': 'gif',
        b'%PDF': 'pdf',
        b'PK\x03\x04': 'zip',
        b'7z\xbc\xaf\x27\x1c': '7z',
        b'\x1f\x8b': 'gz',
        b'BM': 'bmp',
        b'\x00\x01\x00\x00\x00': 'ttf',
        b'<!DOCTYPE html': 'html',
        b'<html': 'html',
        b'<?xml': 'xml',
    }
    
    # Check each signature
    for sig, file_type in signatures.items():
        if data.startswith(sig):
            return file_type
    
    # Check for text files
    text_chars = set(bytes(range(32, 127)) + b'\t\n\r')
    if all(b in text_chars for b in data[:1000]):
        # Check for specific text formats
        text = data[:1000].decode('utf-8', errors='ignore')
        
        if text.startswith('#!/bin/') or text.startswith('#!/usr/bin/'):
            return 'script'
        elif re.search(r'^\s*import\s+|^\s*from\s+\w+\s+import', text, re.MULTILINE):
            return 'python'
        elif re.search(r'^\s*function\s+\w+\s*\(|^\s*var\s+\w+\s*=|^\s*const\s+\w+\s*=', text, re.MULTILINE):
            return 'javascript'
        else:
            return 'txt'
    
    return 'unknown'


def split_binary_data(data: bytes, chunk_size: int = 16) -> List[str]:
    """
    Split binary data into formatted hex dump lines.
    
    Args:
        data: Binary data
        chunk_size: Number of bytes per line
        
    Returns:
        List of formatted hex dump lines
    """
    if not data:
        return []
    
    result = []
    
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        hex_values = ' '.join(f'{b:02x}' for b in chunk)
        ascii_values = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        
        result.append(f'{i:08x}  {hex_values:<{chunk_size*3}}  {ascii_values}')
    
    return result


def extract_strings_from_binary(data: bytes, min_length: int = 4) -> List[str]:
    """
    Extract ASCII strings from binary data.
    
    Args:
        data: Binary data
        min_length: Minimum string length
        
    Returns:
        List of strings
    """
    if not data:
        return []
    
    result = []
    current_string = b''
    
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string += bytes([byte])
        else:
            if len(current_string) >= min_length:
                result.append(current_string.decode('ascii'))
            current_string = b''
    
    # Add the last string if it meets the minimum length
    if len(current_string) >= min_length:
        result.append(current_string.decode('ascii'))
    
    return result


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of binary data.
    
    Args:
        data: Binary data
        
    Returns:
        Entropy value (0-8 bits)
    """
    if not data:
        return 0
    
    # Count byte frequencies
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    
    return entropy


# Import math at the top level
import math
