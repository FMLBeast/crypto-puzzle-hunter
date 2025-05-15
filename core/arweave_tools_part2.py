"""
Arweave Puzzle Series Tools Module - Part 2

This module provides specialized tools for solving puzzles in the Arweave Puzzle Series.
Each tool implements one of the orchestrated solution pointers described in the series pattern.
"""

import re
import math
import json
import base64
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Union

# ---- Puzzle Weave 2 Tools ----

def arweave_fetch(tx_id: str, gateway: str = "arweave.net") -> Dict[str, Any]:
    """
    Fetch transaction data from Arweave.
    
    Args:
        tx_id: Transaction ID
        gateway: Arweave gateway to use
    
    Returns:
        Dictionary with the transaction data
    """
    result = {}
    
    try:
        import requests
        
        # Fetch transaction data
        url = f"https://{gateway}/tx/{tx_id}"
        data_url = f"https://{gateway}/{tx_id}"
        
        # Get transaction metadata
        response = requests.get(url)
        if response.status_code == 200:
            result["metadata"] = response.json()
        
        # Get transaction data
        data_response = requests.get(data_url)
        if data_response.status_code == 200:
            result["data"] = data_response.content
            result["data_hex"] = data_response.content.hex()
            
            # Try to decode as text
            try:
                result["data_text"] = data_response.content.decode('utf-8')
            except:
                result["data_text"] = None
        
        result["success"] = True
        
    except Exception as e:
        result["success"] = False
        result["error"] = str(e)
    
    return result

def steganalysis(data: bytes, method: str = "auto") -> Dict[str, Any]:
    """
    Analyze files for steganographic content.
    
    Args:
        data: Binary data to analyze
        method: Steganography detection method
    
    Returns:
        Dictionary with the results
    """
    result = {}
    
    try:
        # Check file signature
        file_type = "unknown"
        if data[:2] == b'\xff\xd8':
            file_type = "jpeg"
        elif data[:8] == b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a':
            file_type = "png"
        elif data[:3] == b'GIF':
            file_type = "gif"
        elif data[:4] == b'%PDF':
            file_type = "pdf"
        elif data[:2] == b'PK':
            file_type = "zip"
        elif data[:4] == b'Rar!':
            file_type = "rar"
        
        result["file_type"] = file_type
        
        # Basic analysis
        result["file_size"] = len(data)
        result["entropy"] = calculate_entropy(data)
        result["has_high_entropy"] = result["entropy"] > 7.0
        
        # Method-specific analysis
        if method == "lsb" or method == "auto":
            # LSB analysis for images
            if file_type in ["jpeg", "png", "gif"]:
                lsb_data = extract_lsb(data, file_type)
                result["lsb_analysis"] = {
                    "extracted_bytes": lsb_data[:100].hex() if lsb_data else None,
                    "has_hidden_data": is_meaningful_data(lsb_data) if lsb_data else False
                }
        
        if method == "metadata" or method == "auto":
            # Metadata analysis
            metadata = extract_metadata(data, file_type)
            result["metadata_analysis"] = metadata
        
        if method == "strings" or method == "auto":
            # String extraction
            strings = extract_strings(data)
            result["strings_analysis"] = {
                "extracted_strings": strings[:10],  # First 10 strings
                "total_strings": len(strings)
            }
        
        result["success"] = True
        
    except Exception as e:
        result["success"] = False
        result["error"] = str(e)
    
    return result

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0
    
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    
    return entropy

def extract_lsb(data: bytes, file_type: str) -> Optional[bytes]:
    """Extract least significant bits from image data."""
    # This is a simplified implementation
    # A real implementation would parse the image format properly
    if file_type not in ["jpeg", "png", "gif"]:
        return None
    
    # Skip headers - this is very simplified
    if file_type == "png":
        offset = 100  # Skip PNG header
    elif file_type == "jpeg":
        offset = 100  # Skip JPEG header
    else:
        offset = 100  # Skip GIF header
    
    # Extract LSBs from a portion of the file
    lsb_data = bytearray()
    for i in range(offset, min(offset + 1000, len(data))):
        lsb_data.append(data[i] & 1)  # Extract LSB
    
    return bytes(lsb_data)

def is_meaningful_data(data: Optional[bytes]) -> bool:
    """Check if data appears to be meaningful rather than random."""
    if not data or len(data) < 10:
        return False
    
    # Check entropy - meaningful data often has lower entropy
    entropy = calculate_entropy(data)
    if entropy < 6.0:
        return True
    
    # Check for text patterns
    text_chars = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;:!?-_')
    text_char_count = sum(1 for b in data if b in text_chars)
    if text_char_count / len(data) > 0.7:
        return True
    
    return False

def extract_metadata(data: bytes, file_type: str) -> Dict[str, Any]:
    """Extract metadata from file."""
    metadata = {}
    
    # This is a simplified implementation
    # A real implementation would use proper libraries for each file type
    
    if file_type == "jpeg":
        # Look for EXIF marker
        exif_marker = b'\xff\xe1'
        if exif_marker in data:
            metadata["has_exif"] = True
    
    elif file_type == "png":
        # Look for tEXt chunks
        text_marker = b'tEXt'
        if text_marker in data:
            metadata["has_text_chunks"] = True
    
    return metadata

def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    """Extract printable strings from binary data."""
    strings = []
    current_string = ""
    
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""
    
    # Add the last string if it meets the minimum length
    if len(current_string) >= min_length:
        strings.append(current_string)
    
    return strings