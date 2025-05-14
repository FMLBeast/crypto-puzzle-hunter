"""
Binary analyzer module for Crypto Hunter

This module provides functions for analyzing binary files,
detecting file signatures, and extracting hidden data.
"""
import logging
import re
import binascii
import struct
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Union
from io import BytesIO

from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility
import config

logger = logging.getLogger(__name__)


@register_analyzer("binary_analyze")
@analyzer_compatibility(requires_binary=True)
def analyze_binary(state: State) -> State:
    """
    Main binary analyzer function that orchestrates binary analysis.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_data:
        state.add_insight("No binary data available for analysis", analyzer="binary_analyzer")
        return state
    
    # Run various binary analysis functions
    state = detect_file_type(state)
    state = analyze_entropy(state)
    state = search_for_signatures(state)
    state = extract_strings(state)
    state = check_for_embedded_files(state)
    
    return state


@register_analyzer("detect_file_type")
@analyzer_compatibility(requires_binary=True)
def detect_file_type(state: State) -> State:
    """
    Detect the file type based on magic bytes or signatures.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_data:
        return state
    
    data = state.puzzle_data[:32]  # Get first 32 bytes for signature detection
    
    # Convert start of data to hex for comparison
    hex_signature = binascii.hexlify(data).decode('utf-8').upper()
    
    # Check against known file signatures
    for file_type, signature_info in config.FILE_SIGNATURES.items():
        hex_sig = signature_info["hex_signature"]
        offset = signature_info["offset"]
        
        if hex_signature[offset*2:].startswith(hex_sig):
            file_description = signature_info["description"]
            state.add_insight(
                f"Detected file type: {file_type} ({file_description})",
                analyzer="binary_analyzer"
            )
            
            # Update file type if not already set
            if not state.file_type or state.file_type == "bin":
                state.file_type = file_type.lower()
                
            return state
    
    # If not identified, look for other patterns
    # Check for PE file
    if data[0:2] == b'MZ':
        state.add_insight(
            "File appears to be a Windows executable (PE)",
            analyzer="binary_analyzer"
        )
        if not state.file_type or state.file_type == "bin":
            state.file_type = "exe"
    
    # Check for ELF file
    elif data[0:4] == b'\x7FELF':
        state.add_insight(
            "File appears to be an ELF executable",
            analyzer="binary_analyzer"
        )
        if not state.file_type or state.file_type == "bin":
            state.file_type = "elf"
    
    # Check for ZIP file
    elif data[0:4] == b'PK\x03\x04':
        state.add_insight(
            "File appears to be a ZIP archive",
            analyzer="binary_analyzer"
        )
        if not state.file_type or state.file_type == "bin":
            state.file_type = "zip"
    
    # Check for PDF file
    elif data[0:5] == b'%PDF-':
        state.add_insight(
            "File appears to be a PDF document",
            analyzer="binary_analyzer"
        )
        if not state.file_type or state.file_type == "bin":
            state.file_type = "pdf"
    
    # If still not identified
    if not state.file_type or state.file_type == "bin":
        state.add_insight(
            "Could not identify file type from signatures",
            analyzer="binary_analyzer"
        )
    
    return state


@register_analyzer("analyze_entropy")
@analyzer_compatibility(requires_binary=True)
def analyze_entropy(state: State) -> State:
    """
    Analyze the entropy of the binary data to detect encryption, compression, or hidden data.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_data:
        return state
    
    data = state.puzzle_data
    
    # Calculate entropy
    entropy = calculate_entropy(data)
    
    # Interpret entropy value
    if entropy > 7.5:
        state.add_insight(
            f"Very high entropy ({entropy:.2f}): Data is likely encrypted or compressed",
            analyzer="binary_analyzer",
            data={"entropy": entropy}
        )
    elif entropy > 6.5:
        state.add_insight(
            f"High entropy ({entropy:.2f}): Data may be compressed or contain encrypted sections",
            analyzer="binary_analyzer",
            data={"entropy": entropy}
        )
    elif entropy > 5.0:
        state.add_insight(
            f"Medium entropy ({entropy:.2f}): Data appears to be a mix of structured and random content",
            analyzer="binary_analyzer",
            data={"entropy": entropy}
        )
    else:
        state.add_insight(
            f"Low entropy ({entropy:.2f}): Data is likely structured or plain text",
            analyzer="binary_analyzer",
            data={"entropy": entropy}
        )
    
    # Perform sliding window entropy analysis to find hidden data
    if len(data) > 1000:
        anomalies = find_entropy_anomalies(data)
        if anomalies:
            state.add_insight(
                f"Detected {len(anomalies)} entropy anomalies that may indicate hidden data",
                analyzer="binary_analyzer",
                data={"anomalies": anomalies}
            )
            
            # Extract first anomaly if significant
            if anomalies and anomalies[0]["score"] > 2.0:
                start, end, _ = anomalies[0]["range"]
                anomaly_data = data[start:end]
                
                state.add_transformation(
                    name="extract_anomaly",
                    description=f"Extracted entropy anomaly at offset {start}-{end}",
                    input_data=data,
                    output_data=anomaly_data,
                    analyzer="binary_analyzer"
                )
    
    return state


@register_analyzer("search_for_signatures")
@analyzer_compatibility(requires_binary=True)
def search_for_signatures(state: State) -> State:
    """
    Search for known signatures and patterns in the binary data.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_data:
        return state
    
    data = state.puzzle_data
    
    # Search for common crypto-related patterns
    patterns = {
        "bitcoin_address": rb"(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34})",
        "ethereum_address": rb"0x[a-fA-F0-9]{40}",
        "private_key_hex": rb"[0-9a-fA-F]{64}",
        "base64_data": rb"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    }
    
    for name, pattern in patterns.items():
        matches = re.findall(pattern, data)
        if matches:
            # Limit to first 5 matches
            unique_matches = set(matches[:5])
            match_str = ", ".join([m.decode('utf-8', errors='replace') for m in unique_matches])
            state.add_insight(
                f"Found {name} pattern: {match_str}",
                analyzer="binary_analyzer",
                data={"matches": [m.decode('utf-8', errors='replace') for m in matches]}
            )
    
    # Look for hidden file signatures within the file
    offset = 0
    embedded_files = []
    
    while offset < len(data) - 4:
        # Check for common file signatures
        for file_type, signature_info in config.FILE_SIGNATURES.items():
            hex_sig = signature_info["hex_signature"]
            sig_bytes = bytes.fromhex(hex_sig)
            
            if data[offset:offset+len(sig_bytes)] == sig_bytes:
                embedded_files.append({
                    "type": file_type,
                    "offset": offset,
                    "description": signature_info["description"],
                })
                
                # Skip ahead to avoid duplicate matches
                offset += len(sig_bytes)
                break
        
        offset += 1
    
    # Add insights for embedded files
    if embedded_files:
        for embedded in embedded_files:
            state.add_insight(
                f"Detected embedded {embedded['description']} at offset {embedded['offset']}",
                analyzer="binary_analyzer",
                data=embedded
            )
            
            # Extract the first embedded file
            if embedded == embedded_files[0]:
                # Attempt to extract the file
                start_offset = embedded["offset"]
                end_offset = find_file_end(data, start_offset, embedded["type"])
                
                if end_offset > start_offset:
                    embedded_data = data[start_offset:end_offset]
                    state.add_transformation(
                        name="extract_embedded_file",
                        description=f"Extracted embedded {embedded['description']}",
                        input_data=data,
                        output_data=embedded_data,
                        analyzer="binary_analyzer"
                    )
                    
                    # Create a new state for the embedded file
                    embedded_state = State(
                        puzzle_data=embedded_data,
                        metadata={
                            "source": "embedded",
                            "parent_file": state.puzzle_file,
                            "offset": start_offset,
                        }
                    )
                    
                    # Add as a transformation
                    state.add_transformation(
                        name="create_embedded_state",
                        description="Created new state for embedded file",
                        input_data=data,
                        output_data=str(embedded_state.hash),
                        analyzer="binary_analyzer"
                    )
    
    return state


@register_analyzer("extract_strings")
@analyzer_compatibility(requires_binary=True)
def extract_strings(state: State) -> State:
    """
    Extract readable strings from binary data.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_data:
        return state
    
    data = state.puzzle_data
    
    # Extract ASCII strings
    ascii_strings = extract_ascii_strings(data, min_length=4)
    
    # Extract UTF-16 strings (common in Windows binaries)
    utf16_strings = extract_utf16_strings(data, min_length=4)
    
    # Combine and filter strings
    all_strings = ascii_strings + utf16_strings
    
    # Filter out common noise and duplicates
    filtered_strings = filter_strings(all_strings)
    
    if filtered_strings:
        # Limit to top 20 most interesting strings
        top_strings = filtered_strings[:20]
        
        # Join strings for display
        strings_text = "\n".join(top_strings)
        
        state.add_insight(
            f"Extracted {len(filtered_strings)} strings from binary data",
            analyzer="binary_analyzer",
            data={"string_count": len(filtered_strings)}
        )
        
        # Add transformation with extracted strings
        state.add_transformation(
            name="extract_strings",
            description="Extracted readable strings from binary data",
            input_data=data,
            output_data=strings_text,
            analyzer="binary_analyzer"
        )
        
        # Look for potential flags or secrets in strings
        for string in filtered_strings:
            lower_string = string.lower()
            if "flag" in lower_string or "key" in lower_string or "secret" in lower_string:
                state.add_insight(
                    f"Potential secret found: {string}",
                    analyzer="binary_analyzer"
                )
    
    return state


@register_analyzer("check_for_embedded_files")
@analyzer_compatibility(requires_binary=True)
def check_for_embedded_files(state: State) -> State:
    """
    Check for embedded files using more advanced techniques.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    if not state.puzzle_data:
        return state
    
    data = state.puzzle_data
    
    # Check for specific file formats
    
    # Check for ZIP data
    if b'PK\x03\x04' in data:
        state.add_insight(
            "Detected potential ZIP data",
            analyzer="binary_analyzer"
        )
        # Try to extract it
        try:
            import zipfile
            from io import BytesIO
            
            # Find all PK signatures
            zip_starts = [m.start() for m in re.finditer(b'PK\x03\x04', data)]
            
            for start in zip_starts:
                try:
                    # Try to open as ZIP
                    zip_data = data[start:]
                    zip_file = zipfile.ZipFile(BytesIO(zip_data))
                    
                    # List files in ZIP
                    file_list = zip_file.namelist()
                    
                    if file_list:
                        state.add_insight(
                            f"Successfully detected ZIP archive at offset {start} containing {len(file_list)} files",
                            analyzer="binary_analyzer",
                            data={"files": file_list}
                        )
                        
                        # Extract first file as example
                        first_file = file_list[0]
                        extracted = zip_file.read(first_file)
                        
                        state.add_transformation(
                            name="extract_zip_file",
                            description=f"Extracted '{first_file}' from embedded ZIP",
                            input_data=zip_data,
                            output_data=extracted,
                            analyzer="binary_analyzer"
                        )
                        
                        # Stop after first successful ZIP extraction
                        break
                
                except Exception as e:
                    logger.debug(f"Failed to extract ZIP at offset {start}: {e}")
        
        except ImportError:
            state.add_insight(
                "ZIP data detected but zipfile module not available",
                analyzer="binary_analyzer"
            )
    
    # Check for hidden data using offset analysis
    try:
        # Look for sections of data that don't match the file type
        mismatched_sections = find_mismatched_sections(data, state.file_type)
        
        if mismatched_sections:
            for section in mismatched_sections:
                state.add_insight(
                    f"Detected potential hidden data at offset {section['offset']} (size: {section['size']} bytes)",
                    analyzer="binary_analyzer"
                )
                
                # Extract the first mismatched section
                if section == mismatched_sections[0]:
                    section_data = data[section['offset']:section['offset'] + section['size']]
                    state.add_transformation(
                        name="extract_hidden_section",
                        description=f"Extracted potentially hidden data section",
                        input_data=data,
                        output_data=section_data,
                        analyzer="binary_analyzer"
                    )
    
    except Exception as e:
        logger.debug(f"Error in mismatched section analysis: {e}")
    
    return state


# Helper functions

def calculate_entropy(data: bytes) -> float:
    """
    Calculate the Shannon entropy of data.
    
    Args:
        data: Binary data
        
    Returns:
        Entropy value (0-8)
    """
    if not data:
        return 0
    
    # Count byte frequencies
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0
    for count in byte_counts.values():
        probability = count / len(data)
        entropy -= probability * (math.log(probability) / math.log(2))
    
    return entropy


def find_entropy_anomalies(data: bytes, window_size: int = 256, step: int = 64) -> List[Dict[str, Any]]:
    """
    Find entropy anomalies using sliding window analysis.
    
    Args:
        data: Binary data
        window_size: Size of each window
        step: Step size for sliding window
        
    Returns:
        List of anomalies with positions and scores
    """
    if len(data) < window_size * 2:
        return []
    
    # Calculate entropy for each window
    entropies = []
    for i in range(0, len(data) - window_size, step):
        window = data[i:i+window_size]
        entropies.append((i, calculate_entropy(window)))
    
    # Calculate mean and standard deviation
    mean_entropy = sum(e[1] for e in entropies) / len(entropies)
    std_dev = (sum((e[1] - mean_entropy) ** 2 for e in entropies) / len(entropies)) ** 0.5
    
    # Find anomalies (windows with entropy more than 2 std devs from mean)
    anomalies = []
    for i, entropy in entropies:
        z_score = abs(entropy - mean_entropy) / std_dev if std_dev > 0 else 0
        if z_score > 2.0:
            anomalies.append({
                "range": (i, i + window_size, entropy),
                "score": z_score,
                "entropy": entropy
            })
    
    # Merge overlapping anomalies
    merged_anomalies = []
    current = None
    
    for anomaly in sorted(anomalies, key=lambda x: x["range"][0]):
        if current is None:
            current = anomaly
        elif anomaly["range"][0] <= current["range"][1]:
            # Merge
            current["range"] = (
                current["range"][0],
                max(current["range"][1], anomaly["range"][1]),
                max(current["range"][2], anomaly["range"][2])
            )
            current["score"] = max(current["score"], anomaly["score"])
        else:
            merged_anomalies.append(current)
            current = anomaly
    
    if current:
        merged_anomalies.append(current)
    
    return merged_anomalies


def find_file_end(data: bytes, start_offset: int, file_type: str) -> int:
    """
    Attempt to find the end of an embedded file.
    
    Args:
        data: Binary data
        start_offset: Starting offset of the file
        file_type: Type of file to find end for
        
    Returns:
        End offset of the file
    """
    if file_type == "PNG":
        # PNG ends with IEND chunk
        iend_marker = b'IEND\xaeB`\x82'
        for i in range(start_offset, len(data) - 8):
            if data[i:i+8] == iend_marker:
                return i + 8
    
    elif file_type == "JPEG":
        # JPEG ends with EOI marker (0xFF 0xD9)
        for i in range(start_offset, len(data) - 2):
            if data[i:i+2] == b'\xFF\xD9':
                return i + 2
    
    elif file_type == "GIF":
        # GIF ends with file terminator (0x3B)
        for i in range(start_offset, len(data) - 1):
            if data[i] == 0x3B:
                return i + 1
    
    elif file_type == "PDF":
        # PDF ends with %%EOF marker
        eof_marker = b'%%EOF'
        for i in range(start_offset, len(data) - 5):
            if data[i:i+5] == eof_marker:
                return i + 5
    
    # For other types, use a reasonable fixed size
    return min(start_offset + 10000, len(data))


def extract_ascii_strings(data: bytes, min_length: int = 4) -> List[str]:
    """
    Extract ASCII strings from binary data.
    
    Args:
        data: Binary data
        min_length: Minimum string length
        
    Returns:
        List of extracted strings
    """
    # Define ASCII printable characters
    ascii_chars = set(bytes(range(32, 127)))
    
    strings = []
    current_string = []
    
    for byte in data:
        if byte in ascii_chars:
            current_string.append(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(bytes(current_string).decode('ascii'))
            current_string = []
    
    # Add the last string if it meets the minimum length
    if len(current_string) >= min_length:
        strings.append(bytes(current_string).decode('ascii'))
    
    return strings


def extract_utf16_strings(data: bytes, min_length: int = 4) -> List[str]:
    """
    Extract UTF-16 strings from binary data.
    
    Args:
        data: Binary data
        min_length: Minimum string length
        
    Returns:
        List of extracted strings
    """
    strings = []
    
    # Try both little and big endian
    for encoding in ['utf-16le', 'utf-16be']:
        offset = 0
        while offset < len(data) - 1:
            # Try to find start of a UTF-16 string
            try:
                end_offset = offset
                while end_offset < len(data) - 1:
                    # Check if this is a printable UTF-16 character
                    try:
                        char = data[end_offset:end_offset+2].decode(encoding)
                        if not char.isprintable() and not char.isspace():
                            break
                        end_offset += 2
                    except:
                        break
                
                if end_offset > offset:
                    str_len = (end_offset - offset) // 2
                    if str_len >= min_length:
                        string = data[offset:end_offset].decode(encoding)
                        strings.append(string)
                
                offset = end_offset + 2
            
            except:
                offset += 2
    
    return strings


def filter_strings(strings: List[str]) -> List[str]:
    """
    Filter and rank strings by interest level.
    
    Args:
        strings: List of strings to filter
        
    Returns:
        Filtered and ranked list of strings
    """
    if not strings:
        return []
    
    # Remove duplicates
    unique_strings = list(set(strings))
    
    # Filter out strings that are likely noise
    noise_patterns = [
        r'^[A-Z0-9]+$',           # All caps and numbers
        r'^[0-9]+$',              # All numbers
        r'^[a-zA-Z0-9]{1,3}$',    # Very short strings
    ]
    
    filtered = []
    for string in unique_strings:
        # Skip if matches a noise pattern
        if any(re.match(pattern, string) for pattern in noise_patterns):
            continue
        
        # Skip if too long
        if len(string) > 200:
            continue
        
        filtered.append(string)
    
    # Score strings by interest level
    def score_string(s):
        score = 0
        
        # Strings with special terms are more interesting
        special_terms = ['password', 'key', 'secret', 'flag', 'token', 'hash', 'api', 'http']
        for term in special_terms:
            if term in s.lower():
                score += 10
        
        # Strings with mixed case and special chars are more interesting
        if any(c.isupper() for c in s) and any(c.islower() for c in s):
            score += 3
        
        if any(c in s for c in '{}[]()=_-+*&^%$#@!'):
            score += 2
        
        # Strings with more alphanumeric characters are more interesting
        alpha_num_ratio = sum(c.isalnum() for c in s) / len(s)
        score += alpha_num_ratio * 5
        
        # Penalize very common strings
        common_strings = ['<?xml', '<html', '<!DOCTYPE', 'Microsoft', 'Windows']
        if any(cs in s for cs in common_strings):
            score -= 5
        
        return score
    
    # Sort by score (descending)
    return sorted(filtered, key=score_string, reverse=True)


def find_mismatched_sections(data: bytes, file_type: str) -> List[Dict[str, Any]]:
    """
    Find sections of data that don't match the expected file format.
    
    Args:
        data: Binary data
        file_type: Expected file type
        
    Returns:
        List of potentially hidden sections
    """
    if not file_type or file_type == "bin":
        return []
    
    mismatched_sections = []
    
    # Different analysis based on file type
    if file_type in ["png", "jpg", "jpeg", "gif"]:
        # For images, look for sections with high entropy
        window_size = 512
        stride = 256
        
        for i in range(0, len(data) - window_size, stride):
            window = data[i:i+window_size]
            entropy = calculate_entropy(window)
            
            # Image data typically has high entropy
            expected_entropy = 7.0 if file_type == "jpg" else 5.5
            
            # Look for windows with unexpectedly low entropy
            if abs(entropy - expected_entropy) > 1.5:
                mismatched_sections.append({
                    "offset": i,
                    "size": window_size,
                    "entropy": entropy,
                })
    
    elif file_type in ["pdf", "doc", "docx"]:
        # For documents, look for unexpected binary data
        window_size = 1024
        stride = 512
        
        for i in range(0, len(data) - window_size, stride):
            window = data[i:i+window_size]
            
            # Count null bytes
            null_ratio = window.count(0) / window_size
            
            # High concentration of nulls might indicate hidden data
            if null_ratio > 0.7:
                mismatched_sections.append({
                    "offset": i,
                    "size": window_size,
                    "null_ratio": null_ratio,
                })
    
    return mismatched_sections


# Import math at the top level
import math
