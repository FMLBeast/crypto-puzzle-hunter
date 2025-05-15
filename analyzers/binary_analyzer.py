"""
Binary analyzer for Crypto Hunter.
Analyzes binary data to identify file types, hidden data, and potential steganography.
"""

import os
import re
import string
import binascii
import struct
from collections import Counter
from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

# File signatures for common file types
FILE_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF87a": "GIF image (87a)",
    b"GIF89a": "GIF image (89a)",
    b"BM": "BMP image",
    b"\x25\x50\x44\x46": "PDF document",
    b"\x50\x4B\x03\x04": "ZIP archive",
    b"\x52\x61\x72\x21\x1A\x07": "RAR archive",
    b"\x1F\x8B\x08": "GZIP archive",
    b"\x49\x44\x33": "MP3 audio (with ID3)",
    b"\xFF\xFB": "MP3 audio",
    b"\x4F\x67\x67\x53": "OGG audio/video",
    b"\x00\x00\x00\x20\x66\x74\x79\x70": "MP4 video/audio",
    b"\x4D\x5A": "Executable file",
    b"\x7F\x45\x4C\x46": "ELF executable",
    b"\xCA\xFE\xBA\xBE": "Java class file",
    b"\x4D\x5A\x90\x00": "Windows executable",
    b"PK": "ZIP-based file format",
    b"\x1F\x8B": "GZIP compressed file",
    b"\x25\x21\x50\x53": "PostScript document",
    b"\x7B\x5C\x72\x74\x66": "RTF document",
    b"\x50\x4B\x05\x06": "PKZIP archive",
    b"\x75\x73\x74\x61\x72": "TAR archive",
    b"\x00\x01\x00\x00\x00": "TrueType font",
    b"\x52\x49\x46\x46": "RIFF container (AVI, WAV)",
    b"\x4F\x54\x54\x4F": "OpenType font",
    b"\x28\xB5\x2F\xFD": "Zstandard compressed data",
    b"\x46\x4C\x56\x01": "Flash video",
    b"\x00\x00\x01\xBA": "MPEG transport stream",
    b"\x42\x5A\x68": "BZip2 compressed file",
    b"\x44\x49\x43\x4D": "DICOM medical image",
    b"\x1A\x45\xDF\xA3": "Matroska multimedia container",
    b"\x78\x01": "ZLIB compressed data (low compression)",
    b"\x78\x9C": "ZLIB compressed data (default compression)",
    b"\x78\xDA": "ZLIB compressed data (best compression)",
    b"\x4E\x45\x53\x1A": "Nintendo Entertainment System ROM",
    b"\x42\x4F\x4F\x4B\x4D\x4F\x42\x49": "MOBI ebook",
    b"\x51\x46\x49": "QEMU copy-on-write disk image"
}

@register_analyzer("binary_analyzer")
@analyzer_compatibility(requires_binary=True)
def analyze_binary(state: State) -> State:
    """
    Analyze binary data for file signatures, hidden data, and other patterns.
    
    Args:
        state: Current puzzle state
        
    Returns:
        Updated state
    """
    if not state.binary_data:
        return state
    
    data = state.binary_data
    
    # Add insight about starting analysis
    state.add_insight(
        f"Starting binary analysis of {len(data)} bytes",
        analyzer="binary_analyzer"
    )
    
    # Identify file type
    identify_file_type(state, data)
    
    # Check for embedded files
    check_for_embedded_files(state, data)
    
    # Analyze entropy
    analyze_entropy(state, data)
    
    # Check for hidden text
    check_for_hidden_text(state, data)
    
    # Look for unusual patterns
    check_for_unusual_patterns(state, data)
    
    # Check related files if any
    if state.related_files:
        state.add_insight(
            f"Checking {len(state.related_files)} related files for binary patterns",
            analyzer="binary_analyzer"
        )
        
        for filename, file_info in state.related_files.items():
            binary_content = file_info["content"]
            state.add_insight(
                f"Analyzing related binary file {filename} ({len(binary_content)} bytes)",
                analyzer="binary_analyzer"
            )
            
            # Identify file type of the related file
            file_type = identify_file_type_from_data(binary_content)
            if file_type:
                state.add_insight(
                    f"Related file {filename} appears to be a {file_type}",
                    analyzer="binary_analyzer"
                )
    
    return state

def identify_file_type(state: State, data: bytes) -> None:
    """
    Identify the file type based on signatures.
    
    Args:
        state: Current puzzle state
        data: Binary data to analyze
    """
    file_type = identify_file_type_from_data(data)
    
    if file_type:
        state.add_insight(
            f"File appears to be a {file_type}",
            analyzer="binary_analyzer"
        )
    else:
        state.add_insight(
            "No recognized file signature detected",
            analyzer="binary_analyzer"
        )
        
        # Check if it could be text
        printable_ratio = sum(1 for b in data if chr(b).isprintable()) / len(data) if data else 0
        if printable_ratio > 0.8:
            state.add_insight(
                "Binary data has high ratio of printable characters, may contain text",
                analyzer="binary_analyzer"
            )
            
            # Add transformation to show the text
            try:
                text = data.decode('utf-8', errors='replace')
                state.add_transformation(
                    name="Binary as Text",
                    description="Binary data interpreted as UTF-8 text",
                    input_data=data[:100].hex(),
                    output_data=text[:1000] + "..." if len(text) > 1000 else text,
                    analyzer="binary_analyzer"
                )
            except Exception as e:
                state.add_insight(
                    f"Error decoding binary as text: {e}",
                    analyzer="binary_analyzer"
                )

def identify_file_type_from_data(data: bytes) -> str:
    """
    Identify file type from binary data.
    
    Args:
        data: Binary data to analyze
        
    Returns:
        String describing the identified file type, or None if not identified
    """
    for signature, file_type in FILE_SIGNATURES.items():
        if data.startswith(signature):
            return file_type
    return None

def check_for_embedded_files(state: State, data: bytes) -> None:
    """
    Check for embedded files within the binary data.
    
    Args:
        state: Current puzzle state
        data: Binary data to analyze
    """
    # Scan for file signatures within the data (not just at the beginning)
    embedded_files = []
    
    for signature, file_type in FILE_SIGNATURES.items():
        positions = []
        start_pos = 0
        
        while True:
            pos = data.find(signature, start_pos)
            if pos == -1:
                break
            positions.append(pos)
            start_pos = pos + 1
        
        if positions:
            embedded_files.append((file_type, positions))
    
    if embedded_files:
        # Filter out the signature at the beginning
        embedded_files = [(ftype, pos) for ftype, positions in embedded_files 
                         for pos in positions if pos > 0]
        
        if embedded_files:
            state.add_insight(
                f"Found {len(embedded_files)} potential embedded files or signatures",
                analyzer="binary_analyzer"
            )
            
            for file_type, position in embedded_files[:5]:  # Limit to first 5
                state.add_insight(
                    f"Potential {file_type} at offset {position} (0x{position:X})",
                    analyzer="binary_analyzer"
                )

def analyze_entropy(state: State, data: bytes) -> None:
    """
    Analyze the entropy of the binary data.
    
    Args:
        state: Current puzzle state
        data: Binary data to analyze
    """
    import math
    
    # Count byte frequencies
    byte_counts = Counter(data)
    total_bytes = len(data)
    
    # Calculate Shannon entropy
    entropy = 0
    for byte_val, count in byte_counts.items():
        prob = count / total_bytes
        entropy -= prob * math.log2(prob)
    
    # Interpret entropy level
    max_entropy = 8  # Maximum entropy for a byte (8 bits)
    entropy_ratio = entropy / max_entropy
    
    state.add_insight(
        f"Binary entropy: {entropy:.2f} bits ({entropy_ratio:.1%} of maximum)",
        analyzer="binary_analyzer"
    )
    
    if entropy_ratio > 0.9:
        state.add_insight(
            "Very high entropy suggests encryption, compression, or random data",
            analyzer="binary_analyzer"
        )
    elif entropy_ratio > 0.7:
        state.add_insight(
            "High entropy is typical of compressed, encrypted, or multimedia files",
            analyzer="binary_analyzer"
        )
    elif entropy_ratio < 0.5:
        state.add_insight(
            "Low entropy suggests repetitive patterns or sparse data",
            analyzer="binary_analyzer"
        )
    
    # Analyze entropy distribution across the file
    if len(data) > 1000:
        # Analyze entropy in 1KB chunks
        chunk_size = 1024
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        
        chunk_entropies = []
        for i, chunk in enumerate(chunks):
            # Skip empty chunks
            if not chunk:
                continue
            
            # Calculate entropy for this chunk
            chunk_byte_counts = Counter(chunk)
            chunk_entropy = 0
            for byte_val, count in chunk_byte_counts.items():
                prob = count / len(chunk)
                chunk_entropy -= prob * math.log2(prob)
            
            chunk_entropies.append((i, chunk_entropy))
        
        # Look for unusual entropy changes
        significant_changes = []
        for i in range(1, len(chunk_entropies)):
            prev_entropy = chunk_entropies[i-1][1]
            curr_entropy = chunk_entropies[i][1]
            change = abs(curr_entropy - prev_entropy)
            
            if change > 2.0:  # Significant entropy change
                significant_changes.append((chunk_entropies[i][0], change))
        
        if significant_changes:
            first_change = significant_changes[0]
            state.add_insight(
                f"Significant entropy change at offset {first_change[0] * chunk_size} (0x{first_change[0] * chunk_size:X})",
                analyzer="binary_analyzer"
            )
            
            # Add transformation to show entropy distribution
            output = "Chunk Offset, Entropy\n"
            for chunk_idx, entropy in chunk_entropies:
                output += f"{chunk_idx * chunk_size} (0x{chunk_idx * chunk_size:X}), {entropy:.2f}\n"
            
            state.add_transformation(
                name="Entropy Distribution",
                description="Distribution of entropy across the file in 1KB chunks",
                input_data=f"Binary data ({len(data)} bytes)",
                output_data=output[:1000] + "..." if len(output) > 1000 else output,
                analyzer="binary_analyzer"
            )

def check_for_hidden_text(state: State, data: bytes) -> None:
    """
    Check for hidden text within the binary data.
    
    Args:
        state: Current puzzle state
        data: Binary data to analyze
    """
    # Look for ASCII strings
    ascii_strings = find_strings(data, min_length=4)
    
    if ascii_strings:
        state.add_insight(
            f"Found {len(ascii_strings)} ASCII strings in the binary data",
            analyzer="binary_analyzer"
        )
        
        # Add the first few strings as insights
        for string, offset in ascii_strings[:5]:
            if any(c.isalnum() for c in string):  # Only show strings with alphanumeric chars
                state.add_insight(
                    f"ASCII string at offset {offset} (0x{offset:X}): {string}",
                    analyzer="binary_analyzer"
                )
        
        # Add a transformation with all strings
        output = "Offset, String\n"
        for string, offset in ascii_strings:
            output += f"{offset} (0x{offset:X}), {string}\n"
        
        state.add_transformation(
            name="ASCII Strings",
            description="ASCII strings extracted from binary data",
            input_data=f"Binary data ({len(data)} bytes)",
            output_data=output[:1000] + "..." if len(output) > 1000 else output,
            analyzer="binary_analyzer"
        )
    
    # Look for Unicode strings (UTF-16)
    try:
        # Check for UTF-16 BOM
        if (len(data) >= 2 and data[:2] in (b'\xff\xfe', b'\xfe\xff')) or \
           (b'\x00' in data and b'\x00\x00\x00' not in data):
            
            # Try different UTF-16 variants
            for encoding in ('utf-16', 'utf-16-le', 'utf-16-be'):
                try:
                    text = data.decode(encoding, errors='ignore')
                    # Filter out strings with too many control characters
                    printable_ratio = sum(1 for c in text if c.isprintable()) / len(text) if text else 0
                    if printable_ratio > 0.7:
                        state.add_insight(
                            f"Data may contain text encoded in {encoding.upper()}",
                            analyzer="binary_analyzer"
                        )
                        
                        # Add transformation for the UTF-16 text
                        state.add_transformation(
                            name=f"{encoding.upper()} Text",
                            description=f"Binary data interpreted as {encoding.upper()} text",
                            input_data=data[:100].hex(),
                            output_data=text[:1000] + "..." if len(text) > 1000 else text,
                            analyzer="binary_analyzer"
                        )
                        break
                except:
                    continue
    except Exception as e:
        # Ignore errors in UTF-16 detection
        pass

def check_for_unusual_patterns(state: State, data: bytes) -> None:
    """
    Check for unusual patterns in the binary data.
    
    Args:
        state: Current puzzle state
        data: Binary data to analyze
    """
    # Check for repeating patterns
    repeating = find_repeating_patterns(data)
    if repeating:
        state.add_insight(
            f"Found repeating pattern of length {len(repeating)} bytes",
            analyzer="binary_analyzer"
        )
        
        # Add transformation to show the pattern
        state.add_transformation(
            name="Repeating Pattern",
            description="Repeating byte pattern found in the data",
            input_data=f"Binary data ({len(data)} bytes)",
            output_data=repeating.hex(),
            analyzer="binary_analyzer"
        )
    
    # Check for XOR obfuscation
    xor_key = detect_xor(data)
    if xor_key is not None:
        state.add_insight(
            f"Data may be XOR encoded with byte 0x{xor_key:02X}",
            analyzer="binary_analyzer"
        )
        
        # Add transformation to show the first bytes of the XORed data
        xored_data = bytes([b ^ xor_key for b in data[:100]])
        
        # Try to decode as text
        try:
            xored_text = xored_data.decode('utf-8', errors='replace')
            state.add_transformation(
                name="XOR Decoded",
                description=f"First 100 bytes XORed with 0x{xor_key:02X}",
                input_data=data[:100].hex(),
                output_data=f"Hex: {xored_data.hex()}\nText: {xored_text}",
                analyzer="binary_analyzer"
            )
        except:
            state.add_transformation(
                name="XOR Decoded",
                description=f"First 100 bytes XORed with 0x{xor_key:02X}",
                input_data=data[:100].hex(),
                output_data=xored_data.hex(),
                analyzer="binary_analyzer"
            )
    
    # Check for bit shifting
    bit_shift = detect_bit_shift(data)
    if bit_shift is not None:
        dir_str = "right" if bit_shift > 0 else "left"
        abs_shift = abs(bit_shift)
        state.add_insight(
            f"Data may be bit-shifted {dir_str} by {abs_shift} bits",
            analyzer="binary_analyzer"
        )

def find_strings(data: bytes, min_length=4) -> list:
    """
    Find ASCII strings in binary data.
    
    Args:
        data: Binary data to search
        min_length: Minimum string length to consider
        
    Returns:
        List of tuples (string, offset)
    """
    result = []
    current_string = ""
    string_start = -1
    
    for i, byte in enumerate(data):
        if 32 <= byte <= 126:  # ASCII printable character
            if string_start == -1:
                string_start = i
            current_string += chr(byte)
        else:
            if string_start != -1 and len(current_string) >= min_length:
                result.append((current_string, string_start))
            current_string = ""
            string_start = -1
    
    # Check if we have a string at the end
    if string_start != -1 and len(current_string) >= min_length:
        result.append((current_string, string_start))
    
    return result

def find_repeating_patterns(data: bytes, min_length=3, max_length=64) -> bytes:
    """
    Find repeating byte patterns in the data.
    
    Args:
        data: Binary data to analyze
        min_length: Minimum pattern length to consider
        max_length: Maximum pattern length to consider
        
    Returns:
        The repeating pattern, or None if none found
    """
    if len(data) < min_length * 2:
        return None
    
    # Search for patterns of different lengths
    for pattern_len in range(min_length, min(max_length + 1, len(data) // 2 + 1)):
        for start in range(len(data) - pattern_len * 2 + 1):
            pattern = data[start:start+pattern_len]
            
            # Look for at least 3 repetitions
            repetitions = 1
            pos = start + pattern_len
            while pos + pattern_len <= len(data) and data[pos:pos+pattern_len] == pattern:
                repetitions += 1
                pos += pattern_len
            
            if repetitions >= 3:
                return pattern
    
    return None

def detect_xor(data: bytes) -> int:
    """
    Detect if data might be XOR encoded.
    
    Args:
        data: Binary data to analyze
        
    Returns:
        Potential XOR key, or None if not detected
    """
    if len(data) < 20:
        return None
    
    # Try each possible byte value
    best_key = None
    best_score = 0
    
    for key in range(1, 256):  # Skip 0 as it does nothing
        # XOR the first N bytes
        N = min(100, len(data))
        xored = bytes([b ^ key for b in data[:N]])
        
        # Count printable ASCII characters
        printable_count = sum(1 for b in xored if 32 <= b <= 126)
        score = printable_count / N
        
        if score > 0.7 and score > best_score:
            best_score = score
            best_key = key
    
    return best_key

def detect_bit_shift(data: bytes) -> int:
    """
    Detect if data might be bit-shifted.
    
    Args:
        data: Binary data to analyze
        
    Returns:
        Number of bits shifted (positive for right, negative for left),
        or None if not detected
    """
    if len(data) < 20:
        return None
    
    # Try different shifts
    sample = data[:min(100, len(data))]
    best_shift = None
    best_score = 0
    
    # Try right shifts
    for shift in range(1, 8):
        shifted = bytes([(b >> shift) | ((b << (8 - shift)) & 0xFF) for b in sample])
        
        # Count printable ASCII characters
        printable_count = sum(1 for b in shifted if 32 <= b <= 126)
        score = printable_count / len(shifted)
        
        if score > 0.7 and score > best_score:
            best_score = score
            best_shift = shift
    
    # Try left shifts
    for shift in range(1, 8):
        shifted = bytes([(b << shift) | (b >> (8 - shift)) for b in sample])
        
        # Count printable ASCII characters
        printable_count = sum(1 for b in shifted if 32 <= b <= 126)
        score = printable_count / len(shifted)
        
        if score > 0.7 and score > best_score:
            best_score = score
            best_shift = -shift
    
    return best_shift
