"""
Encoding analyzer for Crypto Hunter.
Detects and decodes various encodings including Base64, Hex, ASCII85, Binary, URL, Morse, etc.
"""

import re
import base64
import binascii
import string
import urllib.parse
from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

# Encoding detection confidence thresholds
CONFIDENCE_THRESHOLD = 0.7  # Minimum confidence to consider an encoding detected

# Morse code mapping
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '0': '-----', '.': '.-.-.-', ',': '--..--', '?': '..--..',
    "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.',
    ')': '-.--.-', '&': '.-...', ':': '---...', ';': '-.-.-.',
    '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
    '"': '.-..-.', '$': '...-..-', '@': '.--.-.', ' ': '/'
}

# Reverse Morse code mapping
MORSE_CODE_REVERSE = {value: key for key, value in MORSE_CODE_DICT.items()}

@register_analyzer("encoding_analyzer")
@analyzer_compatibility(requires_text=True)
def analyze_encodings(state: State, **kwargs) -> State:
    """
    Detect and decode various encodings in the text.

    Args:
        state: Current puzzle state
        **kwargs: Additional parameters (ignored)

    Returns:
        Updated state
    """
    if not state.puzzle_text:
        return state

    text = state.puzzle_text

    state.add_insight(
        "Starting encoding analysis",
        analyzer="encoding_analyzer"
    )

    # Analyze for various encodings
    analyze_base64(state, text)
    analyze_base32(state, text)
    analyze_base85_ascii85(state, text)
    analyze_hex(state, text)
    analyze_binary(state, text)
    analyze_decimal(state, text)
    analyze_url_encoding(state, text)
    analyze_html_entities(state, text)
    analyze_morse_code(state, text)
    analyze_rot13(state, text)
    analyze_quoted_printable(state, text)
    analyze_uuencoding(state, text)
    analyze_leetspeak(state, text)

    # Check related files if any
    if state.related_files:
        state.add_insight(
            f"Checking {len(state.related_files)} related files for encodings",
            analyzer="encoding_analyzer"
        )

        for filename, file_info in state.related_files.items():
            if file_info.get("text_content"):
                related_text = file_info["text_content"]
                state.add_insight(
                    f"Analyzing related file {filename} for encodings",
                    analyzer="encoding_analyzer"
                )

                # Perform basic encoding checks on the related file
                if len(related_text) > 20:  # Only analyze if there's enough text
                    analyze_base64(state, related_text, is_related=True, filename=filename)
                    analyze_hex(state, related_text, is_related=True, filename=filename)

    return state

def analyze_base64(state: State, text: str, is_related=False, filename=None) -> None:
    """
    Analyze text for potential Base64 encoding.

    Args:
        state: Current puzzle state
        text: Text to analyze
        is_related: Whether this is a related file
        filename: Name of the related file (if applicable)
    """
    # Clean text by removing whitespace
    text = text.strip()
    clean_text = ''.join(c for c in text if c not in ' \t\n\r')

    if len(clean_text) < 4:
        return  # Not enough text to analyze

    # Check if the text contains only Base64 characters
    base64_chars = set(string.ascii_letters + string.digits + '+/=')
    is_base64_charset = all(c in base64_chars for c in clean_text)

    if not is_base64_charset:
        # Check for URL-safe Base64
        base64_url_chars = set(string.ascii_letters + string.digits + '-_=')
        is_base64_url = all(c in base64_url_chars for c in clean_text)

        if not is_base64_url:
            return

    # Base64-encoded data length is a multiple of 4
    padding_ok = len(clean_text) % 4 == 0

    # Check if the text ends with padding (= or ==)
    has_valid_padding = clean_text.endswith('=') or clean_text.endswith('==') or not '=' in clean_text

    # If it doesn't meet basic characteristics, it's probably not Base64
    if not (padding_ok and has_valid_padding):
        return

    # Try to decode as Base64
    try:
        # Handle URL-safe Base64
        if '-' in clean_text or '_' in clean_text:
            clean_text = clean_text.replace('-', '+').replace('_', '/')

        # Add padding if needed
        if not clean_text.endswith('='):
            padding_needed = (4 - len(clean_text) % 4) % 4
            clean_text += '=' * padding_needed

        decoded = base64.b64decode(clean_text)

        # Check if the decoded data is printable ASCII
        is_ascii = all(32 <= b <= 126 for b in decoded)

        prefix = f"Related file {filename}: " if is_related else ""

        if is_ascii:
            try:
                decoded_text = decoded.decode('utf-8')
                state.add_insight(
                    f"{prefix}Text appears to be Base64 encoded",
                    analyzer="encoding_analyzer"
                )

                source = f"Related file {filename}" if is_related else "Puzzle text"
                state.add_transformation(
                    name="Base64 Decoding",
                    description=f"Decoded Base64 from {source}",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded_text,
                    analyzer="encoding_analyzer"
                )
            except UnicodeDecodeError:
                # Not valid UTF-8, but still valid Base64
                state.add_insight(
                    f"{prefix}Text is Base64 encoded, but decoded data is not UTF-8 text",
                    analyzer="encoding_analyzer"
                )

                source = f"Related file {filename}" if is_related else "Puzzle text"
                state.add_transformation(
                    name="Base64 Decoding (Binary)",
                    description=f"Decoded Base64 from {source} (showing hex)",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded.hex(),
                    analyzer="encoding_analyzer"
                )
        else:
            # Decoded data is binary
            state.add_insight(
                f"{prefix}Text is Base64 encoded to binary data",
                analyzer="encoding_analyzer"
            )

            source = f"Related file {filename}" if is_related else "Puzzle text"
            state.add_transformation(
                name="Base64 Decoding (Binary)",
                description=f"Decoded Base64 from {source} (showing hex)",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=decoded.hex(),
                analyzer="encoding_analyzer"
            )
    except:
        # Not valid Base64
        pass

def analyze_base32(state: State, text: str) -> None:
    """
    Analyze text for potential Base32 encoding.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Clean text by removing whitespace
    text = text.strip()
    clean_text = ''.join(c for c in text if c not in ' \t\n\r')

    if len(clean_text) < 8:
        return  # Not enough text to analyze

    # Check if the text contains only Base32 characters
    base32_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=')
    is_base32_charset = all(c in base32_chars for c in clean_text.upper())

    if not is_base32_charset:
        return

    # Base32-encoded data length should be a multiple of 8 after padding
    has_valid_length = len(clean_text) % 8 == 0

    # If it doesn't meet basic characteristics, it's probably not Base32
    if not has_valid_length:
        return

    # Try to decode as Base32
    try:
        # Ensure text is uppercase for Base32
        clean_text = clean_text.upper()

        # Add padding if needed
        if not clean_text.endswith('='):
            padding_needed = (8 - len(clean_text) % 8) % 8
            clean_text += '=' * padding_needed

        decoded = base64.b32decode(clean_text)

        # Check if the decoded data is printable ASCII
        is_ascii = all(32 <= b <= 126 for b in decoded)

        if is_ascii:
            try:
                decoded_text = decoded.decode('utf-8')
                state.add_insight(
                    "Text appears to be Base32 encoded",
                    analyzer="encoding_analyzer"
                )

                state.add_transformation(
                    name="Base32 Decoding",
                    description="Decoded Base32",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded_text,
                    analyzer="encoding_analyzer"
                )
            except UnicodeDecodeError:
                # Not valid UTF-8, but still valid Base32
                state.add_insight(
                    "Text is Base32 encoded, but decoded data is not UTF-8 text",
                    analyzer="encoding_analyzer"
                )

                state.add_transformation(
                    name="Base32 Decoding (Binary)",
                    description="Decoded Base32 (showing hex)",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded.hex(),
                    analyzer="encoding_analyzer"
                )
        else:
            # Decoded data is binary
            state.add_insight(
                "Text is Base32 encoded to binary data",
                analyzer="encoding_analyzer"
            )

            state.add_transformation(
                name="Base32 Decoding (Binary)",
                description="Decoded Base32 (showing hex)",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=decoded.hex(),
                analyzer="encoding_analyzer"
            )
    except:
        # Not valid Base32
        pass

def analyze_base85_ascii85(state: State, text: str) -> None:
    """
    Analyze text for potential Base85/ASCII85 encoding.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Clean text by removing whitespace
    text = text.strip()
    clean_text = ''.join(c for c in text if c not in ' \t\n\r')

    if len(clean_text) < 5:
        return  # Not enough text to analyze

    # Check if the text starts and ends with ASCII85 delimiters
    has_delimiters = clean_text.startswith('<~') and clean_text.endswith('~>')

    # If it has delimiters, try to decode as ASCII85
    if has_delimiters:
        try:
            # Remove delimiters
            content = clean_text[2:-2]
            decoded = base64.a85decode(content, adobe=True)

            # Check if the decoded data is printable ASCII
            is_ascii = all(32 <= b <= 126 for b in decoded)

            if is_ascii:
                try:
                    decoded_text = decoded.decode('utf-8')
                    state.add_insight(
                        "Text appears to be ASCII85 encoded",
                        analyzer="encoding_analyzer"
                    )

                    state.add_transformation(
                        name="ASCII85 Decoding",
                        description="Decoded ASCII85",
                        input_data=text[:100] + "..." if len(text) > 100 else text,
                        output_data=decoded_text,
                        analyzer="encoding_analyzer"
                    )
                except UnicodeDecodeError:
                    # Not valid UTF-8, but still valid ASCII85
                    state.add_insight(
                        "Text is ASCII85 encoded, but decoded data is not UTF-8 text",
                        analyzer="encoding_analyzer"
                    )

                    state.add_transformation(
                        name="ASCII85 Decoding (Binary)",
                        description="Decoded ASCII85 (showing hex)",
                        input_data=text[:100] + "..." if len(text) > 100 else text,
                        output_data=decoded.hex(),
                        analyzer="encoding_analyzer"
                    )
            else:
                # Decoded data is binary
                state.add_insight(
                    "Text is ASCII85 encoded to binary data",
                    analyzer="encoding_analyzer"
                )

                state.add_transformation(
                    name="ASCII85 Decoding (Binary)",
                    description="Decoded ASCII85 (showing hex)",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded.hex(),
                    analyzer="encoding_analyzer"
                )
        except:
            # Not valid ASCII85
            pass

    # Try to decode as Base85 (Python's implementation)
    try:
        decoded = base64.b85decode(clean_text)

        # Check if the decoded data is printable ASCII
        is_ascii = all(32 <= b <= 126 for b in decoded)

        if is_ascii:
            try:
                decoded_text = decoded.decode('utf-8')
                state.add_insight(
                    "Text appears to be Base85 encoded",
                    analyzer="encoding_analyzer"
                )

                state.add_transformation(
                    name="Base85 Decoding",
                    description="Decoded Base85",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded_text,
                    analyzer="encoding_analyzer"
                )
            except UnicodeDecodeError:
                # Not valid UTF-8, but still valid Base85
                state.add_insight(
                    "Text is Base85 encoded, but decoded data is not UTF-8 text",
                    analyzer="encoding_analyzer"
                )

                state.add_transformation(
                    name="Base85 Decoding (Binary)",
                    description="Decoded Base85 (showing hex)",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded.hex(),
                    analyzer="encoding_analyzer"
                )
        else:
            # Decoded data is binary
            state.add_insight(
                "Text is Base85 encoded to binary data",
                analyzer="encoding_analyzer"
            )

            state.add_transformation(
                name="Base85 Decoding (Binary)",
                description="Decoded Base85 (showing hex)",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=decoded.hex(),
                analyzer="encoding_analyzer"
            )
    except:
        # Not valid Base85
        pass

def analyze_hex(state: State, text: str, is_related=False, filename=None) -> None:
    """
    Analyze text for potential hexadecimal encoding.

    Args:
        state: Current puzzle state
        text: Text to analyze
        is_related: Whether this is a related file
        filename: Name of the related file (if applicable)
    """
    # Clean text by removing whitespace
    text = text.strip()
    clean_text = ''.join(c for c in text if c not in ' \t\n\r')

    if len(clean_text) < 2:
        return  # Not enough text to analyze

    # Check if the text contains only hex characters
    is_hex = all(c in string.hexdigits for c in clean_text)

    if not is_hex:
        return

    # Hexadecimal data should have an even number of digits
    has_even_length = len(clean_text) % 2 == 0

    # If it doesn't have an even length, it's probably not valid hex
    if not has_even_length:
        return

    # Try to decode as hex
    try:
        decoded = bytes.fromhex(clean_text)

        # Check if the decoded data is printable ASCII
        is_ascii = all(32 <= b <= 126 for b in decoded)

        prefix = f"Related file {filename}: " if is_related else ""

        if is_ascii:
            try:
                decoded_text = decoded.decode('utf-8')
                state.add_insight(
                    f"{prefix}Text appears to be hexadecimal encoded",
                    analyzer="encoding_analyzer"
                )

                source = f"Related file {filename}" if is_related else "Puzzle text"
                state.add_transformation(
                    name="Hexadecimal Decoding",
                    description=f"Decoded hex from {source}",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded_text,
                    analyzer="encoding_analyzer"
                )
            except UnicodeDecodeError:
                # Not valid UTF-8, but still valid hex
                state.add_insight(
                    f"{prefix}Text is hexadecimal encoded, but decoded data is not UTF-8 text",
                    analyzer="encoding_analyzer"
                )

                source = f"Related file {filename}" if is_related else "Puzzle text"
                state.add_transformation(
                    name="Hexadecimal Decoding (Binary)",
                    description=f"Decoded hex from {source} (showing hex dumps)",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=f"Hex dump: {' '.join(f'{b:02x}' for b in decoded)}\n"
                               f"ASCII: {bytes([b if 32 <= b <= 126 else ord('.') for b in decoded]).decode('ascii')}",
                    analyzer="encoding_analyzer"
                )
        else:
            # Decoded data is binary
            state.add_insight(
                f"{prefix}Text is hexadecimal encoded to binary data",
                analyzer="encoding_analyzer"
            )

            source = f"Related file {filename}" if is_related else "Puzzle text"
            state.add_transformation(
                name="Hexadecimal Decoding (Binary)",
                description=f"Decoded hex from {source} (showing hex dumps)",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=f"Hex dump: {' '.join(f'{b:02x}' for b in decoded)}\n"
                           f"ASCII: {bytes([b if 32 <= b <= 126 else ord('.') for b in decoded]).decode('ascii')}",
                analyzer="encoding_analyzer"
            )
    except:
        # Not valid hex
        pass

def analyze_binary(state: State, text: str) -> None:
    """
    Analyze text for potential binary encoding.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Clean text by removing whitespace
    text = text.strip()
    clean_text = ''.join(c for c in text if c not in ' \t\n\r')

    if len(clean_text) < 8:
        return  # Not enough text to analyze

    # Check if the text contains only binary digits
    is_binary = all(c in '01' for c in clean_text)

    if not is_binary:
        return

    # Try to decode as binary (8 bits per byte)
    try:
        # Pad if necessary
        remainder = len(clean_text) % 8
        if remainder != 0:
            clean_text = '0' * (8 - remainder) + clean_text

        # Convert binary to bytes
        decoded = bytes(int(clean_text[i:i+8], 2) for i in range(0, len(clean_text), 8))

        # Check if the decoded data is printable ASCII
        is_ascii = all(32 <= b <= 126 for b in decoded)

        if is_ascii:
            try:
                decoded_text = decoded.decode('utf-8')
                state.add_insight(
                    "Text appears to be binary encoded",
                    analyzer="encoding_analyzer"
                )

                state.add_transformation(
                    name="Binary Decoding",
                    description="Decoded binary",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded_text,
                    analyzer="encoding_analyzer"
                )
            except UnicodeDecodeError:
                # Not valid UTF-8, but still valid binary
                state.add_insight(
                    "Text is binary encoded, but decoded data is not UTF-8 text",
                    analyzer="encoding_analyzer"
                )

                state.add_transformation(
                    name="Binary Decoding (Hex)",
                    description="Decoded binary (showing hex)",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded.hex(),
                    analyzer="encoding_analyzer"
                )
        else:
            # Decoded data is binary
            state.add_insight(
                "Text is binary encoded to binary data",
                analyzer="encoding_analyzer"
            )

            state.add_transformation(
                name="Binary Decoding (Hex)",
                description="Decoded binary (showing hex)",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=decoded.hex(),
                analyzer="encoding_analyzer"
            )
    except:
        # Not valid binary
        pass

def analyze_decimal(state: State, text: str) -> None:
    """
    Analyze text for potential decimal encoding (ASCII codes).

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Look for patterns of decimal numbers, potentially separated by spaces or commas
    text = text.strip()

    # Try to extract decimal numbers
    decimal_pattern = re.compile(r'(\d+)[,\s]*')
    matches = decimal_pattern.findall(text)

    if not matches or len(matches) < 3:
        return  # Not enough numbers

    # Try to interpret as ASCII codes
    try:
        # Convert to integers
        numbers = [int(m) for m in matches]

        # Check if all numbers are in ASCII range
        if all(0 <= n <= 127 for n in numbers):
            # Convert to ASCII
            decoded = ''.join(chr(n) for n in numbers)

            # Check if result is mainly printable
            printable_ratio = sum(c.isprintable() for c in decoded) / len(decoded)

            if printable_ratio > 0.8:
                state.add_insight(
                    "Text appears to be decimal ASCII codes",
                    analyzer="encoding_analyzer"
                )

                state.add_transformation(
                    name="Decimal ASCII Decoding",
                    description="Decoded decimal ASCII codes",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded,
                    analyzer="encoding_analyzer"
                )

                return

        # Try extended ASCII range
        if all(0 <= n <= 255 for n in numbers):
            # Convert to bytes and then to string
            decoded_bytes = bytes(numbers)
            try:
                decoded = decoded_bytes.decode('utf-8', errors='replace')

                state.add_insight(
                    "Text appears to be decimal byte values",
                    analyzer="encoding_analyzer"
                )

                state.add_transformation(
                    name="Decimal Bytes Decoding",
                    description="Decoded decimal byte values",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded,
                    analyzer="encoding_analyzer"
                )
            except:
                # Not valid UTF-8
                state.add_insight(
                    "Text appears to be decimal byte values, but not valid UTF-8",
                    analyzer="encoding_analyzer"
                )

                state.add_transformation(
                    name="Decimal Bytes Decoding (Hex)",
                    description="Decoded decimal byte values (showing hex)",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded_bytes.hex(),
                    analyzer="encoding_analyzer"
                )
    except:
        # Not valid decimal encoding
        pass

def analyze_url_encoding(state: State, text: str) -> None:
    """
    Analyze text for potential URL encoding.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Check if the text contains URL encoded characters
    if '%' not in text:
        return

    # Look for URL encoded patterns
    url_encoded_pattern = re.compile(r'%[0-9A-Fa-f]{2}')
    matches = url_encoded_pattern.findall(text)

    if not matches:
        return

    # Try to decode URL encoding
    try:
        decoded = urllib.parse.unquote(text)

        # Only consider it URL encoded if the decoded text is different
        if decoded != text:
            state.add_insight(
                "Text contains URL encoded characters",
                analyzer="encoding_analyzer"
            )

            state.add_transformation(
                name="URL Decoding",
                description="Decoded URL encoding",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=decoded,
                analyzer="encoding_analyzer"
            )
    except:
        # Not valid URL encoding
        pass

def analyze_html_entities(state: State, text: str) -> None:
    """
    Analyze text for potential HTML entities.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Check if the text contains HTML entities
    if '&' not in text or ';' not in text:
        return

    # Look for HTML entity patterns
    html_entity_pattern = re.compile(r'&[#a-zA-Z0-9]+;')
    matches = html_entity_pattern.findall(text)

    if not matches:
        return

    # Try to decode HTML entities
    try:
        import html
        decoded = html.unescape(text)

        # Only consider it HTML encoded if the decoded text is different
        if decoded != text:
            state.add_insight(
                "Text contains HTML entities",
                analyzer="encoding_analyzer"
            )

            state.add_transformation(
                name="HTML Entity Decoding",
                description="Decoded HTML entities",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=decoded,
                analyzer="encoding_analyzer"
            )
    except:
        # Not valid HTML encoding
        pass

def analyze_morse_code(state: State, text: str) -> None:
    """
    Analyze text for potential Morse code.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Check if the text could be Morse code
    morse_chars = set('.-/ \t\n')

    # Text is likely Morse code if most characters are dots, dashes, and separators
    morse_ratio = sum(1 for c in text if c in morse_chars) / len(text) if text else 0

    if morse_ratio < 0.9:
        return

    # Try to decode Morse code
    try:
        # Split into words (separated by '/')
        morse_words = text.split('/')

        # Decode each word
        decoded_words = []
        for word in morse_words:
            # Split into letters (separated by spaces)
            morse_letters = word.strip().split()

            # Decode each letter
            decoded_word = ''
            for letter in morse_letters:
                if letter in MORSE_CODE_REVERSE:
                    decoded_word += MORSE_CODE_REVERSE[letter]
                else:
                    decoded_word += '?'

            decoded_words.append(decoded_word)

        # Join words with spaces
        decoded = ' '.join(decoded_words)

        # Only consider it Morse code if the decoded text is different and mostly valid
        if decoded and decoded != text and '?' not in decoded:
            state.add_insight(
                "Text appears to be Morse code",
                analyzer="encoding_analyzer"
            )

            state.add_transformation(
                name="Morse Code Decoding",
                description="Decoded Morse code",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=decoded,
                analyzer="encoding_analyzer"
            )
    except:
        # Not valid Morse code
        pass

def analyze_rot13(state: State, text: str) -> None:
    """
    Analyze text for potential ROT13 encoding.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # ROT13 is a special case of Caesar cipher, but it's common enough to check separately

    # Only analyze if the text is mostly alphabetic
    alpha_ratio = sum(1 for c in text if c.isalpha()) / len(text) if text else 0

    if alpha_ratio < 0.7:
        return

    # Apply ROT13
    decoded = ''.join(rot13_char(c) for c in text)

    # Check if the result looks like valid text
    # This is a bit difficult to automate, but we can check for common words
    words = decoded.lower().split()
    common_words = sum(1 for word in words if word in {
        'the', 'and', 'that', 'have', 'for', 'not', 'with', 'you', 'this', 'but',
        'his', 'from', 'they', 'say', 'she', 'will', 'one', 'all', 'would', 'there'
    })

    if common_words >= 2 or (len(words) <= 5 and common_words >= 1):
        state.add_insight(
            "Text appears to be ROT13 encoded",
            analyzer="encoding_analyzer"
        )

        state.add_transformation(
            name="ROT13 Decoding",
            description="Decoded ROT13",
            input_data=text[:100] + "..." if len(text) > 100 else text,
            output_data=decoded,
            analyzer="encoding_analyzer"
        )

def analyze_quoted_printable(state: State, text: str) -> None:
    """
    Analyze text for potential Quoted-Printable encoding.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Check if the text contains Quoted-Printable encoded characters
    if '=' not in text:
        return

    # Look for Quoted-Printable patterns
    qp_pattern = re.compile(r'=[0-9A-Fa-f]{2}')
    matches = qp_pattern.findall(text)

    if not matches:
        return

    # Try to decode Quoted-Printable
    try:
        import quopri
        decoded = quopri.decodestring(text.encode('utf-8')).decode('utf-8')

        # Only consider it Quoted-Printable if the decoded text is different
        if decoded != text:
            state.add_insight(
                "Text appears to be Quoted-Printable encoded",
                analyzer="encoding_analyzer"
            )

            state.add_transformation(
                name="Quoted-Printable Decoding",
                description="Decoded Quoted-Printable",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=decoded,
                analyzer="encoding_analyzer"
            )
    except:
        # Not valid Quoted-Printable
        pass

def analyze_uuencoding(state: State, text: str) -> None:
    """
    Analyze text for potential UUencoding.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Check if the text looks like UUencoded data
    lines = text.strip().split('\n')

    # UUencoded data typically starts with "begin" and ends with "end"
    if not (len(lines) >= 3 and lines[0].startswith('begin ')):
        return

    # Try to decode as UUencoded data
    try:
        import uu
        import tempfile

        # Create temporary files for UUdecode
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_in:
            temp_in.write(text)
            temp_in_name = temp_in.name

        with tempfile.NamedTemporaryFile(delete=False) as temp_out:
            temp_out_name = temp_out.name

        # Decode
        uu.decode(temp_in_name, temp_out_name)

        # Read the decoded data
        with open(temp_out_name, 'rb') as f:
            decoded_data = f.read()

        # Cleanup temporary files
        os.unlink(temp_in_name)
        os.unlink(temp_out_name)

        # Check if the decoded data is printable ASCII
        is_ascii = all(32 <= b <= 126 for b in decoded_data)

        if is_ascii:
            try:
                decoded_text = decoded_data.decode('utf-8')
                state.add_insight(
                    "Text appears to be UUencoded",
                    analyzer="encoding_analyzer"
                )

                state.add_transformation(
                    name="UUencoding Decoding",
                    description="Decoded UUencoded data",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded_text,
                    analyzer="encoding_analyzer"
                )
            except UnicodeDecodeError:
                # Not valid UTF-8, but still valid UUencoded data
                state.add_insight(
                    "Text is UUencoded, but decoded data is not UTF-8 text",
                    analyzer="encoding_analyzer"
                )

                state.add_transformation(
                    name="UUencoding Decoding (Binary)",
                    description="Decoded UUencoded data (showing hex)",
                    input_data=text[:100] + "..." if len(text) > 100 else text,
                    output_data=decoded_data.hex(),
                    analyzer="encoding_analyzer"
                )
        else:
            # Decoded data is binary
            state.add_insight(
                "Text is UUencoded to binary data",
                analyzer="encoding_analyzer"
            )

            state.add_transformation(
                name="UUencoding Decoding (Binary)",
                description="Decoded UUencoded data (showing hex)",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=decoded_data.hex(),
                analyzer="encoding_analyzer"
            )
    except:
        # Not valid UUencoded data
        pass

def analyze_leetspeak(state: State, text: str) -> None:
    """
    Analyze text for potential leetspeak encoding.

    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Check if the text contains leetspeak characters
    leetspeak_chars = set('01234567890!@#$%^&*()_+-=[]{}|;:<>,.?/')

    # Text might be leetspeak if it contains a mix of letters and leetspeak characters
    has_letters = any(c.isalpha() for c in text)
    has_leetspeak = sum(1 for c in text if c in leetspeak_chars) / len(text) > 0.3 if text else False

    if not (has_letters and has_leetspeak):
        return

    # Try to decode leetspeak
    leetspeak_map = {
        '0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a',
        '5': 's', '6': 'g', '7': 't', '8': 'b', '9': 'g',
        '@': 'a', '$': 's', '!': 'i', '+': 't', '(': 'c',
        ')': 'd', '|': 'l', '/': 'l', '\\': 'l', '<': 'c',
        '>': 'd', '^': 'a', '#': 'h'
    }

    decoded = ''
    for c in text:
        if c in leetspeak_map:
            decoded += leetspeak_map[c]
        else:
            decoded += c

    # Only consider it leetspeak if the decoded text is different
    if decoded != text:
        # Check if the result looks like valid text
        words = decoded.lower().split()
        common_words = sum(1 for word in words if word in {
            'the', 'and', 'that', 'have', 'for', 'not', 'with', 'you', 'this', 'but',
            'his', 'from', 'they', 'say', 'she', 'will', 'one', 'all', 'would', 'there'
        })

        if common_words >= 1 or len(words) <= 3:
            state.add_insight(
                "Text appears to contain leetspeak",
                analyzer="encoding_analyzer"
            )

            state.add_transformation(
                name="Leetspeak Decoding",
                description="Decoded leetspeak",
                input_data=text[:100] + "..." if len(text) > 100 else text,
                output_data=decoded,
                analyzer="encoding_analyzer"
            )

# Utility functions

def rot13_char(c: str) -> str:
    """
    Apply ROT13 to a single character.

    Args:
        c: Character to transform

    Returns:
        Transformed character
    """
    if c.isalpha():
        is_upper = c.isupper()
        c = c.lower()

        # Shift by 13
        c = chr((ord(c) - ord('a') + 13) % 26 + ord('a'))

        # Restore case
        if is_upper:
            c = c.upper()

    return c
