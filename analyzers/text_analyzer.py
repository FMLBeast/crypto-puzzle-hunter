"""
Text analyzer for Crypto Hunter.
Analyzes text patterns to identify potential encodings and ciphers.
"""

import re
import string
import collections
from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

@register_analyzer("text_analyzer")
@analyzer_compatibility(requires_text=True)
def analyze_text(state: State) -> State:
    """
    Analyze text patterns to identify potential encodings and ciphers.
    
    Args:
        state: Current puzzle state
        
    Returns:
        Updated state
    """
    if not state.puzzle_text:
        return state
    
    text = state.puzzle_text
    
    # Add insight about starting analysis
    state.add_insight(
        f"Starting text analysis of {len(text)} characters",
        analyzer="text_analyzer"
    )
    
    # Analyze text characteristics
    analyze_character_distribution(state, text)
    analyze_word_patterns(state, text)
    analyze_potential_encodings(state, text)
    analyze_line_patterns(state, text)
    
    # Check related files if any
    if state.related_files:
        state.add_insight(
            f"Checking {len(state.related_files)} related files for text patterns",
            analyzer="text_analyzer"
        )
        
        for filename, file_info in state.related_files.items():
            if file_info.get("text_content"):
                related_text = file_info["text_content"]
                state.add_insight(
                    f"Analyzing related file {filename} ({len(related_text)} characters)",
                    analyzer="text_analyzer"
                )
                
                # Add a transformation to show the related file content
                state.add_transformation(
                    name=f"Related file: {filename}",
                    description=f"Content of related file {filename}",
                    input_data="Related file content",
                    output_data=related_text[:1000] + "..." if len(related_text) > 1000 else related_text,
                    analyzer="text_analyzer"
                )
    
    return state

def analyze_character_distribution(state: State, text: str) -> None:
    """
    Analyze character distribution in the text.
    
    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Count character frequencies
    char_counts = collections.Counter(text)
    total_chars = len(text)
    
    # Calculate entropy
    import math
    entropy = 0
    for char, count in char_counts.items():
        prob = count / total_chars
        entropy -= prob * math.log2(prob)
    
    # Determine most common and least common characters
    most_common = char_counts.most_common(5)
    least_common = char_counts.most_common()[:-6:-1]
    
    # Add insights
    state.add_insight(
        f"Character entropy: {entropy:.2f} bits (higher values indicate more randomness)",
        analyzer="text_analyzer"
    )
    
    state.add_insight(
        f"Most common characters: {', '.join([repr(c) + ':' + str(n) for c, n in most_common])}",
        analyzer="text_analyzer"
    )
    
    state.add_insight(
        f"Least common characters: {', '.join([repr(c) + ':' + str(n) for c, n in least_common])}",
        analyzer="text_analyzer"
    )
    
    # Check character set
    ascii_printable = all(c in string.printable for c in text)
    ascii_letters_only = all(c in string.ascii_letters + string.whitespace for c in text)
    hex_only = all(c in string.hexdigits + string.whitespace for c in text)
    digits_only = all(c in string.digits + string.whitespace for c in text)
    base64_chars = set(string.ascii_letters + string.digits + '+/=' + string.whitespace)
    base64_only = all(c in base64_chars for c in text)
    
    if ascii_printable:
        state.add_insight(
            "Text contains only printable ASCII characters",
            analyzer="text_analyzer"
        )
    
    if ascii_letters_only:
        state.add_insight(
            "Text contains only letters and whitespace (potential cipher text)",
            analyzer="text_analyzer"
        )
    
    if hex_only:
        state.add_insight(
            "Text contains only hexadecimal characters (potential hex encoding)",
            analyzer="text_analyzer"
        )
    
    if digits_only:
        state.add_insight(
            "Text contains only digits (potential numeric encoding)",
            analyzer="text_analyzer"
        )
    
    if base64_only:
        state.add_insight(
            "Text contains only Base64 characters (potential Base64 encoding)",
            analyzer="text_analyzer"
        )
    
    # Add transformation for character frequency
    freq_output = "Character Frequencies:\n"
    for char, count in char_counts.most_common(20):
        freq_output += f"{repr(char)}: {count} ({count/total_chars*100:.2f}%)\n"
    
    state.add_transformation(
        name="Character Frequency Analysis",
        description="Analysis of character frequencies in the text",
        input_data=text[:100] + "..." if len(text) > 100 else text,
        output_data=freq_output,
        analyzer="text_analyzer"
    )

def analyze_word_patterns(state: State, text: str) -> None:
    """
    Analyze word patterns in the text.
    
    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Split into words (handling various separators)
    words = re.findall(r'\b\w+\b', text)
    
    if not words:
        state.add_insight(
            "No clear word patterns found in the text",
            analyzer="text_analyzer"
        )
        return
    
    # Count word frequencies
    word_counts = collections.Counter(words)
    
    # Determine most common words
    most_common_words = word_counts.most_common(5)
    
    # Add insights
    state.add_insight(
        f"Total words: {len(words)}, unique words: {len(word_counts)}",
        analyzer="text_analyzer"
    )
    
    if most_common_words:
        state.add_insight(
            f"Most common words: {', '.join([f'{w}:{c}' for w, c in most_common_words])}",
            analyzer="text_analyzer"
        )
    
    # Look for repeating word patterns
    repeated_patterns = []
    for n in range(2, min(5, len(words) // 2 + 1)):
        for i in range(len(words) - n + 1):
            pattern = tuple(words[i:i+n])
            count = 0
            for j in range(len(words) - n + 1):
                if tuple(words[j:j+n]) == pattern:
                    count += 1
            if count > 1:
                repeated_patterns.append((pattern, count))
    
    # Sort and remove duplicates
    repeated_patterns = sorted(set(repeated_patterns), key=lambda x: x[1], reverse=True)
    
    if repeated_patterns:
        patterns_text = ", ".join([f"{' '.join(p)}:{c}" for p, c in repeated_patterns[:3]])
        state.add_insight(
            f"Repeated word patterns: {patterns_text}",
            analyzer="text_analyzer"
        )
    
    # Check for potential letter substitution ciphers
    if len(words) >= 20:
        # English letter frequency: E, T, A, O, I, N, S, H, R, D, L, U, C...
        english_letter_freq = "ETAOINSRHLDCUMFPGWYBVKJXQZ".lower()
        
        # Calculate letter frequency in the text
        letter_counts = collections.Counter("".join(words).lower())
        text_letter_freq = "".join([c for c, _ in letter_counts.most_common()
                                    if c in string.ascii_lowercase])
        
        # Check if the frequency pattern matches English
        if len(text_letter_freq) >= 10:
            matches = 0
            for i in range(5):
                if i < len(text_letter_freq) and text_letter_freq[i] in english_letter_freq[:10]:
                    matches += 1
            
            if matches >= 3:
                state.add_insight(
                    "Letter frequency distribution is similar to English text",
                    analyzer="text_analyzer"
                )
            else:
                state.add_insight(
                    "Letter frequency distribution differs from standard English (potential substitution cipher)",
                    analyzer="text_analyzer"
                )

def analyze_potential_encodings(state: State, text: str) -> None:
    """
    Analyze if the text matches patterns of common encodings.
    
    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Patterns for common encodings
    patterns = {
        "hexadecimal": r'^[0-9a-fA-F\s]+$',
        "base64": r'^[A-Za-z0-9+/=\s]+$',
        "binary": r'^[01\s]+$',
        "decimal": r'^[0-9\s]+$',
        "morse_code": r'^[\.\-\s/]+$',
        "url_encoding": r'%[0-9a-fA-F]{2}',
        "html_entities": r'&[#a-zA-Z0-9]+;'
    }
    
    # Clean the text
    clean_text = text.strip()
    
    # Check each pattern
    for encoding, pattern in patterns.items():
        if re.match(pattern, clean_text):
            state.add_insight(
                f"Text appears to be {encoding} encoded",
                analyzer="text_analyzer"
            )
        elif encoding == "url_encoding" and re.search(pattern, clean_text):
            state.add_insight(
                f"Text contains URL-encoded characters",
                analyzer="text_analyzer"
            )
        elif encoding == "html_entities" and re.search(pattern, clean_text):
            state.add_insight(
                f"Text contains HTML entities",
                analyzer="text_analyzer"
            )
    
    # Check for potential Base64
    if re.match(patterns["base64"], clean_text):
        # Base64-encoded data often has a length that's a multiple of 4
        if len(clean_text.replace('\n', '').replace(' ', '')) % 4 == 0:
            state.add_insight(
                "Text length is a multiple of 4, consistent with Base64 encoding",
                analyzer="text_analyzer"
            )
    
    # Check for hex with specific length patterns
    if re.match(patterns["hexadecimal"], clean_text):
        clean_hex = clean_text.replace('\n', '').replace(' ', '')
        if len(clean_hex) % 2 == 0:
            if len(clean_hex) == 32:
                state.add_insight(
                    "Text appears to be 16-byte hex data (e.g., MD5 hash)",
                    analyzer="text_analyzer"
                )
            elif len(clean_hex) == 40:
                state.add_insight(
                    "Text appears to be 20-byte hex data (e.g., SHA-1 hash)",
                    analyzer="text_analyzer"
                )
            elif len(clean_hex) == 64:
                state.add_insight(
                    "Text appears to be 32-byte hex data (e.g., SHA-256 hash)",
                    analyzer="text_analyzer"
                )
            else:
                state.add_insight(
                    f"Text appears to be {len(clean_hex)//2}-byte hex data",
                    analyzer="text_analyzer"
                )

def analyze_line_patterns(state: State, text: str) -> None:
    """
    Analyze patterns across different lines in the text.
    
    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    lines = text.splitlines()
    
    if len(lines) <= 1:
        return
    
    # Add insight about number of lines
    state.add_insight(
        f"Text contains {len(lines)} lines",
        analyzer="text_analyzer"
    )
    
    # Check for equal-length lines
    line_lengths = [len(line) for line in lines]
    if len(set(line_lengths)) == 1 and line_lengths[0] > 0:
        state.add_insight(
            f"All lines have equal length ({line_lengths[0]} characters), possible grid or structured data",
            analyzer="text_analyzer"
        )
    
    # Check for lines starting with the same pattern
    line_starts = [line[:min(5, len(line))] for line in lines if line]
    start_counter = collections.Counter(line_starts)
    common_starts = [s for s, count in start_counter.most_common() if count > 1]
    
    if common_starts:
        state.add_insight(
            f"Multiple lines start with the same pattern: {', '.join(repr(s) for s in common_starts[:3])}",
            analyzer="text_analyzer"
        )
    
    # Check for potential ASCII art
    ascii_art_chars = set('-|/\\[]{}()#*+<>=_')
    ascii_art_ratio = sum(1 for c in text if c in ascii_art_chars) / len(text) if text else 0
    
    if ascii_art_ratio > 0.15:
        state.add_insight(
            "Text contains a high ratio of ASCII art characters, may contain visual pattern",
            analyzer="text_analyzer"
        )
