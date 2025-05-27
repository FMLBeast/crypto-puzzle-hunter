"""
Text pattern analyzer for Crypto Hunter.
Focuses on advanced pattern recognition in text for cryptographic puzzles.
"""

import re
import string
import collections
from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

@register_analyzer("text_pattern_analyzer")
@analyzer_compatibility(requires_text=True)
def analyze_text_patterns(state: State) -> State:
    """
    Analyze advanced text patterns to identify potential cryptographic features.
    
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
        f"Starting advanced text pattern analysis of {len(text)} characters",
        analyzer="text_pattern_analyzer"
    )
    
    # Analyze various text patterns
    analyze_repeating_patterns(state, text)
    analyze_positional_patterns(state, text)
    analyze_regex_patterns(state, text)
    analyze_cryptographic_patterns(state, text)
    
    return state

def analyze_repeating_patterns(state: State, text: str) -> None:
    """
    Analyze repeating patterns in the text.
    
    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Find repeating sequences (3+ characters)
    repeats = {}
    for length in range(3, min(20, len(text) // 2)):
        for i in range(len(text) - length + 1):
            pattern = text[i:i+length]
            if pattern in text[i+1:]:
                if pattern in repeats:
                    repeats[pattern] += 1
                else:
                    repeats[pattern] = 2
    
    # Report significant repeating patterns
    significant_repeats = {k: v for k, v in repeats.items() if v > 1 and len(k) > 2}
    if significant_repeats:
        top_repeats = sorted(significant_repeats.items(), key=lambda x: (x[1], len(x[0])), reverse=True)[:5]
        state.add_insight(
            f"Found {len(significant_repeats)} repeating patterns. Top patterns: " + 
            ", ".join([f"'{p}' (repeats {c} times)" for p, c in top_repeats]),
            analyzer="text_pattern_analyzer"
        )
    else:
        state.add_insight(
            "No significant repeating patterns found",
            analyzer="text_pattern_analyzer"
        )

def analyze_positional_patterns(state: State, text: str) -> None:
    """
    Analyze patterns based on character positions.
    
    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Check for patterns in character positions (e.g., every nth character)
    for n in range(2, 10):
        for offset in range(n):
            chars = text[offset::n]
            char_counts = collections.Counter(chars)
            most_common = char_counts.most_common(1)
            
            if most_common and most_common[0][1] > len(chars) * 0.7:  # If one character appears in >70% of positions
                state.add_insight(
                    f"Position pattern detected: Every {n}th character starting at position {offset} " +
                    f"is frequently '{most_common[0][0]}' ({most_common[0][1]} out of {len(chars)} positions)",
                    analyzer="text_pattern_analyzer"
                )
                
                # Create a transformation to show the pattern
                pattern_display = ['_'] * len(text)
                for i in range(offset, len(text), n):
                    pattern_display[i] = text[i]
                
                state.add_transformation(
                    name=f"Position pattern (every {n}th char from pos {offset})",
                    description=f"Highlighting every {n}th character starting at position {offset}",
                    input_data=text,
                    output_data=''.join(pattern_display),
                    analyzer="text_pattern_analyzer"
                )

def analyze_regex_patterns(state: State, text: str) -> None:
    """
    Analyze text using regular expression patterns.
    
    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Check for common formats
    patterns = {
        "Potential hex values": r'\b[0-9A-Fa-f]{6,}\b',
        "Potential base64": r'[A-Za-z0-9+/=]{4,}={0,2}',
        "Potential URLs": r'https?://[^\s]+',
        "Potential email addresses": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "Potential IP addresses": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        "Potential dates": r'\b\d{1,4}[-/]\d{1,2}[-/]\d{1,4}\b',
        "Potential crypto addresses": r'\b(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'
    }
    
    for pattern_name, regex in patterns.items():
        matches = re.findall(regex, text)
        if matches:
            state.add_insight(
                f"{pattern_name} found: {', '.join(matches[:3])}{'...' if len(matches) > 3 else ''}",
                analyzer="text_pattern_analyzer"
            )
            
            if len(matches) > 3:
                state.add_transformation(
                    name=f"All {pattern_name}",
                    description=f"Complete list of {pattern_name} found in text",
                    input_data=text,
                    output_data='\n'.join(matches),
                    analyzer="text_pattern_analyzer"
                )

def analyze_cryptographic_patterns(state: State, text: str) -> None:
    """
    Analyze patterns that might indicate specific cryptographic techniques.
    
    Args:
        state: Current puzzle state
        text: Text to analyze
    """
    # Check for potential Vigenère patterns
    if all(c in string.ascii_letters + string.whitespace for c in text):
        # Calculate Index of Coincidence
        text_clean = ''.join(c.lower() for c in text if c.isalpha())
        if text_clean:
            freqs = collections.Counter(text_clean)
            n = len(text_clean)
            ioc = sum(count * (count - 1) for count in freqs.values()) / (n * (n - 1)) * 26 if n > 1 else 0
            
            if 1.6 < ioc < 1.8:
                state.add_insight(
                    f"Text has an Index of Coincidence of {ioc:.2f}, consistent with English text",
                    analyzer="text_pattern_analyzer"
                )
            elif 1.0 < ioc < 1.5:
                state.add_insight(
                    f"Text has an Index of Coincidence of {ioc:.2f}, suggesting possible polyalphabetic cipher (like Vigenère)",
                    analyzer="text_pattern_analyzer"
                )
            else:
                state.add_insight(
                    f"Text has an Index of Coincidence of {ioc:.2f}, suggesting random or highly encrypted text",
                    analyzer="text_pattern_analyzer"
                )
    
    # Check for potential transposition patterns
    words = [w for w in text.split() if len(w) > 3]
    if words:
        anagram_candidates = []
        for word in words:
            # Check if letters in word could form a common English word
            word_clean = ''.join(c.lower() for c in word if c.isalpha())
            if word_clean and sorted(word_clean) in [
                sorted('the'), sorted('and'), sorted('that'), sorted('have'),
                sorted('for'), sorted('not'), sorted('with'), sorted('you'),
                sorted('this'), sorted('but'), sorted('his'), sorted('from'),
                sorted('they'), sorted('say'), sorted('her'), sorted('she'),
                sorted('will'), sorted('one'), sorted('all'), sorted('would'),
                sorted('there'), sorted('their'), sorted('what'), sorted('out'),
                sorted('about'), sorted('who'), sorted('get'), sorted('which')
            ]:
                anagram_candidates.append(word)
        
        if anagram_candidates:
            state.add_insight(
                f"Potential anagram/transposition candidates: {', '.join(anagram_candidates[:5])}{'...' if len(anagram_candidates) > 5 else ''}",
                analyzer="text_pattern_analyzer"
            )