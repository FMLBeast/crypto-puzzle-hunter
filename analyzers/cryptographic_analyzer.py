"""
Cryptographic analyzer module.
This is an alias for the crypto_analyzer module.
"""

from core.state import State
from analyzers.crypto_analyzer import analyze_crypto
from analyzers.base import register_analyzer, analyzer_compatibility

@register_analyzer("cryptographic_analyzer")
@analyzer_compatibility(requires_text=True)
def analyze_cryptographic(state: State) -> State:
    """
    Analyze the puzzle for cryptographic elements.
    This is an alias for the analyze_crypto function.

    Args:
        state: Current puzzle state

    Returns:
        Updated state with crypto analysis insights
    """
    return analyze_crypto(state)