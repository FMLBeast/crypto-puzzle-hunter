"""
Crypto Analyzer: runs cipher_analyzer then encoding_analyzer.
"""
from .cipher_analyzer   import analyze as _cipher
from .encoding_analyzer import analyze as _enc

def analyze(state, **kwargs):
    try:
        state = _cipher(state, **kwargs)
    except Exception as e:
        state.add_insight(f"cipher_analyzer error: {e}", "crypto_analyzer")
    try:
        state = _enc(state, **kwargs)
    except Exception as e:
        state.add_insight(f"encoding_analyzer error: {e}", "crypto_analyzer")
    return state
