"""
Crypto Hunter - Analyzers Module

This package contains the analyzers for various cryptographic puzzles.
"""

# Load all analyzers
from analyzers.base import (
    register_analyzer,
    analyzer_compatibility,
    get_all_analyzers,
    get_analyzer,
    run_analyzer,
    load_all_analyzers,
)

# Import individual analyzers
# These imports ensure all analyzers are registered
import analyzers.binary_analyzer
import analyzers.blockchain_analyzer
import analyzers.cipher_analyzer
import analyzers.encoding_analyzer
import analyzers.image_analyzer
import analyzers.text_analyzer

# Initialize all analyzers
load_all_analyzers()
