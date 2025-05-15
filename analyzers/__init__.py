"""
Analyzers module for Crypto Hunter.
"""

from analyzers.base import register_analyzer, analyzer_compatibility, get_analyzer, get_all_analyzers
from analyzers.text_analyzer import analyze_text
from analyzers.binary_analyzer import analyze_binary
from analyzers.cipher_analyzer import analyze_ciphers
from analyzers.encoding_analyzer import analyze_encodings
from analyzers.image_analyzer import analyze_image
from analyzers.web_analyzer import analyze_web
from analyzers.vision_analyzer import analyze_vision
from analyzers.code_analyzer import analyze_code

# Import additional analyzers as they are added
