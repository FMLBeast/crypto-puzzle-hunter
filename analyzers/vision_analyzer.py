"""
Vision analyzer for Crypto Hunter.
Integrates the VisionAgent into the analysis flow.
"""

import logging
from typing import Dict, Any, Optional, List
from core.state import State
from core.vision_agent import VisionAgent
from analyzers.base import register_analyzer, analyzer_compatibility
from analyzers.image_analyzer import analyze_image_with_opencv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@register_analyzer("vision_analyzer")
@analyzer_compatibility(file_types=["png", "jpg", "jpeg", "gif", "bmp", "tiff", "webp"], binary=True, text=False)
def analyze_vision(state: State, provider="anthropic", api_key=None, model=None, max_image_size=1024, **kwargs) -> State:
    """
    Analyze images using AI vision capabilities.

    Args:
        state: Current puzzle state
        provider: LLM provider to use (anthropic, openai)
        api_key: Optional API key (if not provided, will use environment variables)
        model: Optional model name (specific to the provider)
        max_image_size: Maximum width or height for the image (to reduce token usage)

    Returns:
        Updated state
    """
    logger.info("Starting vision analysis")

    # Check if we have binary data
    if not state.binary_data:
        state.add_insight("No binary image data available for vision analysis", analyzer="vision_analyzer")
        return state

    # Create a VisionAgent
    vision_agent = VisionAgent(
        provider=provider,
        api_key=api_key,
        model=model
    )

    # Check if the vision agent is in fallback mode (no API access)
    if vision_agent.client is None:
        state.add_insight(
            "Vision API not available. Using OpenCV-based analysis instead.",
            analyzer="vision_analyzer"
        )
        # Use OpenCV-based analysis as a fallback
        return analyze_image_with_opencv(state)

    # Integrate vision analysis results with the state
    state = vision_agent.integrate_with_state(state, state.binary_data, max_image_size=max_image_size)

    return state
