"""
Vision agent for Crypto Hunter.
Allows the agent to analyze images using AI vision capabilities.
"""

import os
import io
import logging
from typing import Dict, Any, Optional, List
from PIL import Image
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VisionAgent:
    """
    Agent capable of analyzing images using AI vision capabilities.
    """
    def __init__(self, 
                 provider="anthropic",
                 api_key=None,
                 model=None):
        """
        Initialize the VisionAgent.

        Args:
            provider: LLM provider to use (anthropic, openai)
            api_key: Optional API key (if not provided, will use environment variables)
            model: Optional model name (specific to the provider)
        """
        self.provider = provider
        self.api_key = api_key
        self.model = model

        # Check environment variables for API keys
        if not self.api_key:
            if provider == "anthropic":
                self.api_key = os.environ.get("ANTHROPIC_API_KEY")
            elif provider == "openai":
                self.api_key = os.environ.get("OPENAI_API_KEY")

        # Initialize the client based on the provider
        self.client = self._initialize_client()

    def _initialize_client(self):
        """
        Initialize the client based on the provider.

        Returns:
            Client object or None if initialization fails
        """
        try:
            if self.provider == "anthropic":
                from anthropic import Anthropic
                # Use the auth_token parameter instead of api_key
                return Anthropic(auth_token=self.api_key)
            elif self.provider == "openai":
                from openai import OpenAI
                return OpenAI(api_key=self.api_key)
            else:
                logger.error(f"Unsupported provider: {self.provider}")
                return None
        except Exception as e:
            logger.error(f"Error initializing client: {e}")
            return None

    def analyze_image(self, image_data: bytes, max_image_size: int = 1024) -> Dict[str, Any]:
        """
        Analyze an image using AI vision capabilities.

        Args:
            image_data: Binary image data
            max_image_size: Maximum width or height for the image (to reduce token usage)

        Returns:
            Dictionary with analysis results
        """
        if not self.client:
            return {
                "success": False,
                "message": "No client available",
                "data": {}
            }

        try:
            # Convert image to format suitable for the provider
            image = Image.open(io.BytesIO(image_data))

            # Analyze the image based on the provider
            if self.provider == "anthropic":
                return self._analyze_with_anthropic(image, max_image_size=max_image_size)
            elif self.provider == "openai":
                return self._analyze_with_openai(image, max_image_size=max_image_size)
            else:
                return {
                    "success": False,
                    "message": f"Unsupported provider: {self.provider}",
                    "data": {}
                }
        except Exception as e:
            logger.error(f"Error analyzing image: {e}")
            return {
                "success": False,
                "message": f"Error analyzing image: {str(e)}",
                "data": {}
            }

    def _analyze_with_anthropic(self, image: Image.Image, max_image_size: int = 1024) -> Dict[str, Any]:
        """
        Analyze an image using Anthropic's Claude.

        Args:
            image: PIL Image object
            max_image_size: Maximum width or height for the image

        Returns:
            Dictionary with analysis results
        """
        try:
            # Resize the image if it's too large to reduce token count
            resized_image = self._resize_image_if_needed(image, max_size=max_image_size)

            # Convert image to base64
            buffered = io.BytesIO()
            resized_image.save(buffered, format="JPEG", quality=85)
            img_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

            # Create the message
            response = self.client.messages.create(
                model=self.model or "claude-3-opus-20240229",
                max_tokens=1000,
                temperature=0.2,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": "Analyze this image in detail. Look for any text, symbols, patterns, or hidden information that might be relevant to a cryptographic puzzle. Consider steganography, encoded messages, QR codes, or other forms of hidden data."
                            },
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": "image/png",
                                    "data": img_base64
                                }
                            }
                        ]
                    }
                ]
            )

            return {
                "success": True,
                "message": "Image analyzed successfully",
                "data": {
                    "analysis": response.content[0].text,
                    "model": response.model,
                    "id": response.id
                }
            }
        except Exception as e:
            logger.error(f"Error analyzing with Anthropic: {e}")
            return {
                "success": False,
                "message": f"Error analyzing with Anthropic: {str(e)}",
                "data": {}
            }

    def _resize_image_if_needed(self, image: Image.Image, max_size: int = 1024) -> Image.Image:
        """
        Resize an image if it's too large, maintaining aspect ratio.

        Args:
            image: PIL Image object
            max_size: Maximum width or height

        Returns:
            Resized PIL Image object
        """
        width, height = image.size

        # If the image is already small enough, return it as is
        if width <= max_size and height <= max_size:
            return image

        # Calculate the new dimensions while maintaining aspect ratio
        if width > height:
            new_width = max_size
            new_height = int(height * (max_size / width))
        else:
            new_height = max_size
            new_width = int(width * (max_size / height))

        # Resize the image
        resized_image = image.resize((new_width, new_height), Image.LANCZOS)

        logger.info(f"Resized image from {width}x{height} to {new_width}x{new_height}")
        return resized_image

    def _analyze_with_openai(self, image: Image.Image, max_image_size: int = 1024) -> Dict[str, Any]:
        """
        Analyze an image using OpenAI's GPT-4 Vision.

        Args:
            image: PIL Image object
            max_image_size: Maximum width or height for the image

        Returns:
            Dictionary with analysis results
        """
        try:
            # Resize the image if it's too large to reduce token count
            resized_image = self._resize_image_if_needed(image, max_size=max_image_size)

            # Convert image to base64
            buffered = io.BytesIO()
            resized_image.save(buffered, format="JPEG", quality=85)
            img_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

            # Create the message
            response = self.client.chat.completions.create(
                model=self.model or "gpt-4o",
                temperature=0.2,
                max_tokens=1000,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": "Analyze this image in detail. Look for any text, symbols, patterns, or hidden information that might be relevant to a cryptographic puzzle. Consider steganography, encoded messages, QR codes, or other forms of hidden data."
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{img_base64}"
                                }
                            }
                        ]
                    }
                ]
            )

            return {
                "success": True,
                "message": "Image analyzed successfully",
                "data": {
                    "analysis": response.choices[0].message.content,
                    "model": response.model,
                    "id": response.id
                }
            }
        except Exception as e:
            logger.error(f"Error analyzing with OpenAI: {e}")
            return {
                "success": False,
                "message": f"Error analyzing with OpenAI: {str(e)}",
                "data": {}
            }

    def integrate_with_state(self, state, image_data: bytes, max_image_size: int = 1024) -> Any:
        """
        Integrate vision analysis results with the puzzle state.

        Args:
            state: Current puzzle state
            image_data: Binary image data
            max_image_size: Maximum width or height for the image (to reduce token usage)

        Returns:
            Updated state
        """
        analysis = self.analyze_image(image_data, max_image_size=max_image_size)

        if not analysis["success"]:
            state.add_insight(f"Vision analysis failed: {analysis['message']}", analyzer="vision_agent")
            return state

        # Add insights from vision analysis
        state.add_insight(
            f"Vision analysis completed successfully",
            analyzer="vision_agent"
        )

        # Add detailed analysis
        analysis_text = analysis["data"]["analysis"]

        # Add the analysis as an insight
        state.add_insight(
            f"Vision analysis: {analysis_text[:200]}...",
            analyzer="vision_agent"
        )

        # Add the full analysis as a transformation
        state.add_transformation(
            name="Vision Analysis",
            description="AI vision analysis of the image",
            input_data="Image data",
            output_data=analysis_text,
            analyzer="vision_agent"
        )

        return state
