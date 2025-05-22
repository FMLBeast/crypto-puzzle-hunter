"""
Web analyzer for Crypto Hunter.
Integrates the WebAgent into the analysis flow.
"""

import re
import logging
from typing import Dict, Any, Optional, List
from core.state import State
from core.web_agent import WebAgent
from analyzers.base import register_analyzer, analyzer_compatibility

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@register_analyzer("web_analyzer")
@analyzer_compatibility(file_types=["*"], binary=True, text=True)
def analyze_web(state: State, query: str = None, **kwargs) -> State:
    """
    Analyze web content related to the puzzle.
    
    Args:
        state: Current puzzle state
        query: Optional search query (if not provided, will be generated from the puzzle content)
        
    Returns:
        Updated state
    """
    logger.info("Starting web analysis")
    
    # Create a WebAgent
    web_agent = WebAgent()
    
    # Generate a search query if not provided
    if not query:
        query = _generate_search_query(state)
    
    logger.info(f"Using search query: {query}")
    
    # Integrate web browsing results with the state
    state = web_agent.integrate_with_state(state, query)
    
    return state

def _generate_search_query(state: State) -> str:
    """
    Generate a search query based on the puzzle content.
    
    Args:
        state: Current puzzle state
        
    Returns:
        Search query
    """
    # Start with the puzzle file name
    query_parts = [state.puzzle_file]
    
    # Add keywords from insights
    keywords = set()
    for insight in state.insights:
        text = insight.get("text", "")
        # Extract potential keywords (nouns, technical terms)
        words = re.findall(r'\b[A-Z][a-z]{2,}\b|\b[a-z]{3,}\b', text)
        for word in words:
            if len(word) > 3 and word.lower() not in ["this", "that", "with", "from", "have", "been"]:
                keywords.add(word)
    
    # Add the most relevant keywords (up to 5)
    query_parts.extend(list(keywords)[:5])
    
    # Add "cryptographic puzzle" to focus the search
    query_parts.append("cryptographic puzzle")
    
    # Join the parts with spaces
    query = " ".join(query_parts)
    
    # Limit the query length
    if len(query) > 100:
        query = query[:100]
    
    return query