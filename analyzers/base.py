"""
Base analyzer module for Crypto Hunter

This module provides the base classes and registration mechanism for analyzers.
"""
import inspect
import logging
from typing import Dict, List, Any, Callable, Optional, Set
from functools import wraps

from core.state import State

logger = logging.getLogger(__name__)

# Registry to store all registered analyzers
_ANALYZER_REGISTRY: Dict[str, Callable] = {}


def register_analyzer(name: Optional[str] = None):
    """
    Decorator to register an analyzer function.

    Args:
        name: Optional name for the analyzer. If not provided, the function name is used.

    Returns:
        Decorator function
    """
    def decorator(func: Callable):
        analyzer_name = name or func.__name__
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Log the analyzer execution
            logger.info(f"Running analyzer: {analyzer_name}")
            result = func(*args, **kwargs)
            logger.info(f"Analyzer {analyzer_name} completed")
            return result
        
        # Register the analyzer
        _ANALYZER_REGISTRY[analyzer_name] = wrapper
        logger.debug(f"Registered analyzer: {analyzer_name}")
        
        return wrapper
    
    return decorator


def get_all_analyzers() -> Dict[str, Callable]:
    """
    Get all registered analyzers.

    Returns:
        Dictionary of analyzer name to function
    """
    return _ANALYZER_REGISTRY


def get_analyzer(name: str) -> Optional[Callable]:
    """
    Get a specific analyzer by name.

    Args:
        name: Name of the analyzer

    Returns:
        Analyzer function or None if not found
    """
    return _ANALYZER_REGISTRY.get(name)


def run_analyzer(name: str, state: State, **kwargs) -> State:
    """
    Run a specific analyzer.

    Args:
        name: Name of the analyzer to run
        state: Current puzzle state
        **kwargs: Additional parameters for the analyzer

    Returns:
        Updated state after analysis
    """
    analyzer = get_analyzer(name)
    if not analyzer:
        logger.error(f"Analyzer not found: {name}")
        state.add_insight(f"Analyzer not found: {name}")
        return state
    
    try:
        # Create a clone of the state for the analyzer
        analyzer_state = state.clone()
        
        # Run the analyzer
        logger.debug(f"Starting analyzer: {name}")
        updated_state = analyzer(analyzer_state, **kwargs)
        logger.debug(f"Completed analyzer: {name}")
        
        # Record the analyzer run
        state.record_analyzer_run(name, "success")
        
        # Return the updated state
        return updated_state
    
    except Exception as e:
        logger.error(f"Error running analyzer {name}: {e}")
        state.add_insight(f"Error in analyzer {name}: {str(e)}")
        state.record_analyzer_run(name, f"error: {str(e)}")
        return state


def get_compatible_analyzers(state: State) -> Dict[str, Callable]:
    """
    Get analyzers compatible with the current state.

    Args:
        state: Current puzzle state

    Returns:
        Dictionary of compatible analyzer names to functions
    """
    compatible_analyzers = {}
    
    for name, analyzer in _ANALYZER_REGISTRY.items():
        # Check if the analyzer has a compatibility check function
        if hasattr(analyzer, 'is_compatible') and callable(analyzer.is_compatible):
            if analyzer.is_compatible(state):
                compatible_analyzers[name] = analyzer
        else:
            # If no compatibility check, assume it's compatible
            compatible_analyzers[name] = analyzer
    
    return compatible_analyzers


def analyzer_compatibility(file_types: Optional[List[str]] = None,
                          requires_text: bool = False,
                          requires_binary: bool = False):
    """
    Decorator to specify analyzer compatibility requirements.

    Args:
        file_types: List of compatible file types (extensions)
        requires_text: Whether text data is required
        requires_binary: Whether binary data is required

    Returns:
        Decorator function
    """
    def decorator(func: Callable):
        @wraps(func)
        def is_compatible(state: State) -> bool:
            """Check if the analyzer is compatible with the state."""
            # Check file type compatibility
            if file_types and state.file_type and state.file_type not in file_types:
                logger.debug(f"Analyzer {func.__name__} incompatible: file type {state.file_type} not in {file_types}")
                return False
            
            # Check text data requirement
            if requires_text and not state.puzzle_text:
                logger.debug(f"Analyzer {func.__name__} incompatible: requires text data")
                return False
            
            # Check binary data requirement
            if requires_binary and not state.puzzle_data:
                logger.debug(f"Analyzer {func.__name__} incompatible: requires binary data")
                return False
            
            return True
        
        # Attach the compatibility check to the function
        func.is_compatible = is_compatible
        
        return func
    
    return decorator


# Import and register all analyzers
def load_all_analyzers():
    """
    Import all analyzer modules to register them.
    This function should be called during application initialization.
    """
    # This will be populated during package initialization
    from analyzers import binary_analyzer
    from analyzers import blockchain_analyzer
    from analyzers import cipher_analyzer
    from analyzers import encoding_analyzer
    from analyzers import image_analyzer
    from analyzers import text_analyzer
    
    logger.info(f"Loaded {len(_ANALYZER_REGISTRY)} analyzers")
