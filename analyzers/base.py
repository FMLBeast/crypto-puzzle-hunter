"""
Base module for analyzers.
Provides registration mechanisms and utility functions.
"""

import functools
import inspect
from typing import Dict, Callable, Any, List

# Registry of analyzers
_ANALYZERS = {}

def register_analyzer(name):
    """
    Decorator to register an analyzer function.

    Args:
        name: Name of the analyzer

    Returns:
        Decorator function
    """
    def decorator(func):
        _ANALYZERS[name] = func
        return func
    return decorator

def analyzer_compatibility(**kwargs):
    """
    Decorator to specify analyzer compatibility requirements.

    Args:
        **kwargs: Compatibility requirements (e.g., requires_text=True)

    Returns:
        Decorator function
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(state, **func_kwargs):
            # Check compatibility
            if kwargs.get('requires_text', False) and not state.puzzle_text:
                state.add_insight(
                    f"Skipping {func.__name__} as it requires text content",
                    analyzer="compatibility_check"
                )
                return state

            if kwargs.get('requires_binary', False) and not state.binary_data:
                state.add_insight(
                    f"Skipping {func.__name__} as it requires binary content",
                    analyzer="compatibility_check"
                )
                return state

            # Check if the function accepts **kwargs
            sig = inspect.signature(func)
            has_var_keyword = any(
                param.kind == inspect.Parameter.VAR_KEYWORD
                for param in sig.parameters.values()
            )

            if has_var_keyword:
                # Function accepts **kwargs, so pass all parameters through
                valid_params = func_kwargs
            else:
                # Filter out any parameters that aren't accepted by the analyzer function
                valid_params = {}
                for param_name, param in func_kwargs.items():
                    if param_name in sig.parameters:
                        valid_params[param_name] = param
                    else:
                        state.add_insight(
                            f"Warning: Parameter '{param_name}' is not accepted by {func.__name__} and will be ignored",
                            analyzer="compatibility_check"
                        )

            # If all requirements are met, run the analyzer with valid parameters
            return func(state, **valid_params)

        # Copy compatibility info to the wrapper function
        wrapper._compatibility = kwargs

        return wrapper
    return decorator

def get_analyzer(name: str) -> Callable:
    """
    Get an analyzer by name.

    Args:
        name: Name of the analyzer

    Returns:
        Analyzer function
    """
    return _ANALYZERS.get(name)

def get_all_analyzers() -> Dict[str, Callable]:
    """
    Get all registered analyzers.

    Returns:
        Dictionary of analyzer names to functions
    """
    return _ANALYZERS

def get_compatible_analyzers(state) -> List[str]:
    """
    Get names of analyzers compatible with the current state.

    Args:
        state: Current puzzle state

    Returns:
        List of compatible analyzer names
    """
    compatible = []

    for name, func in _ANALYZERS.items():
        # Check if the analyzer has compatibility requirements
        if hasattr(func, '_compatibility'):
            requirements = getattr(func, '_compatibility')

            # Check if all requirements are met
            if requirements.get('requires_text', False) and not state.puzzle_text:
                continue

            if requirements.get('requires_binary', False) and not state.binary_data:
                continue

        # If we reach here, the analyzer is compatible
        compatible.append(name)

    return compatible