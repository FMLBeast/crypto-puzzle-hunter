"""
Code analyzer for Crypto Hunter.
Integrates the CodingAgent into the analysis flow.
"""

import logging
from typing import Dict, Any, Optional, List
from core.state import State
from core.coding_agent import CodingAgent
from analyzers.base import register_analyzer, analyzer_compatibility

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@register_analyzer("code_analyzer")
@analyzer_compatibility(file_types=["*"], binary=True, text=True)
def analyze_code(state: State, task_description: str = None, **kwargs) -> State:
    """
    Analyze the puzzle using Python code generation and execution.
    
    Args:
        state: Current puzzle state
        task_description: Optional task description for code generation
        
    Returns:
        Updated state
    """
    logger.info("Starting code-based analysis")
    
    # Create a CodingAgent
    coding_agent = CodingAgent()
    
    # Generate a task description if not provided
    if not task_description:
        task_description = _generate_task_description(state)
    
    logger.info(f"Using task description: {task_description}")
    
    # Generate code for the task
    code = coding_agent.generate_code(task_description, state)
    
    # Prepare inputs for code execution
    inputs = {
        "state": state,
        "text": state.puzzle_text if state.puzzle_text else "",
        "binary_data": state.binary_data if state.binary_data else b"",
        "filename": state.puzzle_file
    }
    
    # Execute the code
    result = coding_agent.execute_code(code, inputs)
    
    # Process the results
    if result.get('success'):
        # Extract analysis results
        output = result.get('result', {})
        
        # Add insights from the analysis
        for key, value in output.items():
            if key not in ['success', 'error'] and not key.startswith('_'):
                state.add_insight(f"Code analysis - {key}: {value}", 
                                analyzer="code_analyzer")
        
        # Check if solution was found
        if 'solution' in output:
            solution = output['solution']
            state.add_insight(f"Potential solution found: {solution}", 
                            analyzer="code_analyzer")
            
            # Set the solution if it seems valid
            if _verify_solution(solution):
                state.set_solution(solution)
    else:
        # Log execution error
        error = result.get('error', 'Unknown error')
        state.add_insight(f"Code analysis failed: {error}", 
                        analyzer="code_analyzer")
    
    return state

def _generate_task_description(state: State) -> str:
    """
    Generate a task description based on the puzzle state.
    
    Args:
        state: Current puzzle state
        
    Returns:
        Task description
    """
    # Start with a basic task description
    task = "Analyze this puzzle and try to find a solution"
    
    # Add file type specific instructions
    if state.puzzle_file:
        file_ext = state.puzzle_file.split('.')[-1].lower() if '.' in state.puzzle_file else ""
        
        if file_ext in ['txt', 'md', 'log', 'csv', 'json', 'xml', 'html']:
            task = f"Analyze this text file for hidden messages, ciphers, or encodings"
        elif file_ext in ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp']:
            task = f"Analyze this image file for steganography or hidden visual patterns"
        elif file_ext in ['bin', 'dat', 'exe', 'dll']:
            task = f"Analyze this binary file for hidden data or unusual patterns"
    
    # Add information from insights
    if state.insights:
        # Extract keywords from insights
        keywords = set()
        for insight in state.insights:
            text = insight.get("text", "").lower()
            if "base64" in text:
                keywords.add("base64")
            if "xor" in text:
                keywords.add("xor")
            if "caesar" in text or "rot13" in text:
                keywords.add("caesar cipher")
            if "hash" in text or "sha" in text or "md5" in text:
                keywords.add("hash")
            if "frequency" in text:
                keywords.add("frequency analysis")
            if "steganography" in text or "steg" in text:
                keywords.add("steganography")
        
        # Add keywords to task description
        if keywords:
            task += f" focusing on {', '.join(keywords)}"
    
    return task

def _verify_solution(solution: str) -> bool:
    """
    Perform basic verification of a potential solution.
    
    Args:
        solution: Potential solution
        
    Returns:
        True if the solution seems valid, False otherwise
    """
    # Skip empty or very short solutions
    if not solution or len(solution) < 3:
        return False
    
    # Skip solutions that are just error messages
    error_indicators = ["error", "exception", "failed", "not found", "undefined"]
    if any(indicator in solution.lower() for indicator in error_indicators):
        return False
    
    # Accept solutions that look reasonable
    return True