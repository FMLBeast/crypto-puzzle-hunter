"""
Test script to verify the fix for the code_agent.py issue.
"""

import logging
import sys
from core.code_agent import CodeAgent, SafeExecutionEnvironment

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_safe_execution():
    """Test the SafeExecutionEnvironment with a simple code snippet."""
    execution_env = SafeExecutionEnvironment()
    
    # Simple code that should work on all platforms
    code = """
def analyze(text="Hello, world!"):
    return {
        "length": len(text),
        "words": len(text.split()),
        "success": True
    }
    
result = analyze()
__output__["result"] = result
"""
    
    result = execution_env.execute(code)
    logger.info(f"Execution result: {result}")
    
    if result.get("success"):
        logger.info("Test passed: SafeExecutionEnvironment works correctly")
    else:
        logger.error(f"Test failed: {result.get('error', 'Unknown error')}")

if __name__ == "__main__":
    logger.info("Testing SafeExecutionEnvironment...")
    test_safe_execution()