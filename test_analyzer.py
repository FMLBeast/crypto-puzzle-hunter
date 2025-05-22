#!/usr/bin/env python
"""
Test script to verify the fix for the text_analyzer issue.
"""

from core.state import State
from analyzers import get_analyzer

def main():
    # Create a state with some text
    state = State()
    state.set_puzzle_text("This is a test puzzle text.")
    
    # Get the text_analyzer
    text_analyzer = get_analyzer("text_analyzer")
    
    # Try to call it with an invalid 'file' parameter
    print("Testing text_analyzer with invalid 'file' parameter...")
    try:
        result_state = text_analyzer(state, file="test.txt")
        print("Success! The analyzer ran without errors.")
        
        # Check if there's a warning insight about the invalid parameter
        warnings = [insight for insight in result_state.insights 
                   if insight.get("analyzer") == "compatibility_check" 
                   and "Warning" in insight.get("text", "")]
        
        if warnings:
            print(f"Found warning insight: {warnings[0]['text']}")
        else:
            print("No warning insight found.")
            
    except Exception as e:
        print(f"Error: {e}")
    
if __name__ == "__main__":
    main()