#!/usr/bin/env python3
"""
Test script to verify that Arweave tools are registered correctly when an Arweave puzzle is processed.
"""

import os
import sys
from pathlib import Path

from core.state import State
from core.code_agent import CodeAgent
from core.agent import CryptoAgent

def test_arweave_tools_registration():
    """Test that Arweave tools are registered correctly."""
    print("Testing Arweave tools registration...")
    
    # Load the bodhi.html file
    bodhi_path = Path("clues/arweave11/bodhi.html")
    if not bodhi_path.exists():
        print(f"Error: {bodhi_path} not found")
        return False
    
    print(f"Loading {bodhi_path}...")
    with open(bodhi_path, "rb") as f:
        content = f.read()
    
    # Create a State object with the file content
    state = State(puzzle_file=bodhi_path.name)
    state.set_puzzle_text(content.decode("utf-8", errors="replace"))
    
    # Add the Arweave pattern to the state
    arweave_pattern_path = Path("patterns/arweave_series/series_patterns.pattern")
    if arweave_pattern_path.exists():
        print(f"Loading Arweave pattern from {arweave_pattern_path}...")
        with open(arweave_pattern_path, "r") as f:
            pattern_text = f.read()
        state.add_pattern(pattern_text, arweave_pattern_path.name, "arweave")
    
    # Create a CodeAgent object
    print("Creating CodeAgent...")
    llm_agent = CryptoAgent(provider="local")  # Use local provider to avoid API calls
    code_agent = CodeAgent(llm_agent=llm_agent)
    
    # Call the integrate_with_state method
    print("Integrating with state...")
    code_agent.integrate_with_state(state)
    
    # Check if Arweave tools are registered
    print("Checking registered tools...")
    registered_tools = code_agent.tool_registry.list_tools()
    
    # Print the registered tools
    print(f"Registered {len(registered_tools)} tools:")
    for tool in registered_tools:
        print(f"  - {tool['name']}: {tool.get('description', '')}")
    
    # Check if any Arweave tools are registered
    arweave_tools = [tool for tool in registered_tools if "arweave" in tool.get('description', '').lower()]
    if arweave_tools:
        print(f"\nFound {len(arweave_tools)} Arweave tools:")
        for tool in arweave_tools:
            print(f"  - {tool['name']}: {tool.get('description', '')}")
        return True
    else:
        print("\nNo Arweave tools found.")
        return False

if __name__ == "__main__":
    success = test_arweave_tools_registration()
    sys.exit(0 if success else 1)