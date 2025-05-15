"""
Arweave Puzzle Series Tools Module - Main

This module imports and combines all the tools from the Arweave Puzzle Series tools modules.
"""

# Import tools from part 1 (Puzzle Weave 1)
from core.arweave_tools import (
    algebra_solver,
    beep_pattern_finder,
    riddle_lookup,
    coordinate_calculator
)

# Import tools from part 2 (Puzzle Weave 2)
from core.arweave_tools_part2 import (
    arweave_fetch,
    steganalysis,
    calculate_entropy,
    extract_lsb,
    is_meaningful_data,
    extract_metadata,
    extract_strings
)

# Import steganography tools
from core.steganography_tools import (
    extract_image_lsb,
    extract_appended_data,
    analyze_audio_spectrogram,
    analyze_zero_width_chars,
    extract_first_letters,
    find_embedded_files,
    analyze_stego
)

# Import tools from part 3 (Puzzle Weave 4 and 8)
from core.arweave_tools_part3 import (
    linear_program_solver,
    combinatorics_calculator,
    knowledge_graph_query,
    timeline_analyzer,
    file_type_router
)

# Dictionary of all available tools
ARWEAVE_TOOLS = {
    # Puzzle Weave 1 Tools
    "algebra_solver": {
        "function": algebra_solver,
        "description": "Set up and solve linear systems automatically",
        "category": "Puzzle Weave 1"
    },
    "beep_pattern_finder": {
        "function": beep_pattern_finder,
        "description": "Find specific events in time-based patterns",
        "category": "Puzzle Weave 1"
    },
    "riddle_lookup": {
        "function": riddle_lookup,
        "description": "Look up common riddles in a database",
        "category": "Puzzle Weave 1"
    },
    "coordinate_calculator": {
        "function": coordinate_calculator,
        "description": "Perform calculations on geographic coordinates",
        "category": "Puzzle Weave 1"
    },

    # Puzzle Weave 2 Tools
    "arweave_fetch": {
        "function": arweave_fetch,
        "description": "Fetch transaction data from Arweave",
        "category": "Puzzle Weave 2"
    },
    "steganalysis": {
        "function": steganalysis,
        "description": "Analyze files for steganographic content",
        "category": "Puzzle Weave 2"
    },

    # Puzzle Weave 4 Tools
    "linear_program_solver": {
        "function": linear_program_solver,
        "description": "Solve linear programming problems",
        "category": "Puzzle Weave 4"
    },
    "combinatorics_calculator": {
        "function": combinatorics_calculator,
        "description": "Calculate combinatorial probabilities",
        "category": "Puzzle Weave 4"
    },

    # Puzzle Weave 8 Tools
    "knowledge_graph_query": {
        "function": knowledge_graph_query,
        "description": "Query a knowledge graph for information",
        "category": "Puzzle Weave 8"
    },
    "timeline_analyzer": {
        "function": timeline_analyzer,
        "description": "Analyze timeline of events to find patterns or matches",
        "category": "Puzzle Weave 8"
    },
    "file_type_router": {
        "function": file_type_router,
        "description": "Detect file type and route to appropriate analysis pipeline",
        "category": "Puzzle Weave 13"
    },

    # Steganography Tools
    "analyze_stego": {
        "function": analyze_stego,
        "description": "Comprehensive steganography analysis for various file types",
        "category": "Steganography"
    },
    "extract_image_lsb": {
        "function": extract_image_lsb,
        "description": "Extract least significant bits from image data",
        "category": "Steganography"
    },
    "extract_appended_data": {
        "function": extract_appended_data,
        "description": "Extract data appended after file EOF markers",
        "category": "Steganography"
    },
    "analyze_audio_spectrogram": {
        "function": analyze_audio_spectrogram,
        "description": "Analyze audio file for hidden data in spectrogram",
        "category": "Steganography"
    },
    "analyze_zero_width_chars": {
        "function": analyze_zero_width_chars,
        "description": "Analyze text for zero-width characters that might hide data",
        "category": "Steganography"
    },
    "extract_first_letters": {
        "function": extract_first_letters,
        "description": "Extract first letters from lines or paragraphs to find hidden messages",
        "category": "Steganography"
    },
    "find_embedded_files": {
        "function": find_embedded_files,
        "description": "Find embedded files within binary data",
        "category": "Steganography"
    }
}

def get_tool(tool_name):
    """Get a tool by name."""
    return ARWEAVE_TOOLS.get(tool_name, {}).get("function")

def list_tools():
    """List all available tools."""
    return [
        {
            "name": name,
            "description": info["description"],
            "category": info["category"]
        }
        for name, info in ARWEAVE_TOOLS.items()
    ]

def get_tools_by_category(category):
    """Get all tools in a specific category."""
    return [
        {
            "name": name,
            "description": info["description"]
        }
        for name, info in ARWEAVE_TOOLS.items()
        if info["category"] == category
    ]

def register_arweave_tools_with_agent(code_agent):
    """Register all Arweave tools with the CodeAgent."""
    registered_tools = []

    for name, info in ARWEAVE_TOOLS.items():
        # Get the source code of the function
        import inspect
        function = info["function"]
        source_code = inspect.getsource(function)

        # Register the tool with the CodeAgent
        tool_id = code_agent.tool_registry.register_tool(
            source_code,
            name=name,
            description=info["description"]
        )

        if tool_id:
            registered_tools.append({
                "name": name,
                "tool_id": tool_id,
                "description": info["description"],
                "category": info["category"]
            })

    return registered_tools
