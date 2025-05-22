"""
Binwalk analyzer module.
Provides functionality to analyze binary data using binwalk.
"""

from core.state import State
from core.steganography_tools import run_binwalk
from analyzers.base import register_analyzer, analyzer_compatibility

@register_analyzer("binwalk")
@analyzer_compatibility(requires_binary=True)
def analyze_binwalk(state: State) -> State:
    """
    Analyze binary data using binwalk to find embedded files and signatures.

    Args:
        state: Current puzzle state

    Returns:
        Updated state with binwalk analysis insights
    """
    # Skip if no binary data
    if not state.binary_data:
        return state

    state.add_insight("Running binwalk analysis...", analyzer="binwalk")

    # Run binwalk on the binary data
    binwalk_results = run_binwalk(state.binary_data)

    if not binwalk_results.get("success"):
        error_msg = binwalk_results.get("error", "Unknown error")
        state.add_insight(f"Binwalk analysis failed: {error_msg}", analyzer="binwalk")
        return state

    # Add insights for signatures found
    signatures = binwalk_results.get("signatures", [])
    if signatures:
        state.add_insight(f"Binwalk found {len(signatures)} signatures", analyzer="binwalk")
        for sig in signatures:
            state.add_insight(
                f"Binwalk signature at offset {sig['offset']}: {sig['description']}",
                analyzer="binwalk"
            )

    # Add insights for extracted files
    extracted_files = binwalk_results.get("extracted_files", [])
    if extracted_files:
        state.add_insight(f"Binwalk extracted {len(extracted_files)} files", analyzer="binwalk")
        for file in extracted_files:
            state.add_insight(
                f"Binwalk extracted file: {file['name']} ({file['size']} bytes)",
                analyzer="binwalk"
            )
            
            # Add the extracted file to the state's extracted files
            if "extracted_files" not in state.metadata:
                state.metadata["extracted_files"] = []
                
            state.metadata["extracted_files"].append({
                "name": file["name"],
                "data": file["data"],
                "size": file["size"],
                "source": "binwalk"
            })

    return state