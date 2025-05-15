"""
Utility functions for the Crypto Hunter application.
"""

import os
import logging
from pathlib import Path
from collections import defaultdict

def browse_puzzles(puzzles_dir):
    """Browse the available puzzles in the directory."""
    puzzles_path = Path(puzzles_dir)
    if not puzzles_path.exists():
        return {}

    categories = defaultdict(list)

    # Look for puzzle directories
    for item in puzzles_path.glob("*"):
        if item.is_dir():
            category = item.name

            # Find all puzzle files in the category
            for puzzle_file in item.glob("*"):
                if puzzle_file.is_file() or puzzle_file.is_dir():
                    categories[category].append(str(puzzle_file))

    return categories

def get_puzzle_info(puzzle_path):
    """Get information about a puzzle file."""
    path = Path(puzzle_path)

    if path.is_dir():
        # Count files in the directory
        files = list(path.glob("*"))
        size = sum(f.stat().st_size for f in files if f.is_file())

        # Check if there's a clue folder with the same name
        clues_dir = Path("clues") / path.name
        has_clue = clues_dir.exists() and clues_dir.is_dir()
    else:
        # Single file
        size = path.stat().st_size

        # Check if there's a clue folder with the same name
        parent_cat = path.parent.name
        clues_dir = Path("clues") / parent_cat
        has_clue = clues_dir.exists() and clues_dir.is_dir()

    return {
        "path": str(path),
        "size": size,
        "has_clue": has_clue
    }

def find_clues(puzzle_path):
    """
    Find clues associated with a puzzle.
    Looks for clues in the 'clues' directory with the same name as the puzzle category.

    Args:
        puzzle_path: Path to the puzzle file or directory

    Returns:
        List of clue file paths
    """
    path = Path(puzzle_path)

    # Determine the category name
    if path.is_dir():
        category = path.name
    else:
        category = path.parent.name

    # Look for clues in the clues directory
    clues_dir = Path("clues") / category
    if clues_dir.exists() and clues_dir.is_dir():
        return [str(clue_file) for clue_file in clues_dir.glob("*") if clue_file.is_file()]

    return []

def load_clues(puzzle_path):
    """
    Load clues associated with a puzzle.

    Args:
        puzzle_path: Path to the puzzle file or directory

    Returns:
        List of clue dictionaries with 'text' and 'file' keys
    """
    clue_files = find_clues(puzzle_path)
    clues = []

    for clue_file in clue_files:
        try:
            with open(clue_file, 'r', errors='replace') as f:
                clue_text = f.read()
                clues.append({
                    "text": clue_text,
                    "file": clue_file
                })
        except Exception as e:
            logging.error(f"Error loading clue {clue_file}: {e}")
            # Try as binary
            try:
                with open(clue_file, 'rb') as f:
                    clue_data = f.read()
                    clues.append({
                        "text": f"Binary clue file ({len(clue_data)} bytes)",
                        "file": clue_file,
                        "binary": True,
                        "data": clue_data
                    })
            except Exception as e2:
                logging.error(f"Error loading binary clue {clue_file}: {e2}")

    return clues

def find_patterns(puzzle_path):
    """
    Find patterns associated with a puzzle.
    Looks for patterns in the 'patterns' directory with the same name as the puzzle category,
    as well as generic patterns that apply to all puzzles.

    Args:
        puzzle_path: Path to the puzzle file or directory

    Returns:
        List of pattern file paths
    """
    path = Path(puzzle_path)

    # Determine the category name
    if path.is_dir():
        category = path.name
    else:
        category = path.parent.name

    pattern_files = []

    # Look for category-specific patterns
    category_patterns_dir = Path("patterns") / category
    if category_patterns_dir.exists() and category_patterns_dir.is_dir():
        pattern_files.extend([str(pattern_file) for pattern_file in category_patterns_dir.glob("*.pattern") if pattern_file.is_file()])

    # Also look for generic patterns
    generic_patterns_dir = Path("patterns/generic")
    if generic_patterns_dir.exists() and generic_patterns_dir.is_dir():
        pattern_files.extend([str(pattern_file) for pattern_file in generic_patterns_dir.glob("*.pattern") if pattern_file.is_file()])

    return pattern_files

def load_patterns(puzzle_path):
    """
    Load patterns associated with a puzzle.

    Args:
        puzzle_path: Path to the puzzle file or directory

    Returns:
        List of pattern dictionaries with 'text', 'file', and 'category' keys
    """
    pattern_files = find_patterns(puzzle_path)
    patterns = []

    for pattern_file in pattern_files:
        try:
            with open(pattern_file, 'r', errors='replace') as f:
                pattern_text = f.read()
                # Determine the category from the file path
                pattern_path = Path(pattern_file)
                category = pattern_path.parent.name

                patterns.append({
                    "text": pattern_text,
                    "file": pattern_file,
                    "category": category
                })
        except Exception as e:
            logging.error(f"Error loading pattern {pattern_file}: {e}")

    return patterns

def setup_logging(verbose=False):
    """Set up logging for the application."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
