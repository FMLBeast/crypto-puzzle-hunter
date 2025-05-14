#!/usr/bin/env python3
"""
Crypto Hunter - Main Entry Point

A modern tool for analyzing and solving cryptographic puzzles using
AI and specialized analyzers.
"""
import argparse
import os
import sys
import glob
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# Add the project root to the sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.state import State
from core.agent import CryptoAgent
from ui.cli import display_banner, display_results, setup_logging, print_success, print_error, print_warning, console
from ui.interactive import InteractiveSession
import config
from analyzers.base import get_all_analyzers
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Crypto Hunter - AI-powered cryptography puzzle solver"
    )
    parser.add_argument(
        "--puzzle-file", type=str, help="Path to the puzzle file to analyze"
    )
    parser.add_argument(
        "--puzzle-dir",
        type=str,
        default="./puzzles",
        help="Directory containing puzzles to browse",
    )
    parser.add_argument(
        "--browse-puzzles",
        action="store_true",
        help="Browse available puzzles",
    )
    parser.add_argument(
        "--use-clues",
        action="store_true",
        help="Use clues if available",
    )
    parser.add_argument(
        "--interactive", action="store_true", help="Run in interactive mode"
    )
    parser.add_argument(
        "--iterations", type=int, default=10, help="Maximum number of analysis iterations"
    )
    parser.add_argument(
        "--results-dir",
        type=str,
        default="./results",
        help="Directory to store results",
    )
    parser.add_argument(
        "--clues-dir",
        type=str,
        default="./clues",
        help="Directory containing clues",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--analyzer",
        type=str,
        choices=get_all_analyzers().keys(),
        help="Specify a particular analyzer to use",
    )
    parser.add_argument(
        "--llm-provider",
        type=str,
        default="anthropic",
        choices=["anthropic", "openai"],
        help="LLM provider to use",
    )
    parser.add_argument(
        "--save-state", action="store_true", help="Save state between runs"
    )
    return parser.parse_args()


def ensure_dir_exists(directory):
    """Ensure that the specified directory exists."""
    Path(directory).mkdir(parents=True, exist_ok=True)


def find_puzzles(puzzle_dir: str) -> Dict[str, List[str]]:
    """
    Find puzzle files in the specified directory and its subdirectories.
    
    Args:
        puzzle_dir: Directory to search
        
    Returns:
        Dictionary mapping category names to lists of puzzle files
    """
    if not os.path.exists(puzzle_dir):
        print_warning(f"Puzzle directory not found: {puzzle_dir}")
        # Create the directory structure
        ensure_dir_exists(puzzle_dir)
        ensure_dir_exists(os.path.join(puzzle_dir, "beginner"))
        ensure_dir_exists(os.path.join(puzzle_dir, "intermediate"))
        ensure_dir_exists(os.path.join(puzzle_dir, "advanced"))
        print_success(f"Created puzzle directory structure in {puzzle_dir}")
        return {}
    
    # Find all directories in puzzle_dir
    categories = [d for d in os.listdir(puzzle_dir) 
                if os.path.isdir(os.path.join(puzzle_dir, d))]
    
    # If no categories, check if there are puzzles directly in the puzzle_dir
    if not categories:
        puzzle_files = glob.glob(os.path.join(puzzle_dir, "*.*"))
        if puzzle_files:
            return {"uncategorized": puzzle_files}
        return {}
    
    # Find puzzles in each category
    puzzles_by_category = {}
    for category in categories:
        category_path = os.path.join(puzzle_dir, category)
        puzzle_files = glob.glob(os.path.join(category_path, "*.*"))
        if puzzle_files:
            puzzles_by_category[category] = puzzle_files
    
    return puzzles_by_category


def find_clue(puzzle_file: str, clues_dir: str) -> Optional[str]:
    """
    Find a clue file corresponding to a puzzle file.
    
    Args:
        puzzle_file: Path to the puzzle file
        clues_dir: Directory containing clues
        
    Returns:
        Path to the clue file if found, None otherwise
    """
    if not os.path.exists(clues_dir):
        return None
    
    # Get puzzle filename without extension
    puzzle_name = os.path.splitext(os.path.basename(puzzle_file))[0]
    
    # Look for clue files with the same name but different extensions
    possible_clue_files = [
        os.path.join(clues_dir, f"{puzzle_name}.clue"),
        os.path.join(clues_dir, f"{puzzle_name}.txt"),
        os.path.join(clues_dir, f"{puzzle_name}_clue.txt"),
    ]
    
    for clue_file in possible_clue_files:
        if os.path.exists(clue_file):
            return clue_file
    
    # Look for clue files in a subdirectory matching the puzzle's directory structure
    puzzle_rel_path = os.path.relpath(os.path.dirname(puzzle_file), 
                                    start=os.path.dirname(os.path.dirname(puzzle_file)))
    clue_subdir = os.path.join(clues_dir, puzzle_rel_path)
    
    if os.path.exists(clue_subdir):
        possible_subdir_clue_files = [
            os.path.join(clue_subdir, f"{puzzle_name}.clue"),
            os.path.join(clue_subdir, f"{puzzle_name}.txt"),
            os.path.join(clue_subdir, f"{puzzle_name}_clue.txt"),
        ]
        
        for clue_file in possible_subdir_clue_files:
            if os.path.exists(clue_file):
                return clue_file
    
    return None


def browse_puzzles(puzzle_dir: str, clues_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Allow the user to browse and select a puzzle.
    
    Args:
        puzzle_dir: Directory containing puzzles
        clues_dir: Directory containing clues
        
    Returns:
        Tuple of (selected puzzle file path, clue file path or None)
    """
    puzzles_by_category = find_puzzles(puzzle_dir)
    
    if not puzzles_by_category:
        print_warning(f"No puzzles found in {puzzle_dir}")
        print("You can add puzzles to the following directories:")
        print(f"  {puzzle_dir}/beginner/")
        print(f"  {puzzle_dir}/intermediate/")
        print(f"  {puzzle_dir}/advanced/")
        return None, None
    
    # Display available categories
    console.print("\n[bold cyan]Available Puzzle Categories:[/bold cyan]")
    
    categories_table = Table(box=box.ROUNDED)
    categories_table.add_column("#", style="dim")
    categories_table.add_column("Category", style="cyan")
    categories_table.add_column("Puzzles", style="green")
    
    for i, (category, puzzles) in enumerate(puzzles_by_category.items(), 1):
        categories_table.add_row(
            str(i),
            category,
            str(len(puzzles))
        )
    
    console.print(categories_table)
    
    # Let user select a category
    valid_indices = list(range(1, len(puzzles_by_category) + 1))
    
    if not valid_indices:
        return None, None
    
    category_index = int(Prompt.ask(
        "Select a category (number)",
        choices=[str(i) for i in valid_indices],
        default="1"
    ))
    
    selected_category = list(puzzles_by_category.keys())[category_index - 1]
    puzzles = puzzles_by_category[selected_category]
    
    # Display puzzles in the selected category
    console.print(f"\n[bold cyan]Puzzles in category '{selected_category}':[/bold cyan]")
    
    puzzles_table = Table(box=box.ROUNDED)
    puzzles_table.add_column("#", style="dim")
    puzzles_table.add_column("Puzzle", style="green")
    puzzles_table.add_column("Size", style="blue")
    puzzles_table.add_column("Has Clue", style="magenta")
    
    for i, puzzle_file in enumerate(puzzles, 1):
        puzzle_name = os.path.basename(puzzle_file)
        size = os.path.getsize(puzzle_file)
        size_str = f"{size} bytes"
        
        # Check if there's a clue file
        clue_file = find_clue(puzzle_file, clues_dir)
        has_clue = "[green]Yes[/green]" if clue_file else "[red]No[/red]"
        
        puzzles_table.add_row(
            str(i),
            puzzle_name,
            size_str,
            has_clue
        )
    
    console.print(puzzles_table)
    
    # Let user select a puzzle
    puzzle_index = int(Prompt.ask(
        "Select a puzzle (number)",
        choices=[str(i) for i in range(1, len(puzzles) + 1)],
        default="1"
    ))
    
    selected_puzzle = puzzles[puzzle_index - 1]
    clue_file = find_clue(selected_puzzle, clues_dir)
    
    # Ask if they want to use the clue (if available)
    use_clue = False
    if clue_file:
        use_clue = Confirm.ask("This puzzle has a clue available. Do you want to use it?")
    
    return selected_puzzle, clue_file if use_clue else None


def process_puzzle(puzzle_file: str, clue_file: Optional[str], agent: CryptoAgent, 
                  analyzer: Optional[str], iterations: int, results_dir: str) -> int:
    """
    Process a puzzle file with optional clue.
    
    Args:
        puzzle_file: Path to the puzzle file
        clue_file: Path to the clue file (or None)
        agent: CryptoAgent instance
        analyzer: Specific analyzer to use (or None for all)
        iterations: Maximum number of iterations
        results_dir: Directory to save results
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    if not os.path.exists(puzzle_file):
        print_error(f"File not found: {puzzle_file}")
        return 1
    
    # Initialize state with the puzzle file
    state = State(puzzle_file=puzzle_file)
    
    # Add clue if available
    if clue_file and os.path.exists(clue_file):
        try:
            with open(clue_file, 'r') as f:
                clue_text = f.read()
            
            console.print("\n[bold cyan]Clue Information:[/bold cyan]")
            console.print(clue_text)
            console.print()
            
            # Add clue to state metadata
            state.metadata["clue"] = clue_text
            state.add_insight(
                f"Clue provided: {clue_text[:100]}{'...' if len(clue_text) > 100 else ''}",
                analyzer="user"
            )
        except Exception as e:
            print_warning(f"Error reading clue file: {e}")
    
    # Run the analysis
    if analyzer:
        # Run a specific analyzer
        analyzers = {analyzer: get_all_analyzers()[analyzer]}
        final_state = agent.analyze(
            state, analyzers=analyzers, max_iterations=iterations
        )
    else:
        # Run all analyzers
        final_state = agent.analyze(
            state, max_iterations=iterations
        )
    
    # Display and save results
    display_results(final_state)
    results_file = os.path.join(results_dir, f"{os.path.basename(puzzle_file)}_result.json")
    final_state.save(results_file)
    
    # Copy solution to clipboard if available
    if final_state.solution:
        try:
            import pyperclip
            pyperclip.copy(final_state.solution)
            print_success("Solution copied to clipboard!")
        except ImportError:
            print_warning("Install pyperclip to enable copying to clipboard.")
    
    return 0


def main():
    """Main entry point for Crypto Hunter."""
    args = parse_arguments()
    
    # Setup logging and display banner
    setup_logging(verbose=args.verbose)
    display_banner()
    
    # Ensure directories exist
    ensure_dir_exists(args.results_dir)
    ensure_dir_exists(args.puzzle_dir)
    ensure_dir_exists(args.clues_dir)
    
    # Create crypto agent with appropriate LLM
    agent = CryptoAgent(provider=args.llm_provider)
    
    if args.interactive:
        # Run interactive session
        session = InteractiveSession(
            agent=agent, 
            results_dir=args.results_dir,
            puzzle_dir=args.puzzle_dir,
            clues_dir=args.clues_dir
        )
        session.start()
    elif args.browse_puzzles:
        # Browse and select a puzzle
        selected_puzzle, clue_file = browse_puzzles(args.puzzle_dir, args.clues_dir)
        
        if selected_puzzle:
            return process_puzzle(
                selected_puzzle,
                clue_file,
                agent,
                args.analyzer,
                args.iterations,
                args.results_dir
            )
        else:
            print_warning("No puzzle selected.")
            return 1
    elif args.puzzle_file:
        # Find clue if requested
        clue_file = None
        if args.use_clues:
            clue_file = find_clue(args.puzzle_file, args.clues_dir)
        
        # Process the specified puzzle file
        return process_puzzle(
            args.puzzle_file,
            clue_file,
            agent,
            args.analyzer,
            args.iterations,
            args.results_dir
        )
    else:
        # If no specific mode was requested, prompt the user to select one
        console.print("\n[bold cyan]Welcome to Crypto Hunter![/bold cyan]")
        console.print("Please select how you would like to proceed:\n")
        
        options = [
            "Browse puzzle collection",
            "Interactive mode",
            "Exit"
        ]
        
        for i, option in enumerate(options, 1):
            console.print(f"  {i}. {option}")
        
        choice = Prompt.ask(
            "\nSelect an option",
            choices=["1", "2", "3"],
            default="1"
        )
        
        if choice == "1":
            # Browse puzzles
            selected_puzzle, clue_file = browse_puzzles(args.puzzle_dir, args.clues_dir)
            
            if selected_puzzle:
                return process_puzzle(
                    selected_puzzle,
                    clue_file,
                    agent,
                    args.analyzer,
                    args.iterations,
                    args.results_dir
                )
            else:
                print_warning("No puzzle selected.")
                return 1
        elif choice == "2":
            # Interactive mode
            session = InteractiveSession(
                agent=agent, 
                results_dir=args.results_dir,
                puzzle_dir=args.puzzle_dir,
                clues_dir=args.clues_dir
            )
            session.start()
        else:
            # Exit
            console.print("\nGoodbye!\n")
            return 0
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
