#!/usr/bin/env python
"""
Crypto Hunter - The Ultimate Cryptographic Puzzle Solver

A tool for analyzing and solving cryptographic puzzles using AI assistance.
"""

import os
import sys
import argparse
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt
from rich import box

from core.state import State
from core.agent import CryptoAgent
from core.utils import browse_puzzles, get_puzzle_info, setup_logging, load_clues, load_patterns
from core.logger import solution_logger

console = Console()


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Crypto Hunter - Cryptographic Puzzle Solver")
    parser.add_argument("--puzzle-file", type=str, help="Path to the puzzle file")
    parser.add_argument("--output-dir", type=str, default="./output", help="Directory to store output")
    parser.add_argument("--results-dir", type=str, default="./results", help="Directory to store results")
    parser.add_argument("--browse-puzzles", action="store_true", help="Browse the puzzle collection")
    parser.add_argument("--puzzle-dir", type=str, default="./puzzles", help="Directory containing puzzles")
    parser.add_argument("--use-clues", action="store_true", help="Use available clues for the puzzle")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--iterations", type=int, default=15, help="Maximum number of analysis iterations")
    parser.add_argument("--provider", type=str, default="anthropic",
                        choices=["anthropic", "openai", "huggingface", "local"],
                        help="LLM provider to use")
    parser.add_argument("--model", type=str, help="Specific model to use with provider")
    parser.add_argument("--api-key", type=str, help="API key for the LLM provider")
    parser.add_argument("--analyzer", type=str, help="Use a specific analyzer")

    return parser.parse_args()


def display_welcome():
    """Display the welcome message."""
    console.print(Panel.fit(
        "[bold cyan]Crypto Hunter v1.0.0[/bold cyan]\n"
        "[bold white]The Ultimate Cryptographic Puzzle Solver[/bold white]",
        box=box.DOUBLE,
        padding=(1, 10)
    ))
    console.print("\nWelcome to Crypto Hunter!")


def setup_environment(args):
    """Set up the environment for the application."""
    # Create output and results directories if they don't exist
    os.makedirs(args.output_dir, exist_ok=True)
    os.makedirs(args.results_dir, exist_ok=True)

    # Setup logging
    setup_logging(args.verbose)

    # Initialize solution logger with verbose flag
    global solution_logger
    solution_logger.__init__(verbose=args.verbose)


def interactive_menu():
    """Display the interactive menu."""
    console.print("Please select how you would like to proceed:")
    console.print("  1. Browse puzzle collection")
    console.print("  2. Interactive mode")
    console.print("  3. Exit")

    choice = Prompt.ask("Select an option [1/2/3]", choices=["1", "2", "3"], default="1")

    if choice == "1":
        return "browse"
    elif choice == "2":
        return "interactive"
    else:
        return "exit"


def select_provider_interactively():
    """Allow user to select an LLM provider."""
    console.print("\n[bold]Available LLM Providers:[/bold]")
    console.print("  1. Anthropic Claude (requires API key)")
    console.print("  2. OpenAI (requires API key)")
    console.print("  3. Hugging Face (requires API key)")
    console.print("  4. Local fallback mode (no API needed)")

    choice = Prompt.ask("Select a provider", choices=["1", "2", "3", "4"], default="1")

    providers = {
        "1": "anthropic",
        "2": "openai",
        "3": "huggingface",
        "4": "local"
    }

    provider = providers[choice]

    # Ask for API key if needed
    api_key = None
    if provider != "local":
        env_var = f"{provider.upper()}_API_KEY"
        if os.environ.get(env_var):
            use_env = Prompt.ask(f"Use {env_var} from environment?", choices=["y", "n"], default="y")
            if use_env.lower() == "n":
                api_key = Prompt.ask("Enter API key", password=True)
        else:
            api_key = Prompt.ask("Enter API key", password=True)

    return provider, api_key


def print_state_details(state):
    """Print detailed insights and transformations from the state."""
    console.print("\n[bold]Current Insights:[/bold]")
    if state.insights:
        for i, insight in enumerate(state.insights, 1):
            console.print(f"{i}. [{insight.get('time', '')}] {insight.get('analyzer', '')}: {insight.get('text', '')}")
    else:
        console.print("[italic]No insights yet.[/italic]")

    console.print("\n[bold]Current Transformations:[/bold]")
    if state.transformations:
        for i, transform in enumerate(state.transformations, 1):
            console.print(f"{i}. [{transform.get('name', 'Transformation')}] {transform.get('description', '')}")
            console.print(f"   Input: {transform.get('input_data', '')[:100]}...")
            console.print(f"   Output: {transform.get('output_data', '')[:100]}...")
    else:
        console.print("[italic]No transformations yet.[/italic]")


def process_all_files_in_folder(folder_path, agent, output_dir="./output", iterations=15, results_dir="./results",
                                use_clues=False, verbose=False):
    """
    Process all files in a puzzle folder as a single puzzle.

    Args:
        folder_path: Path to the puzzle folder
        agent: CryptoAgent instance for analysis
        output_dir: Directory to store output files
        iterations: Maximum number of iterations for the agent
        results_dir: Directory to store results
        use_clues: Whether to use available clues
        verbose: Whether to print detailed reasoning

    Returns:
        Final state of the puzzle analysis
    """
    # Create a state object that will hold all files
    state = State()

    # Load all files in the folder
    folder_path = Path(folder_path)
    files = list(folder_path.glob("*"))
    if not files:
        console.print(f"[bold red]No files found in {folder_path}[/bold red]")
        return None

    # Check for description.txt file
    description_file = folder_path / "description.txt"
    description_content = None
    description_url = None

    if description_file.exists() and description_file.is_file():
        try:
            with open(description_file, "r", encoding="utf-8") as f:
                description_content = f.read()

            # Check if there's a URL in the description
            import re
            url_pattern = re.compile(r'https?://\S+')
            url_match = url_pattern.search(description_content)
            if url_match:
                description_url = url_match.group(0)

            console.print(f"[bold green]Found description.txt file for this puzzle![/bold green]")
            console.print(Panel.fit(
                description_content,
                title="Puzzle Description",
                border_style="green"
            ))

            if description_url:
                console.print(f"[bold cyan]Puzzle URL: {description_url}[/bold cyan]")
        except Exception as e:
            console.print(f"[bold red]Error reading description.txt: {e}[/bold red]")

    # Add all files to the state
    console.print(f"[bold]Loading all files from {folder_path} as part of the puzzle:[/bold]")

    for file_path in files:
        if file_path.is_file():
            console.print(f"  - {file_path.name} ({file_path.stat().st_size} bytes)")

            # Add all files to the state with their paths
            with open(file_path, "rb") as f:
                content = f.read()

            # Add file content to the state
            state.add_related_file(file_path.name, content)

    # Use the first file as the main puzzle file if none is set
    if not state.puzzle_file and files:
        first_file = files[0]
        if first_file.is_file():
            # Fix: Pass the full path, not just the name
            state.set_puzzle_file(str(first_file))

            # For binary files, we'll need to handle differently
            if state.is_binary():
                state.set_binary_data(state.related_files[first_file.name]["content"])
            else:
                state.set_puzzle_text(state.related_files[first_file.name]["content"].decode("utf-8", errors="replace"))

    # Check for binary image files among the related files
    for filename, file_info in state.related_files.items():
        file_ext = os.path.splitext(filename)[1].lower()
        if file_ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.webp']:
            console.print(f"[bold]Found image file: {filename}[/bold]")
            # Set binary data for image files to enable image analyzers
            state.set_binary_data(file_info["content"])
            break

    # Check for clues if enabled
    if use_clues:
        console.print("\n[bold]Checking for clues...[/bold]")
        clues = load_clues(folder_path)

        if clues:
            console.print(f"[green]Found {len(clues)} clues![/green]")

            for i, clue in enumerate(clues, 1):
                console.print(f"[bold]Clue {i}:[/bold] {clue['file']}")
                if not clue.get('binary', False):
                    state.add_clue(clue['text'], clue['file'])
                else:
                    state.add_clue(f"Binary clue file: {clue['file']}", clue['file'])
                    # Set binary data for binary clues to enable binary analyzers
                    if 'data' in clue:
                        print(f"Setting binary data from clue: {clue['file']} ({len(clue['data'])} bytes)")
                        state.set_binary_data(clue['data'])
                    else:
                        print(f"Warning: Binary clue {clue['file']} has no 'data' key")
                        # Try to load the file directly
                        try:
                            with open(clue['file'], 'rb') as f:
                                binary_data = f.read()
                                print(f"Loaded binary data directly: {len(binary_data)} bytes")
                                state.set_binary_data(binary_data)
                        except Exception as e:
                            print(f"Error loading binary data directly: {e}")
        else:
            console.print("[yellow]No clues found.[/yellow]")

    # Load patterns from similar puzzles
    console.print("\n[bold]Loading patterns from similar puzzles...[/bold]")
    patterns = load_patterns(folder_path)

    if patterns:
        console.print(f"[green]Found {len(patterns)} patterns![/green]")

        for i, pattern in enumerate(patterns, 1):
            console.print(f"[bold]Pattern {i}:[/bold] {pattern['file']} [{pattern['category']}]")
            state.add_pattern(pattern['text'], pattern['file'], pattern['category'])
    else:
        console.print("[yellow]No patterns found.[/yellow]")

    # Show folder contents summary
    console.print("\n[bold]Puzzle Folder Summary:[/bold]")
    folder_table = Table(show_header=True, header_style="bold magenta")
    folder_table.add_column("File")
    folder_table.add_column("Size")
    folder_table.add_column("Type")

    for file_path in files:
        if file_path.is_file():
            file_type = "Text" if not state.is_binary_file(file_path) else "Binary"
            folder_table.add_row(
                file_path.name,
                f"{file_path.stat().st_size} bytes",
                file_type
            )

    console.print(folder_table)
    console.print("\n[bold cyan]Analyzing all files as part of a single puzzle...[/bold cyan]")

    # Debug before analysis
    if verbose:
        console.print("[blue]Starting analysis with LLM agent...[/blue]")

    # Run the analysis once with full iterations
    final_state = agent.analyze(state, max_iterations=iterations)

    if verbose:
        console.print(f"\n[bold]Analysis completed after {iterations} iterations.[/bold]")
        print_state_details(final_state)

    # Save results
    # Save comprehensive results using enhanced saver
    try:
        from core.enhanced_state_saver import enhanced_saver
        saved_files = enhanced_saver.save_comprehensive_results(final_state, str(folder_path))

        console.print(f"\n[bold green]Results saved successfully![/bold green]")
        console.print(f"Generated {len(saved_files)} output files:")

        # Show key files to user
        key_files = ["summary", "html_report", "potential_keys_txt", "compressed_archive"]
        for key_file in key_files:
            if key_file in saved_files:
                console.print(f"  [cyan]{key_file}:[/cyan] {saved_files[key_file]}")

        if "html_report" in saved_files:
            console.print(
                f"\n[bold blue]💡 Tip:[/bold blue] Open the HTML report for a comprehensive view: {saved_files['html_report']}")

    except Exception as save_error:
        console.print(f"[bold red]Warning: Enhanced save failed, using basic save: {save_error}[/bold red]")
        # Fallback to basic save
        result_path = os.path.join(results_dir, f"{folder_path.name}_results.json")
        with open(result_path, "w") as f:
            json.dump({
                "status": "completed",
                "solution": final_state.solution,
                "insights": final_state.insights,
                "transformations": final_state.transformations
            }, f, indent=2)

    return final_state


def process_puzzle(puzzle_path, agent, output_dir="./output", iterations=15, results_dir="./results", use_clues=False,
                   verbose=False):
    """
    Process a single puzzle file or folder.

    Args:
        puzzle_path: Path to the puzzle file or folder
        agent: CryptoAgent instance
        output_dir: Directory to store output files
        iterations: Maximum number of analysis iterations
        results_dir: Directory to store results
        use_clues: Whether to use available clues
        verbose: Whether to print detailed reasoning

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    path = Path(puzzle_path)

    # Check if the path is a directory
    if path.is_dir():
        console.print(f"[bold]Processing puzzle folder: {path}[/bold]")
        final_state = process_all_files_in_folder(
            path, agent, output_dir, iterations, results_dir, use_clues, verbose
        )
    else:
        # Single file mode - load the file but also check if there are other files in the same directory
        console.print(f"[bold]Processing puzzle file: {path}[/bold]")

        # Check if there are other files in the same directory
        parent_dir = path.parent
        other_files = [f for f in parent_dir.glob("*") if f != path and f.is_file()]

        if other_files:
            console.print("[yellow]Note: Other files found in the same directory.[/yellow]")
            console.print("[yellow]These might be related to the puzzle. Consider using the folder mode.[/yellow]")

            process_all = Prompt.ask(
                "Process all files in the directory as one puzzle?",
                choices=["y", "n"],
                default="y"
            )

            if process_all.lower() == "y":
                final_state = process_all_files_in_folder(
                    parent_dir, agent, output_dir, iterations, results_dir, use_clues, verbose
                )
                return 0 if final_state and final_state.solution else 1

        # Process just the single file
        with open(path, "rb") as f:
            content = f.read()

        # Create state
        state = State(puzzle_file=path.name)

        # Set content based on file type
        if state.is_binary():
            state.set_binary_data(content)
            # Check if it's an image file
            file_ext = os.path.splitext(path.name)[1].lower()
            if file_ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.webp']:
                console.print(f"[bold]Processing image file: {path.name}[/bold]")
        else:
            state.set_puzzle_text(content.decode("utf-8", errors="replace"))

        # Check for clues if enabled
        if use_clues:
            console.print("\n[bold]Checking for clues...[/bold]")
            clues = load_clues(path)

            if clues:
                console.print(f"[green]Found {len(clues)} clues![/green]")

                for i, clue in enumerate(clues, 1):
                    console.print(f"[bold]Clue {i}:[/bold] {clue['file']}")
                    if not clue.get('binary', False):
                        state.add_clue(clue['text'], clue['file'])
                    else:
                        state.add_clue(f"Binary clue file: {clue['file']}", clue['file'])
                        # Set binary data for binary clues to enable binary analyzers
                        if 'data' in clue:
                            print(f"Setting binary data from clue: {clue['file']} ({len(clue['data'])} bytes)")
                            state.set_binary_data(clue['data'])
                        else:
                            print(f"Warning: Binary clue {clue['file']} has no 'data' key")
                            # Try to load the file directly
                            try:
                                with open(clue['file'], 'rb') as f:
                                    binary_data = f.read()
                                    print(f"Loaded binary data directly: {len(binary_data)} bytes")
                                    state.set_binary_data(binary_data)
                            except Exception as e:
                                print(f"Error loading binary data directly: {e}")
            else:
                console.print("[yellow]No clues found.[/yellow]")

        # Load patterns from similar puzzles
        console.print("\n[bold]Loading patterns from similar puzzles...[/bold]")
        patterns = load_patterns(path)

        if patterns:
            console.print(f"[green]Found {len(patterns)} patterns![/green]")

            for i, pattern in enumerate(patterns, 1):
                console.print(f"[bold]Pattern {i}:[/bold] {pattern['file']} [{pattern['category']}]")
                state.add_pattern(pattern['text'], pattern['file'], pattern['category'])
        else:
            console.print("[yellow]No patterns found.[/yellow]")

        # Debug before analysis
        if verbose:
            console.print("[blue]Starting analysis with LLM agent...[/blue]")

        # Run analysis once with full iterations
        final_state = agent.analyze(state, max_iterations=iterations)

        if verbose:
            console.print(f"\n[bold]Analysis completed after {iterations} iterations.[/bold]")
            print_state_details(final_state)

        # Save comprehensive results using enhanced saver
        # Save comprehensive results using enhanced saver
        try:
            from core.enhanced_state_saver import enhanced_saver
            saved_files = enhanced_saver.save_comprehensive_results(final_state, str(path))

            console.print(f"\n[bold green]Results saved successfully![/bold green]")
            console.print(f"Generated {len(saved_files)} output files:")

            # Show key files to user
            key_files = ["summary", "html_report", "potential_keys_txt", "compressed_archive"]
            for key_file in key_files:
                if key_file in saved_files:
                    console.print(f"  [cyan]{key_file}:[/cyan] {saved_files[key_file]}")

            if "html_report" in saved_files:
                console.print(
                    f"\n[bold blue]💡 Tip:[/bold blue] Open the HTML report for a comprehensive view: {saved_files['html_report']}")

        except Exception as save_error:
            console.print(f"[bold red]Warning: Enhanced save failed, using basic save: {save_error}[/bold red]")
            # Fallback to basic save
            result_path = os.path.join(results_dir, f"{path.name}_results.json")
            with open(result_path, "w") as f:
                json.dump({
                    "status": "completed",
                    "solution": final_state.solution,
                    "insights": final_state.insights,
                    "transformations": final_state.transformations
                }, f, indent=2)

    # Display results
    if final_state:
        display_results(final_state, puzzle_path)
        return 0 if final_state.solution else 1
    else:
        console.print("[bold red]Failed to process puzzle.[/bold red]")
        return 1


def display_results(state, puzzle_path):
    """Display the analysis results in a structured format."""
    console.print("\n[bold cyan]═════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]           ANALYSIS RESULTS           [/bold cyan]")
    console.print("[bold cyan]═════════════════════════════════════════[/bold cyan]\n")

    # Display puzzle info in a panel
    info_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE_HEAD)
    info_table.add_column("Property", style="cyan")
    info_table.add_column("Value", style="green")

    info_table.add_row("File", str(puzzle_path))
    info_table.add_row("Type", state.file_type or "Unknown")
    info_table.add_row("Size", f"{state.file_size} bytes" if state.file_size else "Unknown")

    status_style = "green" if state.solution else "yellow"
    info_table.add_row("Status", f"[{status_style}]{'Solved' if state.solution else 'Unsolved'}[/{status_style}]")

    if state.solution:
        info_table.add_row("Solution", f"[bold green]{state.solution}[/bold green]")

    console.print(Panel(info_table, title="[bold]Puzzle Information[/bold]", border_style="blue"))

    # Display insights in a panel
    if state.insights:
        insights_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE_HEAD)
        insights_table.add_column("Time", style="dim")
        insights_table.add_column("Analyzer", style="cyan")
        insights_table.add_column("Insight", style="green", no_wrap=False)

        for insight in state.insights:
            insights_table.add_row(
                insight.get("time", ""),
                insight.get("analyzer", ""),
                insight.get("text", "")
            )

        console.print(Panel(insights_table, title="[bold]Analysis Insights[/bold]", border_style="blue"))
    else:
        console.print(Panel("[italic]No insights gathered.[/italic]", title="[bold]Analysis Insights[/bold]", border_style="blue"))

    # Display related files in a panel if they exist
    if state.related_files:
        files_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE_HEAD)
        files_table.add_column("Filename", style="cyan")
        files_table.add_column("Size", style="green")
        files_table.add_column("SHA-256", style="dim")

        for filename, file_info in state.related_files.items():
            files_table.add_row(
                filename,
                f"{file_info['size']} bytes",
                file_info['sha256'][:16] + "..."
            )

        console.print(Panel(files_table, title="[bold]Related Files[/bold]", border_style="blue"))

    # Display clues in a panel if they exist
    if state.clues:
        clues_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE_HEAD)
        clues_table.add_column("File", style="cyan")
        clues_table.add_column("Text", style="green", no_wrap=False)

        for clue in state.clues:
            clue_text = clue.get("text", "")
            # Format long text better
            displayed_text = clue_text if len(clue_text) <= 80 else f"{clue_text[:77]}..."

            clues_table.add_row(
                clue.get("file", "N/A"),
                displayed_text
            )

        console.print(Panel(clues_table, title="[bold]Clues[/bold]", border_style="blue"))

    # Display patterns in a panel if they exist
    if state.patterns:
        patterns_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE_HEAD)
        patterns_table.add_column("Category", style="cyan")
        patterns_table.add_column("File", style="dim")
        patterns_table.add_column("Description", style="green", no_wrap=False)

        for pattern in state.patterns:
            pattern_text = pattern.get("text", "")
            # Format long text better
            displayed_text = pattern_text if len(pattern_text) <= 80 else f"{pattern_text[:77]}..."

            patterns_table.add_row(
                pattern.get("category", "Unknown"),
                pattern.get("file", "N/A"),
                displayed_text
            )

        console.print(Panel(patterns_table, title="[bold]Patterns from Similar Puzzles[/bold]", border_style="blue"))

    # Display transformations in panels
    if state.transformations:
        transformations_panels = []
        for i, transform in enumerate(state.transformations):
            input_data = transform.get('input_data', '')
            output_data = transform.get('output_data', '')

            # Format input/output data for better readability
            input_display = input_data if len(input_data) <= 100 else f"{input_data[:97]}..."
            output_display = output_data if len(output_data) <= 100 else f"{output_data[:97]}..."

            transform_panel = Panel(
                f"[bold cyan]{transform.get('name', 'Transformation')}[/bold cyan]\n"
                f"[italic]{transform.get('description', '')}[/italic]\n\n"
                f"[bold]Input:[/bold] {input_display}\n\n"
                f"[bold]Output:[/bold] {output_display}",
                title=f"Transformation {i + 1}",
                title_align="left",
                border_style="green"
            )
            transformations_panels.append(transform_panel)

        console.print(Panel.fit(
            "\n".join([str(p) for p in transformations_panels]), 
            title="[bold]Transformations[/bold]", 
            border_style="blue"
        ))
    else:
        console.print(Panel("[italic]No transformations applied.[/italic]", title="[bold]Transformations[/bold]", border_style="blue"))

    console.print("\n[bold cyan]═════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]            END OF RESULTS             [/bold cyan]")
    console.print("[bold cyan]═════════════════════════════════════════[/bold cyan]")


def browse_puzzle_collection(puzzles_dir, agent, results_dir, use_clues=False, verbose=False):
    """Browse the puzzle collection interactively."""
    categories = browse_puzzles(puzzles_dir)

    if not categories:
        console.print("[bold red]No puzzles found in the collection.[/bold red]")
        return 1

    # Display categories
    console.print("Available Puzzle Categories:")
    category_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
    category_table.add_column("#")
    category_table.add_column("Category")
    category_table.add_column("Puzzles")

    for i, (category, puzzles) in enumerate(categories.items(), 1):
        category_table.add_row(
            str(i),
            category,
            str(len(puzzles))
        )

    console.print(category_table)

    # Select category
    category_choices = [str(i) for i in range(1, len(categories) + 1)]
    category_choice = IntPrompt.ask(
        f"Select a category (number) [{'/'.join(category_choices)}]",
        choices=category_choices,
        default=1
    )

    # Get the selected category
    selected_category = list(categories.keys())[category_choice - 1]
    puzzles = categories[selected_category]

    # Display puzzles in the category
    console.print(f"Puzzles in category '{selected_category}':")
    puzzle_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
    puzzle_table.add_column("#")
    puzzle_table.add_column("Puzzle")
    puzzle_table.add_column("Size")
    puzzle_table.add_column("Has Clue")

    for i, puzzle in enumerate(puzzles, 1):
        info = get_puzzle_info(puzzle)
        puzzle_table.add_row(
            str(i),
            Path(puzzle).name,
            f"{info['size']} bytes",
            "Yes" if info["has_clue"] else "No"
        )

    console.print(puzzle_table)

    # Select puzzle
    puzzle_choices = [str(i) for i in range(1, len(puzzles) + 1)]
    puzzle_choice = IntPrompt.ask(
        f"Select a puzzle (number) [{'/'.join(puzzle_choices)}]",
        choices=puzzle_choices,
        default=1
    )

    # Get the selected puzzle path
    selected_puzzle = puzzles[puzzle_choice - 1]

    # Check if it has clues and ask if we should use them
    info = get_puzzle_info(selected_puzzle)
    if info["has_clue"] and not use_clues:
        use_clues = Prompt.ask(
            "This puzzle has clues available. Use them?",
            choices=["y", "n"],
            default="y"
        ).lower() == "y"

    # Determine if we should process a folder or single file
    selected_path = Path(selected_puzzle)

    if selected_path.is_dir():
        console.print(f"[bold cyan]Selected puzzle folder: {selected_path}[/bold cyan]")
        return process_all_files_in_folder(
            selected_path, agent, results_dir=results_dir, use_clues=use_clues, verbose=verbose
        )
    else:
        # Check if there are other files in the same folder
        parent_dir = selected_path.parent
        other_files = list(parent_dir.glob("*"))

        if len(other_files) > 1:  # More than just the selected file
            console.print("[yellow]This puzzle has multiple files in its folder.[/yellow]")
            process_all = Prompt.ask(
                "Process all files in the folder as part of the puzzle?",
                choices=["y", "n"],
                default="y"
            )

            if process_all.lower() == "y":
                console.print(f"[bold cyan]Processing all files in: {parent_dir}[/bold cyan]")
                return process_all_files_in_folder(
                    parent_dir, agent, results_dir=results_dir, use_clues=use_clues, verbose=verbose
                )

        # Process just the selected file
        console.print(f"[bold cyan]Selected puzzle file: {selected_path}[/bold cyan]")
        return process_puzzle(
            selected_puzzle, agent, results_dir=results_dir, use_clues=use_clues, verbose=verbose
        )


def interactive_mode(agent):
    """Run in interactive mode."""
    # (No changes needed here)
    # ...


def main():
    """Main entry point for the application."""
    # Display welcome message
    display_welcome()

    # Parse command line arguments
    args = parse_arguments()

    # Set up the environment
    setup_environment(args)

    # Enter interactive or browsing mode if no puzzle file is provided
    mode = None
    if not args.puzzle_file and not args.browse_puzzles and not args.interactive:
        mode = interactive_menu()

        if mode == "exit":
            return 0
    elif args.browse_puzzles:
        mode = "browse"
    elif args.interactive:
        mode = "interactive"
    else:
        mode = "process"

    # Select provider interactively if not specified
    provider = args.provider
    api_key = args.api_key

    if not provider and not api_key:
        provider, api_key = select_provider_interactively()

    # Initialize the agent
    agent = CryptoAgent(
        provider=provider,
        api_key=api_key,
        model=args.model,
        verbose=args.verbose
    )

    # Execute the appropriate mode
    if mode == "browse":
        return browse_puzzle_collection(
            args.puzzle_dir, agent, args.results_dir, args.use_clues, verbose=args.verbose
        )
    elif mode == "interactive":
        return interactive_mode(agent)
    else:  # Process a single puzzle
        return process_puzzle(
            args.puzzle_file,
            agent,
            args.output_dir,
            args.iterations,
            args.results_dir,
            args.use_clues,
            verbose=args.verbose
        )


if __name__ == "__main__":
    sys.exit(main())
