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
from ui.interactive import start_interactive_session
from core.enhanced_state_saver import EnhancedStateSaver
import re
import time
from datetime import datetime


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Crypto Hunter - Cryptographic Puzzle Solver")
    parser.add_argument("puzzle", nargs="?", help="Path to puzzle file or directory")
    parser.add_argument("--provider", choices=["anthropic", "openai", "huggingface", "local"],
                        default="openai", help="LLM provider to use")
    parser.add_argument("--api-key", help="API key for the LLM provider")
    parser.add_argument("--model", help="Specific model to use")
    parser.add_argument("--iterations", type=int, default=10, help="Maximum analysis iterations")
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--results-dir", default="results", help="Results directory")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--browse", action="store_true", help="Browse puzzle collection")
    parser.add_argument("--no-clues", action="store_true", help="Don't use clues")
    parser.add_argument("--last-results", action="store_true", help="Show last results")

    return parser.parse_args()


def display_welcome():
    """Display the welcome message."""
    console = Console()
    console.print(Panel.fit("🔐 Crypto Hunter - AI-Powered Puzzle Solver 🔐", style="bold blue"))


def setup_environment(args):
    """Set up the environment for the application."""
    # Create directories
    os.makedirs(args.output_dir, exist_ok=True)
    os.makedirs(args.results_dir, exist_ok=True)

    # Setup logging
    setup_logging(args.verbose)


def process_puzzle_with_incremental_output(puzzle_path, agent, output_dir, iterations, results_dir, use_clues, verbose):
    """
    Process a puzzle with incremental output and robust error handling.
    """
    console = Console()

    try:
        # Initialize components
        saver = EnhancedStateSaver(output_dir, results_dir)
        state = State()

        # Load puzzle
        console.print(f"📁 Loading puzzle: {puzzle_path}")
        state.set_puzzle_file(puzzle_path)

        # Load clues and patterns
        if use_clues:
            try:
                clues = load_clues(puzzle_path)
                for clue in clues:
                    state.add_clue(clue['text'], clue['file'])
                if clues:
                    console.print(f"💡 Loaded {len(clues)} clues")
            except Exception as e:
                console.print(f"⚠️ Clue loading failed: {e}", style="yellow")

        try:
            patterns = load_patterns(puzzle_path)
            for pattern in patterns:
                state.add_pattern(pattern['text'], pattern['file'], pattern['category'])
            if patterns:
                console.print(f"🔍 Loaded {len(patterns)} patterns")
        except Exception as e:
            console.print(f"⚠️ Pattern loading failed: {e}", style="yellow")

        # Save initial state
        console.print("💾 Saving initial state...")
        try:
            initial_save = saver.save_comprehensive_results(state, puzzle_path, create_compressed=False)
            console.print(f"📄 Initial state saved")
        except Exception as e:
            console.print(f"⚠️ Initial save failed: {e}", style="yellow")

        # Start incremental analysis
        console.print(f"🚀 Starting analysis with {iterations} max iterations...")

        completed_iterations = 0
        successful_analyzers = []
        failed_analyzers = []

        # Get available analyzers
        from analyzers import get_compatible_analyzers, get_analyzer, get_all_analyzers

        try:
            # Phase 1: Run basic analyzers first
            console.print("📊 Phase 1: Basic Analysis")

            basic_analyzers = ['binary_analyzer', 'text_analyzer']
            for analyzer_name in basic_analyzers:
                if completed_iterations >= iterations:
                    break

                console.print(f"  🔧 Running {analyzer_name}...")
                try:
                    analyzer = get_analyzer(analyzer_name)
                    if analyzer:
                        prev_insights = len(state.insights)
                        prev_transformations = len(state.transformations)

                        state = analyzer(state)

                        new_insights = len(state.insights) - prev_insights
                        new_transformations = len(state.transformations) - prev_transformations

                        console.print(f"    ✅ Generated {new_insights} insights, {new_transformations} transformations")
                        successful_analyzers.append(analyzer_name)
                        completed_iterations += 1

                        # Save incremental results
                        try:
                            incremental_save = saver.save_comprehensive_results(
                                state, puzzle_path, create_compressed=False
                            )
                            console.print(f"    💾 Progress saved")
                        except Exception as e:
                            console.print(f"    ⚠️ Save failed: {e}", style="yellow")

                except Exception as e:
                    console.print(f"    ❌ {analyzer_name} failed: {e}", style="red")
                    failed_analyzers.append((analyzer_name, str(e)))

            # Phase 2: Specialized analyzers
            console.print("🎯 Phase 2: Specialized Analysis")

            specialized_analyzers = ['encoding_analyzer', 'crypto_analyzer', 'cipher_analyzer']
            if state.is_binary():
                specialized_analyzers.extend(['image_analyzer', 'binwalk_analyzer'])

            for analyzer_name in specialized_analyzers:
                if completed_iterations >= iterations:
                    break

                console.print(f"  🔧 Running {analyzer_name}...")
                try:
                    analyzer = get_analyzer(analyzer_name)
                    if analyzer:
                        prev_insights = len(state.insights)
                        prev_transformations = len(state.transformations)

                        state = analyzer(state)

                        new_insights = len(state.insights) - prev_insights
                        new_transformations = len(state.transformations) - prev_transformations

                        console.print(f"    ✅ Generated {new_insights} insights, {new_transformations} transformations")
                        successful_analyzers.append(analyzer_name)
                        completed_iterations += 1

                        # Save incremental results
                        try:
                            incremental_save = saver.save_comprehensive_results(
                                state, puzzle_path, create_compressed=False
                            )
                            console.print(f"    💾 Progress saved")
                        except Exception as e:
                            console.print(f"    ⚠️ Save failed: {e}", style="yellow")

                        # Check for solution
                        if state.solution:
                            console.print(f"    🎉 Solution found: {state.solution}")
                            break

                except Exception as e:
                    console.print(f"    ❌ {analyzer_name} failed: {e}", style="red")
                    failed_analyzers.append((analyzer_name, str(e)))

            # Phase 3: Advanced analysis with LLM (if available)
            if completed_iterations < iterations and agent.llm_available:
                console.print("🤖 Phase 3: AI-Guided Analysis")

                try:
                    # Let the agent orchestrate remaining analysis
                    remaining_iterations = iterations - completed_iterations
                    console.print(f"  🧠 Running AI analysis for {remaining_iterations} iterations...")

                    state = agent.analyze(state, remaining_iterations)
                    completed_iterations = iterations  # Mark as complete

                    console.print("    ✅ AI analysis completed")

                except Exception as e:
                    console.print(f"    ❌ AI analysis failed: {e}", style="red")
                    failed_analyzers.append(("ai_analysis", str(e)))

        except Exception as e:
            console.print(f"❌ Analysis pipeline failed: {e}", style="red")

        # Final save with comprehensive results
        console.print("💾 Creating final comprehensive results...")

        try:
            final_save = saver.save_comprehensive_results(
                state, puzzle_path, create_compressed=True
            )

            console.print("📊 Final Results:")
            for file_type, file_path in final_save.items():
                if file_path and os.path.exists(file_path):
                    console.print(f"  • {file_type}: {file_path}")

        except Exception as e:
            console.print(f"❌ Final save failed: {e}", style="red")

            # Emergency save
            try:
                emergency_results = {
                    'puzzle_path': puzzle_path,
                    'completed_iterations': completed_iterations,
                    'successful_analyzers': successful_analyzers,
                    'failed_analyzers': failed_analyzers,
                    'insights_count': len(state.insights),
                    'transformations_count': len(state.transformations),
                    'solution': state.solution,
                    'timestamp': datetime.now().isoformat()
                }

                emergency_file = os.path.join(results_dir, f"emergency_results_{int(time.time())}.json")
                with open(emergency_file, 'w') as f:
                    json.dump(emergency_results, f, indent=2)

                console.print(f"🚨 Emergency results saved to: {emergency_file}")

            except Exception as e2:
                console.print(f"❌ Emergency save also failed: {e2}", style="red")

        # Display summary
        display_analysis_summary(state, completed_iterations, successful_analyzers, failed_analyzers)

        return 0 if not failed_analyzers or state.solution else 1

    except Exception as e:
        console.print(f"❌ Critical error: {e}", style="red")
        return 1


def display_analysis_summary(state, completed_iterations, successful_analyzers, failed_analyzers):
    """Display a summary of the analysis results."""
    console = Console()

    # Create summary table
    table = Table(title="Analysis Summary", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Completed Iterations", str(completed_iterations))
    table.add_row("Successful Analyzers", str(len(successful_analyzers)))
    table.add_row("Failed Analyzers", str(len(failed_analyzers)))
    table.add_row("Total Insights", str(len(state.insights)))
    table.add_row("Total Transformations", str(len(state.transformations)))
    table.add_row("Solution Found", "Yes" if state.solution else "No")

    console.print(table)

    # Show successful analyzers
    if successful_analyzers:
        console.print("\n✅ Successful Analyzers:")
        for analyzer in successful_analyzers:
            console.print(f"  • {analyzer}")

    # Show failed analyzers
    if failed_analyzers:
        console.print("\n❌ Failed Analyzers:")
        for analyzer, error in failed_analyzers:
            console.print(f"  • {analyzer}: {error[:50]}...")

    # Show recent insights
    if state.insights:
        console.print(f"\n💡 Recent Insights (last 3):")
        for insight in state.insights[-3:]:
            console.print(f"  • {insight['text'][:80]}...")

    # Show solution if found
    if state.solution:
        console.print(f"\n🎯 Solution: {state.solution}")


def process_puzzle(puzzle_path, agent, output_dir, iterations, results_dir, use_clues, verbose):
    """
    Process a single puzzle file or folder with robust error handling.
    """
    console = Console()

    if os.path.isdir(puzzle_path):
        return process_all_files_in_folder(puzzle_path, agent, output_dir, iterations, results_dir, use_clues, verbose)

    if not os.path.exists(puzzle_path):
        console.print(f"❌ Puzzle file not found: {puzzle_path}", style="red")
        return 1

    return process_puzzle_with_incremental_output(
        puzzle_path, agent, output_dir, iterations, results_dir, use_clues, verbose
    )


def process_all_files_in_folder(folder_path, agent, output_dir, iterations, results_dir, use_clues, verbose):
    """
    Process all files in a puzzle folder as a single puzzle.
    """
    console = Console()

    try:
        saver = EnhancedStateSaver(output_dir, results_dir)
        state = State()

        # Get all files in the folder
        puzzle_files = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if not file.startswith('.'):  # Skip hidden files
                    puzzle_files.append(file_path)

        if not puzzle_files:
            console.print(f"❌ No files found in folder: {folder_path}", style="red")
            return 1

        console.print(f"📁 Processing folder with {len(puzzle_files)} files")

        # Process each file
        for i, file_path in enumerate(puzzle_files, 1):
            console.print(f"📄 Processing file {i}/{len(puzzle_files)}: {os.path.basename(file_path)}")

            try:
                # Load file content
                with open(file_path, 'rb') as f:
                    file_content = f.read()

                # Add as related file to state
                state.add_related_file(os.path.basename(file_path), file_content)

                # If this is the first/main file, set it as the puzzle file
                if i == 1:
                    state.set_puzzle_file(file_path)

            except Exception as e:
                console.print(f"⚠️ Failed to load {file_path}: {e}", style="yellow")
                continue

        # Run analysis on the combined state
        return process_puzzle_with_incremental_output(
            folder_path, agent, output_dir, iterations, results_dir, use_clues, verbose
        )

    except Exception as e:
        console.print(f"❌ Failed to process folder: {e}", style="red")
        return 1


def display_results(state, puzzle_path):
    """Display the analysis results in a structured format."""
    console = Console()

    console.print("\n" + "=" * 80)
    console.print("📊 ANALYSIS RESULTS", style="bold blue", justify="center")
    console.print("=" * 80)

    # Basic info
    console.print(f"📁 Puzzle: {puzzle_path}")
    console.print(f"📈 Insights: {len(state.insights)}")
    console.print(f"🔄 Transformations: {len(state.transformations)}")

    if state.solution:
        console.print(Panel(f"🎯 SOLUTION: {state.solution}", style="bold green"))

    # Show key insights
    if state.insights:
        console.print("\n💡 Key Insights:")
        for i, insight in enumerate(state.insights[-5:], 1):  # Show last 5
            console.print(f"  {i}. {insight['text']}")

    # Show transformations
    if state.transformations:
        console.print("\n🔄 Recent Transformations:")
        for i, transform in enumerate(state.transformations[-3:], 1):  # Show last 3
            console.print(f"  {i}. {transform['name']}: {transform['description']}")


def browse_puzzle_collection(puzzles_dir, agent, results_dir, use_clues, verbose):
    """Browse the puzzle collection interactively."""
    console = Console()

    try:
        puzzles = browse_puzzles(puzzles_dir)
        if not puzzles:
            console.print("❌ No puzzles found in the collection.", style="red")
            return 1

        while True:
            console.print("\n🧩 Available Puzzles:")
            for i, puzzle in enumerate(puzzles, 1):
                info = get_puzzle_info(puzzle)
                console.print(f"  {i}. {info['name']} ({info['type']}, {info['size']})")

            console.print("  0. Exit")

            try:
                choice = IntPrompt.ask("Select puzzle", default=0)
                if choice == 0:
                    break
                elif 1 <= choice <= len(puzzles):
                    selected_puzzle = puzzles[choice - 1]
                    iterations = IntPrompt.ask("Max iterations", default=10)

                    result = process_puzzle(
                        selected_puzzle, agent, "output", iterations,
                        results_dir, use_clues, verbose
                    )

                    if result == 0:
                        console.print("✅ Analysis completed successfully!", style="green")
                    else:
                        console.print("⚠️ Analysis completed with issues.", style="yellow")
                else:
                    console.print("❌ Invalid selection.", style="red")

            except KeyboardInterrupt:
                break
            except Exception as e:
                console.print(f"❌ Error: {e}", style="red")

        return 0

    except Exception as e:
        console.print(f"❌ Failed to browse puzzles: {e}", style="red")
        return 1


def interactive_mode(agent):
    """Run in interactive mode."""
    start_interactive_session(agent)


def read_last_results(results_dir):
    """
    Read and display the most recent results file.
    """
    console = Console()

    try:
        if not os.path.exists(results_dir):
            console.print(f"❌ Results directory not found: {results_dir}", style="red")
            return 1

        # Find the most recent results file
        result_files = []
        for file in os.listdir(results_dir):
            if file.endswith('.json') and ('results' in file or 'analysis' in file):
                file_path = os.path.join(results_dir, file)
                result_files.append((file_path, os.path.getmtime(file_path)))

        if not result_files:
            console.print("❌ No results files found.", style="red")
            return 1

        # Sort by modification time (newest first)
        result_files.sort(key=lambda x: x[1], reverse=True)
        latest_file = result_files[0][0]

        console.print(f"📄 Loading latest results from: {latest_file}")

        with open(latest_file, 'r') as f:
            results = json.load(f)

        # Display results
        console.print("\n📊 Latest Analysis Results:")
        console.print(f"Puzzle: {results.get('puzzle_path', 'Unknown')}")
        console.print(f"Date: {results.get('analysis_date', 'Unknown')}")
        console.print(f"Insights: {results.get('insights_count', 0)}")
        console.print(f"Transformations: {results.get('transformations_count', 0)}")

        if results.get('solution'):
            console.print(f"🎯 Solution: {results['solution']}")

        if 'insights' in results and results['insights']:
            console.print("\n💡 Recent Insights:")
            for i, insight in enumerate(results['insights'][-5:], 1):
                console.print(f"  {i}. {insight}")

        return 0

    except Exception as e:
        console.print(f"❌ Failed to read results: {e}", style="red")
        return 1


def main():
    """Main entry point for the application."""
    args = parse_arguments()

    # Setup environment
    setup_environment(args)

    # Display welcome
    if not args.puzzle and not args.interactive and not args.browse and not args.last_results:
        display_welcome()

    # Handle special modes
    if args.last_results:
        return read_last_results(args.results_dir)

    # Initialize agent
    try:
        agent = CryptoAgent(args.provider, args.api_key, args.model, args.verbose)
    except Exception as e:
        console = Console()
        console.print(f"❌ Failed to initialize agent: {e}", style="red")
        return 1

    # Handle different modes
    if args.interactive:
        interactive_mode(agent)
        return 0
    elif args.browse:
        puzzles_dir = args.puzzle or "puzzles"
        return browse_puzzle_collection(
            puzzles_dir, agent, args.results_dir, not args.no_clues, args.verbose
        )
    elif args.puzzle:
        return process_puzzle(
            args.puzzle, agent, args.output_dir, args.iterations,
            args.results_dir, not args.no_clues, args.verbose
        )
    else:
        # Interactive menu
        console = Console()
        while True:
            console.print("\n🔐 Crypto Hunter Menu:")
            console.print("1. Analyze single puzzle")
            console.print("2. Browse puzzle collection")
            console.print("3. Interactive mode")
            console.print("4. View last results")
            console.print("0. Exit")

            try:
                choice = IntPrompt.ask("Select option", default=0)

                if choice == 0:
                    break
                elif choice == 1:
                    puzzle_path = Prompt.ask("Enter puzzle path")
                    iterations = IntPrompt.ask("Max iterations", default=10)
                    result = process_puzzle(
                        puzzle_path, agent, args.output_dir, iterations,
                        args.results_dir, not args.no_clues, args.verbose
                    )
                elif choice == 2:
                    puzzles_dir = Prompt.ask("Enter puzzles directory", default="puzzles")
                    browse_puzzle_collection(
                        puzzles_dir, agent, args.results_dir, not args.no_clues, args.verbose
                    )
                elif choice == 3:
                    interactive_mode(agent)
                elif choice == 4:
                    read_last_results(args.results_dir)
                else:
                    console.print("❌ Invalid selection.", style="red")

            except KeyboardInterrupt:
                break
            except Exception as e:
                console.print(f"❌ Error: {e}", style="red")

        return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)