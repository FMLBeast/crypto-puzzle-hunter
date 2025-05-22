#!/usr/bin/env python3
"""
Benchmarking Tool for Crypto Hunter Analyzers

This tool measures the performance of analyzers on different puzzles.
"""
import os
import sys
import time
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

import matplotlib.pyplot as plt
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.state import State
from analyzers.base import get_all_analyzers, run_analyzer, get_analyzer


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Benchmark Crypto Hunter Analyzers"
    )
    parser.add_argument(
        "--analyzer",
        type=str,
        default=None,
        help="Specific analyzer to benchmark (default: all analyzers)",
    )
    parser.add_argument(
        "--puzzle-dir",
        type=str,
        default="examples/puzzle_samples",
        help="Directory containing puzzle files to test",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to save benchmark results (default: display only)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Number of iterations for each test (default: 1)",
    )
    
    return parser.parse_args()


def get_puzzle_files(directory: str) -> List[str]:
    """
    Get list of puzzle files from a directory.
    
    Args:
        directory: Directory path
        
    Returns:
        List of file paths
    """
    if not os.path.exists(directory):
        raise FileNotFoundError(f"Puzzle directory not found: {directory}")
    
    return [str(p) for p in Path(directory).glob("*") if p.is_file()]


def run_benchmark(analyzers: Dict[str, Any], puzzle_files: List[str], iterations: int) -> Dict[str, Any]:
    """
    Run benchmark tests on analyzers and puzzles.
    
    Args:
        analyzers: Dictionary of analyzers to test
        puzzle_files: List of puzzle files to test
        iterations: Number of iterations for each test
        
    Returns:
        Benchmark results
    """
    console = Console()
    results = {
        "timestamp": datetime.now().isoformat(),
        "iterations": iterations,
        "analyzers": list(analyzers.keys()),
        "puzzles": [os.path.basename(p) for p in puzzle_files],
        "results": []
    }
    
    total_tests = len(analyzers) * len(puzzle_files)
    
    with Progress(
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Running benchmarks", total=total_tests)
        
        for puzzle_file in puzzle_files:
            puzzle_name = os.path.basename(puzzle_file)
            
            for analyzer_name, analyzer_func in analyzers.items():
                # Initialize state with the puzzle file
                try:
                    state = State(puzzle_file=puzzle_file)
                except Exception as e:
                    console.print(f"[red]Error loading puzzle {puzzle_name}: {e}[/red]")
                    progress.update(task, advance=1)
                    continue
                
                # Run benchmark
                times = []
                insights_count = []
                transforms_count = []
                
                for _ in range(iterations):
                    # Clone the state for a fresh start
                    test_state = state.clone()
                    
                    # Measure execution time
                    start_time = time.time()
                    try:
                        updated_state = run_analyzer(analyzer_name, test_state)
                        end_time = time.time()
                        
                        # Record metrics
                        execution_time = end_time - start_time
                        times.append(execution_time)
                        
                        # Count new insights and transformations
                        insights = len(updated_state.insights) - len(test_state.insights)
                        transforms = len(updated_state.transformations) - len(test_state.transformations)
                        
                        insights_count.append(insights)
                        transforms_count.append(transforms)
                    
                    except Exception as e:
                        console.print(f"[red]Error running {analyzer_name} on {puzzle_name}: {e}[/red]")
                        times.append(0)
                        insights_count.append(0)
                        transforms_count.append(0)
                
                # Calculate statistics
                avg_time = sum(times) / len(times) if times else 0
                max_time = max(times) if times else 0
                min_time = min(times) if times else 0
                
                avg_insights = sum(insights_count) / len(insights_count) if insights_count else 0
                avg_transforms = sum(transforms_count) / len(transforms_count) if transforms_count else 0
                
                # Store results
                results["results"].append({
                    "puzzle": puzzle_name,
                    "analyzer": analyzer_name,
                    "avg_time": avg_time,
                    "min_time": min_time,
                    "max_time": max_time,
                    "avg_insights": avg_insights,
                    "avg_transforms": avg_transforms,
                })
                
                progress.update(task, advance=1)
    
    return results


def display_results(results: Dict[str, Any]):
    """
    Display benchmark results in a table.
    
    Args:
        results: Benchmark results
    """
    console = Console()
    
    # Display summary
    console.print(f"\n[bold]Benchmark Results[/bold]")
    console.print(f"Timestamp: {results['timestamp']}")
    console.print(f"Iterations: {results['iterations']}")
    console.print(f"Analyzers: {len(results['analyzers'])}")
    console.print(f"Puzzles: {len(results['puzzles'])}")
    console.print()
    
    # Display detailed results
    table = Table(title="Benchmark Results")
    table.add_column("Puzzle", style="cyan")
    table.add_column("Analyzer", style="magenta")
    table.add_column("Avg Time (s)", style="green")
    table.add_column("Min Time (s)", style="blue")
    table.add_column("Max Time (s)", style="red")
    table.add_column("Insights", style="yellow")
    table.add_column("Transforms", style="yellow")
    
    for result in results["results"]:
        table.add_row(
            result["puzzle"],
            result["analyzer"],
            f"{result['avg_time']:.4f}",
            f"{result['min_time']:.4f}",
            f"{result['max_time']:.4f}",
            f"{result['avg_insights']:.1f}",
            f"{result['avg_transforms']:.1f}",
        )
    
    console.print(table)


def save_results(results: Dict[str, Any], file_path: str):
    """
    Save benchmark results to a JSON file.
    
    Args:
        results: Benchmark results
        file_path: Path to save results
    """
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
    
    with open(file_path, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Benchmark results saved to {file_path}")


def plot_results(results: Dict[str, Any], output_path: Optional[str] = None):
    """
    Plot benchmark results.
    
    Args:
        results: Benchmark results
        output_path: Path to save plot
    """
    # Extract data for plotting
    analyzers = results["analyzers"]
    puzzles = results["puzzles"]
    
    # Organize data by analyzer and puzzle
    data = {}
    for analyzer in analyzers:
        data[analyzer] = {}
        for puzzle in puzzles:
            data[analyzer][puzzle] = None
    
    for result in results["results"]:
        analyzer = result["analyzer"]
        puzzle = result["puzzle"]
        avg_time = result["avg_time"]
        data[analyzer][puzzle] = avg_time
    
    # Create plot
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Plot data
    x = range(len(puzzles))
    width = 0.8 / len(analyzers)
    
    for i, analyzer in enumerate(analyzers):
        values = [data[analyzer][puzzle] if data[analyzer][puzzle] is not None else 0 for puzzle in puzzles]
        ax.bar([pos + i * width for pos in x], values, width, label=analyzer)
    
    # Set labels and title
    ax.set_xlabel("Puzzle")
    ax.set_ylabel("Average Execution Time (s)")
    ax.set_title("Analyzer Performance by Puzzle")
    ax.set_xticks([pos + (len(analyzers) - 1) * width / 2 for pos in x])
    ax.set_xticklabels(puzzles, rotation=45, ha="right")
    ax.legend()
    
    plt.tight_layout()
    
    # Save or display
    if output_path:
        plt.savefig(output_path, bbox_inches="tight")
        print(f"Plot saved to {output_path}")
    else:
        plt.show()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    try:
        # Get analyzers to test
        all_analyzers = get_all_analyzers()
        
        if args.analyzer:
            if args.analyzer not in all_analyzers:
                print(f"Error: Analyzer '{args.analyzer}' not found")
                return 1
            
            analyzers = {args.analyzer: all_analyzers[args.analyzer]}
        else:
            analyzers = all_analyzers
        
        # Get puzzle files
        puzzle_files = get_puzzle_files(args.puzzle_dir)
        
        # Run benchmarks
        results = run_benchmark(analyzers, puzzle_files, args.iterations)
        
        # Display results
        display_results(results)
        
        # Plot results
        plot_path = f"{args.output}.png" if args.output else None
        plot_results(results, plot_path)
        
        # Save results if requested
        if args.output:
            save_results(results, args.output)
    
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
