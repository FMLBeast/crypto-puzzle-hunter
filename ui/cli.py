"""
Command-line interface module for Crypto Hunter

This module provides the CLI interface for displaying information
and results to the user.
"""
import os
import sys
import logging
import json
import logging.config
from typing import Dict, List, Any, Optional
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.logging import RichHandler
from rich import box

import config
from core.state import State

# Initialize Rich console
console = Console()


def setup_logging(verbose: bool = False):
    """
    Set up logging configuration.

    Args:
        verbose: Whether to enable verbose logging
    """
    log_config = config.LOGGING_CONFIG.copy()
    
    # Set log level based on verbosity
    if verbose:
        log_config["handlers"]["console"]["level"] = "DEBUG"
        log_config["loggers"][""]["level"] = "DEBUG"
    
    # Configure Rich handler for console output
    logging.config.dictConfig(log_config)
    
    # Replace console handler with Rich handler
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, RichHandler):
            root_logger.removeHandler(handler)
            rich_handler = RichHandler(rich_tracebacks=True, show_time=False)
            rich_handler.setLevel(handler.level)
            root_logger.addHandler(rich_handler)


def display_banner():
    """Display the Crypto Hunter banner."""
    banner = f"""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║   [bold cyan]Crypto Hunter v{config.VERSION}[/bold cyan]                                        ║
    ║   [italic]The Ultimate Cryptographic Puzzle Solver[/italic]                     ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """
    console.print(banner)
    console.print()


def display_results(state: State):
    """
    Display analysis results to the console.

    Args:
        state: The current puzzle state
    """
    console.print("[bold green]Analysis Results[/bold green]")
    console.print()
    
    # Display puzzle information
    puzzle_info = Table(title="Puzzle Information", box=box.ROUNDED)
    puzzle_info.add_column("Property", style="cyan")
    puzzle_info.add_column("Value")
    
    puzzle_info.add_row("File", state.puzzle_file or "N/A")
    puzzle_info.add_row("Type", state.file_type or "N/A")
    puzzle_info.add_row("Size", f"{state.file_size} bytes" if state.file_size else "N/A")
    puzzle_info.add_row("Hash", state.hash or "N/A")
    puzzle_info.add_row("Status", state.status)
    
    if state.solution:
        puzzle_info.add_row("Solution", state.solution)
    
    console.print(puzzle_info)
    console.print()
    
    # Display insights
    if state.insights:
        insights_table = Table(title="Analysis Insights", box=box.ROUNDED)
        insights_table.add_column("Time", style="dim")
        insights_table.add_column("Analyzer", style="magenta")
        insights_table.add_column("Insight", style="green")
        
        for insight in state.insights:
            timestamp = datetime.fromisoformat(insight["timestamp"]).strftime("%H:%M:%S")
            analyzer = insight["analyzer"] or "Unknown"
            message = insight["message"]
            insights_table.add_row(timestamp, analyzer, message)
        
        console.print(insights_table)
        console.print()
    
    # Display transformations
    if state.transformations:
        transform_table = Table(title="Data Transformations", box=box.ROUNDED)
        transform_table.add_column("Time", style="dim")
        transform_table.add_column("Transformation", style="yellow")
        transform_table.add_column("Description", style="cyan")
        
        for transform in state.transformations:
            timestamp = datetime.fromisoformat(transform["timestamp"]).strftime("%H:%M:%S")
            name = transform["name"]
            description = transform["description"]
            transform_table.add_row(timestamp, name, description)
        
        console.print(transform_table)
        console.print()
    
    # Display analyzers used
    analyzers_used = Table(title="Analyzers Used", box=box.ROUNDED)
    analyzers_used.add_column("Analyzer", style="blue")
    
    for analyzer in state.analyzers_used:
        analyzers_used.add_row(analyzer)
    
    console.print(analyzers_used)
    console.print()
    
    # Display the puzzle text preview if available
    if state.puzzle_text:
        text_preview = state.puzzle_text
        if len(text_preview) > 1000:
            text_preview = text_preview[:1000] + "... (truncated)"
        
        syntax = Syntax(
            text_preview,
            "text",
            theme="monokai",
            line_numbers=True,
            word_wrap=True,
        )
        console.print(Panel(syntax, title="Puzzle Text Preview", border_style="green"))
        console.print()
    
    # Display summary and next steps
    if state.solution:
        console.print(
            Panel(
                f"[bold green]Solution found:[/bold green] {state.solution}",
                title="Solution",
                border_style="green",
            )
        )
    else:
        # Suggest next steps if no solution found
        console.print(
            Panel(
                "No definitive solution found yet. Consider the following options:\n"
                "1. Run with more iterations (--iterations N)\n"
                "2. Try specific analyzers (--analyzer NAME)\n"
                "3. Use interactive mode (--interactive)\n"
                "4. Examine the insights and transformations for clues",
                title="Next Steps",
                border_style="yellow",
            )
        )


def display_analyzer_help():
    """Display help information about available analyzers."""
    analyzer_help = Table(title="Available Analyzers", box=box.ROUNDED)
    analyzer_help.add_column("Name", style="cyan")
    analyzer_help.add_column("Description")
    analyzer_help.add_column("Best For", style="magenta")
    
    # Add rows for each analyzer
    analyzer_help.add_row(
        "text_analyzer",
        "Analyzes text for patterns, encodings, and cryptographic schemes",
        "Text-based puzzles, substitution ciphers, encodings",
    )
    analyzer_help.add_row(
        "binary_analyzer",
        "Analyzes binary files for hidden data and file structure",
        "Binary files, steganography, hidden data extraction",
    )
    analyzer_help.add_row(
        "image_analyzer", 
        "Analyzes images for steganography and hidden data",
        "Image steganography, metadata analysis, pixel manipulation",
    )
    analyzer_help.add_row(
        "blockchain_analyzer",
        "Analyzes blockchain addresses and transaction data",
        "Ethereum/Bitcoin puzzles, smart contract analysis",
    )
    analyzer_help.add_row(
        "cipher_analyzer",
        "Specialized analysis for specific cipher types",
        "AES, RSA, Vigenère, and other structured ciphers",
    )
    analyzer_help.add_row(
        "encoding_analyzer",
        "Detects and decodes various encoding schemes",
        "Multi-layered encodings, custom encoding schemes",
    )
    
    console.print(analyzer_help)
    console.print()


def save_results_to_file(state: State, file_path: str):
    """
    Save analysis results to a file.

    Args:
        state: The current puzzle state
        file_path: Path to save the results
    """
    try:
        with open(file_path, "w") as f:
            json.dump(state.to_dict(), f, indent=2)
        console.print(f"[green]Results saved to {file_path}[/green]")
    except Exception as e:
        console.print(f"[red]Error saving results: {e}[/red]")


def print_error(message: str):
    """
    Print an error message.

    Args:
        message: The error message
    """
    console.print(f"[bold red]Error:[/bold red] {message}")


def print_warning(message: str):
    """
    Print a warning message.

    Args:
        message: The warning message
    """
    console.print(f"[bold yellow]Warning:[/bold yellow] {message}")


def print_success(message: str):
    """
    Print a success message.

    Args:
        message: The success message
    """
    console.print(f"[bold green]Success:[/bold green] {message}")


def display_progress(current: int, total: int, message: str = "Processing"):
    """
    Display a progress bar.

    Args:
        current: Current progress value
        total: Total progress value
        message: Progress message
    """
    from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn
    
    with Progress(
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(message, total=total)
        progress.update(task, completed=current)
