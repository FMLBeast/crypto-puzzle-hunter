#!/usr/bin/env python3
"""
Result Visualization Tool for Crypto Hunter

This tool visualizes analysis results from Crypto Hunter.
"""
import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

import matplotlib.pyplot as plt
import networkx as nx
from rich.console import Console
from rich.table import Table
from rich import box
from rich.syntax import Syntax

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.state import State


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Visualize Crypto Hunter analysis results"
    )
    parser.add_argument(
        "--result-file",
        type=str,
        required=True,
        help="Path to result JSON file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to save visualization (default: display only)",
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["graph", "timeline", "table"],
        default="graph",
        help="Visualization format (default: graph)",
    )
    
    return parser.parse_args()


def load_result(file_path: str) -> Dict[str, Any]:
    """
    Load analysis result from JSON file.
    
    Args:
        file_path: Path to result file
        
    Returns:
        Result data as dictionary
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Result file not found: {file_path}")
    
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON in result file: {file_path}")


def visualize_as_graph(result: Dict[str, Any], output_path: Optional[str] = None):
    """
    Visualize the analysis as a graph.
    
    Args:
        result: Analysis result data
        output_path: Path to save the visualization
    """
    # Create a directed graph
    G = nx.DiGraph()
    
    # Add nodes for the puzzle file
    puzzle_name = os.path.basename(result.get("puzzle_file", "Unknown Puzzle"))
    G.add_node(puzzle_name, type="puzzle", color="lightblue", size=1500)
    
    # Add nodes for insights
    insights = result.get("insights", [])
    for i, insight in enumerate(insights):
        node_id = f"Insight {i+1}"
        G.add_node(node_id, type="insight", color="lightgreen", size=1000)
        G.add_edge(puzzle_name, node_id, weight=1)
    
    # Add nodes for transformations
    transformations = result.get("transformations", [])
    for i, transform in enumerate(transformations):
        node_id = f"Transform {i+1}"
        G.add_node(node_id, type="transform", color="lightyellow", size=1000)
        G.add_edge(puzzle_name, node_id, weight=1)
    
    # Add solution node if available
    solution = result.get("solution")
    if solution:
        G.add_node("Solution", type="solution", color="lightcoral", size=1500)
        G.add_edge(puzzle_name, "Solution", weight=2)
    
    # Set node attributes for visualization
    node_colors = [G.nodes[n]["color"] for n in G.nodes()]
    node_sizes = [G.nodes[n]["size"] for n in G.nodes()]
    
    # Create plot
    plt.figure(figsize=(12, 10))
    pos = nx.spring_layout(G, seed=42)
    nx.draw_networkx(
        G,
        pos,
        node_color=node_colors,
        node_size=node_sizes,
        font_size=10,
        font_weight="bold",
        arrows=True,
        width=1.5,
    )
    
    # Set title
    plt.title(f"Analysis Graph for {puzzle_name}")
    plt.axis("off")
    
    # Save or display
    if output_path:
        plt.savefig(output_path, bbox_inches="tight")
        print(f"Graph visualization saved to {output_path}")
    else:
        plt.show()


def visualize_as_timeline(result: Dict[str, Any], output_path: Optional[str] = None):
    """
    Visualize the analysis as a timeline.
    
    Args:
        result: Analysis result data
        output_path: Path to save the visualization
    """
    # Extract timestamps and events
    events = []
    
    # Add insights
    for insight in result.get("insights", []):
        events.append({
            "time": insight.get("timestamp"),
            "type": "Insight",
            "analyzer": insight.get("analyzer", "Unknown"),
            "description": insight.get("message"),
        })
    
    # Add transformations
    for transform in result.get("transformations", []):
        events.append({
            "time": transform.get("timestamp"),
            "type": "Transformation",
            "analyzer": transform.get("analyzer", "Unknown"),
            "description": transform.get("description"),
        })
    
    # Sort events by time
    events.sort(key=lambda x: x["time"] if x["time"] else "")
    
    # Create figure
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Plot events
    y_positions = {}
    y_counter = 0
    
    for i, event in enumerate(events):
        event_type = event["type"]
        if event_type not in y_positions:
            y_positions[event_type] = y_counter
            y_counter += 1
        
        y = y_positions[event_type]
        
        # Parse timestamp
        time_str = event["time"]
        if time_str:
            try:
                timestamp = datetime.fromisoformat(time_str)
                x = timestamp.timestamp()
            except:
                x = i
        else:
            x = i
        
        # Plot point
        color = "green" if event_type == "Insight" else "orange"
        ax.scatter(x, y, color=color, s=100, zorder=2)
        
        # Add label
        ax.annotate(
            event["description"][:30] + "..." if len(event["description"]) > 30 else event["description"],
            (x, y),
            xytext=(5, 0),
            textcoords="offset points",
            fontsize=8,
            va="center",
        )
    
    # Set y-ticks to event types
    ax.set_yticks(list(y_positions.values()))
    ax.set_yticklabels(list(y_positions.keys()))
    
    # Set title and labels
    puzzle_name = os.path.basename(result.get("puzzle_file", "Unknown Puzzle"))
    ax.set_title(f"Analysis Timeline for {puzzle_name}")
    ax.set_xlabel("Time")
    ax.grid(True, axis="y", linestyle="--", alpha=0.7)
    
    # Format x-axis if timestamps
    if events and "timestamp" in events[0]:
        plt.tight_layout()
    
    # Save or display
    if output_path:
        plt.savefig(output_path, bbox_inches="tight")
        print(f"Timeline visualization saved to {output_path}")
    else:
        plt.show()


def visualize_as_table(result: Dict[str, Any]):
    """
    Visualize the analysis as a rich table.
    
    Args:
        result: Analysis result data
    """
    console = Console()
    
    # Display puzzle information
    puzzle_info = Table(title="Puzzle Information", box=box.ROUNDED)
    puzzle_info.add_column("Property", style="cyan")
    puzzle_info.add_column("Value")
    
    puzzle_info.add_row("File", result.get("puzzle_file", "N/A"))
    puzzle_info.add_row("Type", result.get("file_type", "N/A"))
    puzzle_info.add_row("Size", f"{result.get('file_size', 'N/A')} bytes" if result.get("file_size") else "N/A")
    puzzle_info.add_row("Hash", result.get("hash", "N/A"))
    puzzle_info.add_row("Status", result.get("status", "N/A"))
    
    if result.get("solution"):
        puzzle_info.add_row("Solution", result.get("solution"))
    
    console.print(puzzle_info)
    console.print()
    
    # Display insights
    if result.get("insights"):
        insights_table = Table(title="Analysis Insights", box=box.ROUNDED)
        insights_table.add_column("Time", style="dim")
        insights_table.add_column("Analyzer", style="magenta")
        insights_table.add_column("Insight", style="green")
        
        for insight in result.get("insights", []):
            timestamp = datetime.fromisoformat(insight.get("timestamp", "")).strftime("%H:%M:%S") \
                if insight.get("timestamp") else ""
            analyzer = insight.get("analyzer", "Unknown")
            message = insight.get("message", "")
            insights_table.add_row(timestamp, analyzer, message)
        
        console.print(insights_table)
        console.print()
    
    # Display transformations
    if result.get("transformations"):
        transform_table = Table(title="Data Transformations", box=box.ROUNDED)
        transform_table.add_column("Time", style="dim")
        transform_table.add_column("Transformation", style="yellow")
        transform_table.add_column("Description", style="cyan")
        
        for transform in result.get("transformations", []):
            timestamp = datetime.fromisoformat(transform.get("timestamp", "")).strftime("%H:%M:%S") \
                if transform.get("timestamp") else ""
            name = transform.get("name", "")
            description = transform.get("description", "")
            transform_table.add_row(timestamp, name, description)
        
        console.print(transform_table)
        console.print()
    
    # Display analyzers used
    analyzers_used = Table(title="Analyzers Used", box=box.ROUNDED)
    analyzers_used.add_column("Analyzer", style="blue")
    
    for analyzer in result.get("analyzers_used", []):
        analyzers_used.add_row(analyzer)
    
    console.print(analyzers_used)
    console.print()
    
    # Display the puzzle text preview if available
    if result.get("puzzle_text"):
        text_preview = result.get("puzzle_text")
        if len(text_preview) > 1000:
            text_preview = text_preview[:1000] + "... (truncated)"
        
        syntax = Syntax(
            text_preview,
            "text",
            theme="monokai",
            line_numbers=True,
            word_wrap=True,
        )
        console.print("\nPuzzle Text Preview:")
        console.print(syntax)


def main():
    """Main entry point."""
    args = parse_arguments()
    
    try:
        # Load the result
        result = load_result(args.result_file)
        
        # Visualize based on format
        if args.format == "graph":
            visualize_as_graph(result, args.output)
        elif args.format == "timeline":
            visualize_as_timeline(result, args.output)
        elif args.format == "table":
            visualize_as_table(result)
    
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
