"""
Solution Logger Module
Provides real-time logging of the solution process.
"""

import time
from typing import Optional, Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

class SolutionLogger:
    """
    Class to handle real-time logging of the solution process.
    """
    def __init__(self, verbose: bool = False):
        """
        Initialize the solution logger.

        Args:
            verbose: Whether to output detailed logs
        """
        self.verbose = verbose
        self.insights: List[Dict[str, Any]] = []
        self.transformations: List[Dict[str, Any]] = []
        self.solution: Optional[str] = None

    def log_insight(self, text: str, analyzer: str, time_str: Optional[str] = None) -> None:
        """
        Log an insight in real-time.

        Args:
            text: Insight text
            analyzer: Name of the analyzer that generated the insight
            time_str: Optional time string (if not provided, current time will be used)
        """
        if not time_str:
            time_str = time.strftime("%H:%M:%S")

        insight = {
            "time": time_str,
            "analyzer": analyzer,
            "text": text
        }

        self.insights.append(insight)

        # Always print insights in real-time with proper formatting
        console.print()  # Ensure we start on a new line
        console.print(f"╭─ [bold cyan][{time_str}][/bold cyan] [bold green]{analyzer}[/bold green] ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮")
        console.print(f"│ {text}")
        console.print(f"╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯")

    def log_transformation(self, name: str, description: str, 
                          input_data: str, output_data: str, 
                          analyzer: str, time_str: Optional[str] = None) -> None:
        """
        Log a transformation in real-time.

        Args:
            name: Name of the transformation
            description: Description of what the transformation does
            input_data: Input data for the transformation
            output_data: Output data from the transformation
            analyzer: Name of the analyzer that performed the transformation
            time_str: Optional time string (if not provided, current time will be used)
        """
        if not time_str:
            time_str = time.strftime("%H:%M:%S")

        transformation = {
            "time": time_str,
            "name": name,
            "description": description,
            "input_data": input_data,
            "output_data": output_data,
            "analyzer": analyzer
        }

        self.transformations.append(transformation)

        # Always print transformations in real-time with consistent formatting
        console.print()  # Ensure we start on a new line
        console.print(f"╭─ [bold cyan][{time_str}][/bold cyan] [bold green]{analyzer}[/bold green] ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮")
        console.print(f"│ {name}")
        console.print(f"│ {description}")
        console.print(f"│ ")
        console.print(f"│ Input: {input_data[:100]}{'...' if len(input_data) > 100 else ''}")
        console.print(f"│ Output: {output_data[:100]}{'...' if len(output_data) > 100 else ''}")
        console.print(f"╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯")

    def log_solution(self, solution: str) -> None:
        """
        Log the solution in real-time.

        Args:
            solution: Solution to the puzzle
        """
        self.solution = solution

        # Always print the solution in real-time with consistent formatting
        console.print()  # Ensure we start on a new line
        console.print(f"╭─ [bold cyan]SOLUTION FOUND[/bold cyan] ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮")
        console.print(f"│ ")
        console.print(f"│ [bold green]{solution}[/bold green]")
        console.print(f"│ ")
        console.print(f"╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯")

    def get_insights(self) -> List[Dict[str, Any]]:
        """
        Get all logged insights.

        Returns:
            List of insights
        """
        return self.insights

    def get_transformations(self) -> List[Dict[str, Any]]:
        """
        Get all logged transformations.

        Returns:
            List of transformations
        """
        return self.transformations

    def get_solution(self) -> Optional[str]:
        """
        Get the logged solution.

        Returns:
            Solution or None if not found
        """
        return self.solution

# Global instance of the solution logger
solution_logger = SolutionLogger()
