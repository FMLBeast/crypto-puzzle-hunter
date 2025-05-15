"""
Interactive session module for Crypto Hunter

This module provides the interactive session interface
for hands-on puzzle solving.
"""
import os
import sys
import cmd
import logging
import readline
import shlex
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from rich.console import Console
from rich.syntax import Syntax
from rich.panel import Panel
from rich.table import Table
from rich import box

import config
from core.state import State
from core.agent import CryptoAgent
from analyzers.base import get_all_analyzers, run_analyzer, get_analyzer
from ui.cli import console, print_error, print_warning, print_success

logger = logging.getLogger(__name__)


class InteractiveSession(cmd.Cmd):
    """
    Interactive session for Crypto Hunter.
    Provides a command-line interface for hands-on puzzle solving.
    """

    def __init__(self, agent: CryptoAgent, results_dir: str = "./results"):
        """
        Initialize the interactive session.

        Args:
            agent: The AI agent for analysis
            results_dir: Directory to store results
        """
        super().__init__()
        self.agent = agent
        self.results_dir = results_dir
        self.state: Optional[State] = None
        self.analyzers = get_all_analyzers()

        # Set up command prompt
        self.prompt = config.INTERACTIVE_CONFIG["prompt"]
        self.intro = config.INTERACTIVE_CONFIG["intro_text"]

        # Command history
        self.history_file = config.INTERACTIVE_CONFIG["history_file"]
        self._load_history()

    def _load_history(self):
        """Load command history from file."""
        try:
            if os.path.exists(self.history_file):
                readline.read_history_file(self.history_file)
                logger.debug(f"Loaded command history from {self.history_file}")
        except Exception as e:
            logger.warning(f"Could not load command history: {e}")

    def _save_history(self):
        """Save command history to file."""
        try:
            readline.write_history_file(self.history_file)
            logger.debug(f"Saved command history to {self.history_file}")
        except Exception as e:
            logger.warning(f"Could not save command history: {e}")

    def emptyline(self):
        """Do nothing on empty line."""
        pass

    def default(self, line: str):
        """Handle unknown commands."""
        print_error(f"Unknown command: {line}")
        print_warning("Type 'help' to see available commands")

    def do_exit(self, arg: str) -> bool:
        """Exit the interactive session."""
        self._save_history()
        console.print("Goodbye!")
        return True

    def do_quit(self, arg: str) -> bool:
        """Exit the interactive session."""
        return self.do_exit(arg)

    def do_eof(self, arg: str) -> bool:
        """Handle Ctrl+D."""
        console.print()
        return self.do_exit(arg)

    def do_load(self, arg: str):
        """
        Load a puzzle file.

        Usage: load <file_path>
        """
        args = shlex.split(arg)
        if not args:
            print_error("No file path provided")
            print_warning("Usage: load <file_path>")
            return

        file_path = args[0]
        if not os.path.exists(file_path):
            print_error(f"File not found: {file_path}")
            return

        try:
            self.state = State(puzzle_file=file_path)
            print_success(f"Loaded puzzle file: {file_path}")

            # Display basic file info
            file_info = Table(title="File Information", box=box.ROUNDED)
            file_info.add_column("Property", style="cyan")
            file_info.add_column("Value")

            file_info.add_row("File", os.path.basename(file_path))
            file_info.add_row("Type", self.state.file_type or "Unknown")
            file_info.add_row("Size", f"{self.state.file_size} bytes" if self.state.file_size else "Unknown")

            console.print(file_info)

            # If it's a text file, show a preview
            if self.state.puzzle_text and len(self.state.puzzle_text) <= 1000:
                syntax = Syntax(
                    self.state.puzzle_text,
                    "text",
                    theme="monokai",
                    line_numbers=True,
                    word_wrap=True,
                )
                console.print(Panel(syntax, title="Puzzle Text", border_style="green"))

        except Exception as e:
            print_error(f"Error loading file: {e}")
            logger.error(f"Error loading file: {e}", exc_info=True)

    def do_analyze(self, arg: str):
        """
        Run analysis on the loaded puzzle.

        Usage: analyze [analyzer_name] [--iterations=N]
        """
        if not self.state:
            print_error("No puzzle loaded. Use 'load' command first.")
            return

        args = shlex.split(arg)
        analyzer_name = None
        iterations = 10

        # Parse arguments
        for arg in args:
            if arg.startswith("--iterations="):
                try:
                    iterations = int(arg.split("=")[1])
                except ValueError:
                    print_error(f"Invalid iterations value: {arg}")
                    return
            elif not arg.startswith("--"):
                analyzer_name = arg

        try:
            if analyzer_name:
                # Run specific analyzer
                if analyzer_name not in self.analyzers:
                    print_error(f"Analyzer not found: {analyzer_name}")
                    print_warning(f"Available analyzers: {', '.join(self.analyzers.keys())}")
                    return

                console.print(f"Running analyzer: [cyan]{analyzer_name}[/cyan]")
                analyzers = {analyzer_name: self.analyzers[analyzer_name]}
                self.state = self.agent.analyze(
                    self.state, analyzers=analyzers, max_iterations=1
                )
            else:
                # Run full analysis
                console.print(f"Running analysis with [cyan]{iterations}[/cyan] iterations")
                self.state = self.agent.analyze(
                    self.state, max_iterations=iterations
                )

            # Display insights from the analysis
            if self.state.insights:
                insights_table = Table(title="Analysis Insights", box=box.ROUNDED)
                insights_table.add_column("Analyzer", style="magenta")
                insights_table.add_column("Insight", style="green")

                for insight in self.state.insights[-10:]:  # Show latest 10 insights
                    analyzer = insight["analyzer"] or "Unknown"
                    message = insight["message"]
                    insights_table.add_row(analyzer, message)

                console.print(insights_table)

            # Display solution if found
            if self.state.solution:
                console.print(
                    Panel(
                        f"[bold green]Solution found:[/bold green] {self.state.solution}",
                        title="Solution",
                        border_style="green",
                    )
                )

        except Exception as e:
            print_error(f"Error during analysis: {e}")
            logger.error(f"Error during analysis: {e}", exc_info=True)

    def do_insights(self, arg: str):
        """
        Display insights from analysis.

        Usage: insights [--limit=N]
        """
        if not self.state:
            print_error("No puzzle loaded. Use 'load' command first.")
            return

        if not self.state.insights:
            print_warning("No insights available yet. Run 'analyze' first.")
            return

        # Parse arguments
        args = shlex.split(arg)
        limit = 10

        for arg in args:
            if arg.startswith("--limit="):
                try:
                    limit = int(arg.split("=")[1])
                except ValueError:
                    print_error(f"Invalid limit value: {arg}")
                    return

        # Display insights
        insights_table = Table(title=f"Analysis Insights (showing {min(limit, len(self.state.insights))} of {len(self.state.insights)})", box=box.ROUNDED)
        insights_table.add_column("Time", style="dim")
        insights_table.add_column("Analyzer", style="magenta")
        insights_table.add_column("Insight", style="green")

        import datetime
        for insight in self.state.insights[-limit:]:
            timestamp = datetime.datetime.fromisoformat(insight["timestamp"]).strftime("%H:%M:%S")
            analyzer = insight["analyzer"] or "Unknown"
            message = insight["message"]
            insights_table.add_row(timestamp, analyzer, message)

        console.print(insights_table)

    def do_transforms(self, arg: str):
        """
        Display data transformations from analysis.

        Usage: transforms [--limit=N]
        """
        if not self.state:
            print_error("No puzzle loaded. Use 'load' command first.")
            return

        if not self.state.transformations:
            print_warning("No transformations available yet. Run 'analyze' first.")
            return

        # Parse arguments
        args = shlex.split(arg)
        limit = 10

        for arg in args:
            if arg.startswith("--limit="):
                try:
                    limit = int(arg.split("=")[1])
                except ValueError:
                    print_error(f"Invalid limit value: {arg}")
                    return

        # Display transformations
        transform_table = Table(title=f"Data Transformations (showing {min(limit, len(self.state.transformations))} of {len(self.state.transformations)})", box=box.ROUNDED)
        transform_table.add_column("Time", style="dim")
        transform_table.add_column("Transformation", style="yellow")
        transform_table.add_column("Description", style="cyan")

        import datetime
        for transform in self.state.transformations[-limit:]:
            timestamp = datetime.datetime.fromisoformat(transform["timestamp"]).strftime("%H:%M:%S")
            name = transform["name"]
            description = transform["description"]
            transform_table.add_row(timestamp, name, description)

        console.print(transform_table)

    def do_text(self, arg: str):
        """
        Display the current puzzle text.

        Usage: text [--limit=N]
        """
        if not self.state:
            print_error("No puzzle loaded. Use 'load' command first.")
            return

        if not self.state.puzzle_text:
            print_warning("No text data available for this puzzle.")
            return

        # Parse arguments
        args = shlex.split(arg)
        limit = 1000

        for arg in args:
            if arg.startswith("--limit="):
                try:
                    limit = int(arg.split("=")[1])
                except ValueError:
                    print_error(f"Invalid limit value: {arg}")
                    return

        # Display text
        text = self.state.puzzle_text
        if len(text) > limit:
            text = text[:limit] + f"... (truncated, {len(text) - limit} more characters)"

        syntax = Syntax(
            text,
            "text",
            theme="monokai",
            line_numbers=True,
            word_wrap=True,
        )
        console.print(Panel(syntax, title="Puzzle Text", border_style="green"))

    def do_save(self, arg: str):
        """
        Save the current state to a file.

        Usage: save [file_path]
        """
        if not self.state:
            print_error("No puzzle loaded. Use 'load' command first.")
            return

        args = shlex.split(arg)
        file_path = args[0] if args else os.path.join(self.results_dir, "interactive_session.json")

        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)

            # Save state
            self.state.save(file_path)
            print_success(f"State saved to {file_path}")

        except Exception as e:
            print_error(f"Error saving state: {e}")
            logger.error(f"Error saving state: {e}", exc_info=True)

    def do_load_state(self, arg: str):
        """
        Load a saved state from a file.

        Usage: load_state <file_path>
        """
        args = shlex.split(arg)
        if not args:
            print_error("No file path provided")
            print_warning("Usage: load_state <file_path>")
            return

        file_path = args[0]
        if not os.path.exists(file_path):
            print_error(f"File not found: {file_path}")
            return

        try:
            self.state = State.load(file_path)
            print_success(f"State loaded from {file_path}")

        except Exception as e:
            print_error(f"Error loading state: {e}")
            logger.error(f"Error loading state: {e}", exc_info=True)

    def do_ask(self, arg: str):
        """
        Ask the AI a question about the puzzle.

        Usage: ask <question>
        """
        if not arg.strip():
            print_error("No question provided")
            print_warning("Usage: ask <question>")
            return

        context = None
        if self.state:
            context = self._create_context_from_state()

        try:
            console.print("[italic]Thinking...[/italic]")
            response = self.agent.ask_llm(arg, context=context)

            console.print(Panel(
                response,
                title="AI Response",
                border_style="blue",
            ))

        except Exception as e:
            print_error(f"Error asking AI: {e}")
            logger.error(f"Error asking AI: {e}", exc_info=True)

    def do_interpret(self, arg: str):
        """
        Ask the AI to interpret the current puzzle data.

        Usage: interpret
        """
        if not self.state:
            print_error("No puzzle loaded. Use 'load' command first.")
            return

        data = self.state.puzzle_text if self.state.puzzle_text else self.state.puzzle_data
        if not data:
            print_error("No data available to interpret")
            return

        try:
            console.print("[italic]Analyzing data...[/italic]")
            interpretation = self.agent.interpret_data(data, self.state)

            console.print(Panel(
                interpretation,
                title="Data Interpretation",
                border_style="blue",
            ))

        except Exception as e:
            print_error(f"Error interpreting data: {e}")
            logger.error(f"Error interpreting data: {e}", exc_info=True)

    def do_solution(self, arg: str):
        """
        Set or display the solution for the current puzzle.

        Usage: solution [<solution_text>]
        """
        if not self.state:
            print_error("No puzzle loaded. Use 'load' command first.")
            return

        if not arg.strip():
            # Display current solution
            if self.state.solution:
                console.print(Panel(
                    self.state.solution,
                    title="Current Solution",
                    border_style="green",
                ))
            else:
                print_warning("No solution has been set yet")
        else:
            # Set new solution
            self.state.set_solution(arg.strip(), analyzer="user")
            print_success(f"Solution set: {arg.strip()}")

    def do_analyzers(self, arg: str):
        """
        List available analyzers and their descriptions.

        Usage: analyzers
        """
        analyzer_table = Table(title="Available Analyzers", box=box.ROUNDED)
        analyzer_table.add_column("Name", style="cyan")
        analyzer_table.add_column("Function")

        for name, func in self.analyzers.items():
            description = func.__doc__.split("\n")[0] if func.__doc__ else "No description available"
            analyzer_table.add_row(name, description)

        console.print(analyzer_table)

    def do_status(self, arg: str):
        """
        Display the current puzzle and analysis status.

        Usage: status
        """
        if not self.state:
            print_warning("No puzzle loaded. Use 'load' command first.")
            return

        status_table = Table(title="Puzzle Status", box=box.ROUNDED)
        status_table.add_column("Property", style="cyan")
        status_table.add_column("Value")

        status_table.add_row("File", self.state.puzzle_file or "N/A")
        status_table.add_row("Type", self.state.file_type or "N/A")
        status_table.add_row("Size", f"{self.state.file_size} bytes" if self.state.file_size else "N/A")
        status_table.add_row("Status", self.state.status)
        status_table.add_row("Insights", str(len(self.state.insights)))
        status_table.add_row("Transformations", str(len(self.state.transformations)))
        status_table.add_row("Analyzers Used", ", ".join(self.state.analyzers_used) or "None")

        if self.state.solution:
            status_table.add_row("Solution", self.state.solution)

        console.print(status_table)

    def _create_context_from_state(self) -> str:
        """
        Create context information from the current state.

        Returns:
            Context string for the AI
        """
        if not self.state:
            return ""

        context = [f"Puzzle file: {self.state.puzzle_file}"]
        context.append(f"File type: {self.state.file_type}")
        context.append(f"File size: {self.state.file_size} bytes")

        if self.state.insights:
            context.append("\nRecent insights:")
            for insight in self.state.insights[-5:]:
                context.append(f"- {insight['message']}")

        if self.state.transformations:
            context.append("\nRecent transformations:")
            for transform in self.state.transformations[-3:]:
                context.append(f"- {transform['name']}: {transform['description']}")

        return "\n".join(context)

    def start(self):
        """Start the interactive session."""
        try:
            # Initialize user interaction handler if available
            try:
                from core.user_interaction import start_user_interaction, register_callback

                # Register callback for handling questions
                def handle_question(question: str, context: dict) -> str:
                    """Handle user questions during interactive session."""
                    try:
                        # Create context from current state
                        state_context = self._create_context_from_state()

                        # Generate a response using the agent
                        response = self.agent.send_message(
                            f"The user has asked: '{question}'\n\nCurrent context:\n{state_context}\n\nPlease provide a helpful response."
                        )
                        return response or "I'm sorry, I couldn't generate a response at this time."
                    except Exception as e:
                        return f"Error processing your question: {str(e)}"

                # Register the callback
                register_callback("question_callback", handle_question)

                # Start listening for user input
                start_user_interaction()
                console.print("[dim]User interaction enabled. You can type a message at any time to interact with the agent.[/dim]")

            except ImportError:
                logger.warning("User interaction module not available. Running without interactive capabilities.")

            # Start the command loop
            self.cmdloop()

        except KeyboardInterrupt:
            console.print("\nInterrupted")
            self._save_history()
            return
        except Exception as e:
            print_error(f"Error in interactive session: {e}")
            logger.error(f"Error in interactive session: {e}", exc_info=True)
            self._save_history()
            return
