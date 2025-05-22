"""
Interactive session module for Crypto Hunter.
Provides an interactive shell for puzzle solving.
"""

import cmd
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.state import State
from core.agent import CryptoAgent
from analyzers import get_all_analyzers, get_analyzer

console = Console()

class InteractiveSession(cmd.Cmd):
    """Interactive command-line session for Crypto Hunter."""

    intro = """
    Welcome to Crypto Hunter Interactive Mode!
    Type 'help' or '?' to list commands.
    """
    prompt = 'crypto-hunter> '

    def __init__(self, agent: CryptoAgent = None):
        super().__init__()
        self.agent = agent or CryptoAgent()
        self.state = State()
        self.history = []

    def do_load(self, line):
        """Load a puzzle file: load <filepath>"""
        if not line:
            console.print("[red]Usage: load <filepath>[/red]")
            return

        try:
            path = Path(line.strip())
            if not path.exists():
                console.print(f"[red]File not found: {path}[/red]")
                return

            self.state = State(puzzle_file=str(path))
            console.print(f"[green]Loaded: {path.name}[/green]")
            console.print(f"Type: {self.state.file_type}, Size: {self.state.file_size} bytes")
        except Exception as e:
            console.print(f"[red]Error loading file: {e}[/red]")

    def do_analyze(self, line):
        """Run analysis: analyze [analyzer_name] [iterations]"""
        parts = line.strip().split()
        analyzer_name = parts[0] if parts else None
        iterations = int(parts[1]) if len(parts) > 1 else 5

        if not self.state.puzzle_file:
            console.print("[red]No puzzle loaded. Use 'load <filepath>' first.[/red]")
            return

        try:
            if analyzer_name:
                analyzer_func = get_analyzer(analyzer_name)
                if analyzer_func:
                    console.print(f"[blue]Running {analyzer_name}...[/blue]")
                    self.state = analyzer_func(self.state)
                else:
                    console.print(f"[red]Analyzer '{analyzer_name}' not found[/red]")
            else:
                console.print(f"[blue]Running full analysis ({iterations} iterations)...[/blue]")
                self.state = self.agent.analyze(self.state, max_iterations=iterations)

            self._show_results()
        except Exception as e:
            console.print(f"[red]Analysis failed: {e}[/red]")

    def do_status(self, line):
        """Show current puzzle status"""
        if not self.state.puzzle_file:
            console.print("[yellow]No puzzle loaded[/yellow]")
            return

        console.print(Panel(self.state.get_summary(), title="Puzzle Status"))

    def do_insights(self, line):
        """Show all insights: insights [count]"""
        count = int(line.strip()) if line.strip().isdigit() else None
        insights = self.state.insights[-count:] if count else self.state.insights

        if not insights:
            console.print("[yellow]No insights yet[/yellow]")
            return

        table = Table(title="Insights")
        table.add_column("Time", style="dim")
        table.add_column("Analyzer", style="magenta")
        table.add_column("Insight", style="green")

        for insight in insights:
            table.add_row(
                insight.get("time", ""),
                insight.get("analyzer", ""),
                insight.get("message", "")
            )

        console.print(table)

    def do_transformations(self, line):
        """Show transformations: transformations [count]"""
        count = int(line.strip()) if line.strip().isdigit() else None
        transforms = self.state.transformations[-count:] if count else self.state.transformations

        if not transforms:
            console.print("[yellow]No transformations yet[/yellow]")
            return

        for i, transform in enumerate(transforms, 1):
            console.print(Panel(
                f"[bold]{transform.get('name', 'Transformation')}[/bold]\n"
                f"{transform.get('description', '')}\n\n"
                f"[dim]Input:[/dim] {transform.get('input_data', '')[:100]}{'...' if len(str(transform.get('input_data', ''))) > 100 else ''}\n"
                f"[dim]Output:[/dim] {transform.get('output_data', '')[:100]}{'...' if len(str(transform.get('output_data', ''))) > 100 else ''}",
                title=f"Transformation {i}"
            ))

    def do_analyzers(self, line):
        """List available analyzers"""
        analyzers = get_all_analyzers()

        table = Table(title="Available Analyzers")
        table.add_column("Name", style="cyan")
        table.add_column("Used", style="green")

        for name in sorted(analyzers.keys()):
            used = "✓" if name in self.state.analyzers_used else ""
            table.add_row(name, used)

        console.print(table)

    def do_solution(self, line):
        """Show solution if found"""
        if self.state.solution:
            console.print(Panel(
                f"[bold green]{self.state.solution}[/bold green]",
                title="Solution Found!"
            ))
        else:
            console.print("[yellow]No solution found yet[/yellow]")

    def do_reset(self, line):
        """Reset the current session"""
        self.state = State()
        console.print("[green]Session reset[/green]")

    def do_exit(self, line):
        """Exit the interactive session"""
        console.print("[blue]Goodbye![/blue]")
        return True

    def do_quit(self, line):
        """Exit the interactive session"""
        return self.do_exit(line)

    def _show_results(self):
        """Show brief analysis results"""
        if self.state.solution:
            console.print(Panel(
                f"[bold green]SOLUTION: {self.state.solution}[/bold green]",
                title="Success!"
            ))

        recent_insights = self.state.insights[-5:] if len(self.state.insights) > 5 else self.state.insights
        if recent_insights:
            console.print("\n[bold]Recent Insights:[/bold]")
            for insight in recent_insights:
                console.print(f"• {insight.get('message', '')}")

    def emptyline(self):
        """Override to do nothing on empty line"""
        pass

def start_interactive_session(agent: CryptoAgent = None):
    """Start an interactive session"""
    session = InteractiveSession(agent)
    try:
        session.cmdloop()
    except KeyboardInterrupt:
        console.print("\n[blue]Goodbye![/blue]")
    except Exception as e:
        console.print(f"[red]Session error: {e}[/red]")