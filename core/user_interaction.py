"""
User Interaction Module
Provides functionality for handling user input during agent processing.
"""

import threading
import queue
import time
from typing import Optional, Callable, Dict, Any, List
from rich.console import Console
from rich.prompt import Prompt

# Console for user interaction
console = Console()

class UserInteractionHandler:
    """
    Handles user interaction during agent processing.
    Allows users to interrupt and interact with the agent at any time.
    """

    def __init__(self):
        """Initialize the user interaction handler."""
        self.input_queue = queue.Queue()
        self.response_queue = queue.Queue()
        self.is_listening = False
        self.listener_thread = None
        self.callbacks = {}
        self.current_context = {}

    def start_listening(self):
        """Start listening for user input in a separate thread."""
        if self.is_listening:
            return

        self.is_listening = True
        self.listener_thread = threading.Thread(target=self._input_listener, daemon=True)
        self.listener_thread.start()
        console.print("[dim]User interaction enabled. Type a message at any time to interact with the agent.[/dim]")

    def stop_listening(self):
        """Stop listening for user input."""
        self.is_listening = False
        if self.listener_thread and self.listener_thread.is_alive():
            # The thread is daemon, so it will terminate when the main thread exits
            self.listener_thread = None

    def _input_listener(self):
        """Thread function that listens for user input."""
        import sys
        import select
        import os

        # Check if we're on Windows
        is_windows = os.name == 'nt'

        if is_windows:
            # Windows doesn't support select on stdin, use a simpler approach
            while self.is_listening:
                try:
                    console.print("\n[bold cyan]>>> [/bold cyan]", end="")
                    user_input = input()
                    if user_input.strip():
                        self.input_queue.put(user_input)
                except Exception as e:
                    console.print(f"[red]Error in input listener: {e}[/red]")
                    time.sleep(1)  # Longer sleep on error
        else:
            # Unix-like systems can use select for non-blocking input
            while self.is_listening:
                try:
                    # Check if input is available
                    console.print("\n[bold cyan]>>> [/bold cyan]", end="")
                    rlist, _, _ = select.select([sys.stdin], [], [], 0.1)

                    if rlist:
                        user_input = sys.stdin.readline().strip()
                        if user_input:
                            self.input_queue.put(user_input)

                    time.sleep(0.1)  # Small sleep to prevent high CPU usage
                except Exception as e:
                    console.print(f"[red]Error in input listener: {e}[/red]")
                    time.sleep(1)  # Longer sleep on error

    def check_for_input(self) -> Optional[str]:
        """
        Check if there's any user input available.

        Returns:
            User input string if available, None otherwise
        """
        try:
            return self.input_queue.get_nowait()
        except queue.Empty:
            return None

    def process_input(self, user_input: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process user input and return a response.

        Args:
            user_input: The user input to process
            context: Current context information

        Returns:
            Updated context with response information
        """
        self.current_context = context.copy()

        # Check for special commands
        if user_input.lower().startswith("help"):
            return self._handle_help_command()
        elif user_input.lower().startswith("status"):
            return self._handle_status_command()

        # Process as a question or instruction for the agent
        console.print("[yellow]Processing your request...[/yellow]")

        # Call the appropriate callback if registered
        if "question_callback" in self.callbacks:
            response = self.callbacks["question_callback"](user_input, context)
            console.print(f"[green]Agent response:[/green] {response}")

            # Update context with the interaction
            context["last_interaction"] = {
                "user_input": user_input,
                "agent_response": response,
                "timestamp": time.time()
            }

            # Add to interaction history
            if "interaction_history" not in context:
                context["interaction_history"] = []
            context["interaction_history"].append(context["last_interaction"])

        return context

    def _handle_help_command(self) -> Dict[str, Any]:
        """Handle the help command."""
        console.print("""
        [bold]Available commands:[/bold]

        [cyan]help[/cyan] - Show this help message
        [cyan]status[/cyan] - Show current status of the agent

        You can also ask questions or provide instructions directly to the agent.
        The agent will prioritize your requests while maintaining the context of the current task.
        """)
        return self.current_context

    def _handle_status_command(self) -> Dict[str, Any]:
        """Handle the status command."""
        if not self.current_context:
            console.print("[yellow]No active context available.[/yellow]")
            return {}

        console.print("[bold]Current Status:[/bold]")

        # Display relevant context information
        if "current_task" in self.current_context:
            console.print(f"Current task: {self.current_context['current_task']}")

        if "progress" in self.current_context:
            console.print(f"Progress: {self.current_context['progress']}")

        if "insights" in self.current_context and self.current_context["insights"]:
            console.print("[bold]Recent insights:[/bold]")
            for insight in self.current_context["insights"][-3:]:
                console.print(f"- {insight}")

        return self.current_context

    def register_callback(self, name: str, callback: Callable):
        """
        Register a callback function.

        Args:
            name: Name of the callback
            callback: Callback function
        """
        self.callbacks[name] = callback

    def set_context(self, context: Dict[str, Any]):
        """
        Set the current context.

        Args:
            context: Context information
        """
        self.current_context = context.copy()

# Global instance of the user interaction handler
interaction_handler = UserInteractionHandler()

def start_user_interaction():
    """Start the user interaction handler."""
    interaction_handler.start_listening()

def stop_user_interaction():
    """Stop the user interaction handler."""
    interaction_handler.stop_listening()

def check_for_user_input() -> Optional[str]:
    """
    Check if there's any user input available.

    Returns:
        User input string if available, None otherwise
    """
    return interaction_handler.check_for_input()

def process_user_input(user_input: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process user input and return a response.

    Args:
        user_input: The user input to process
        context: Current context information

    Returns:
        Updated context with response information
    """
    return interaction_handler.process_input(user_input, context)

def register_callback(name: str, callback: Callable):
    """
    Register a callback function.

    Args:
        name: Name of the callback
        callback: Callback function
    """
    interaction_handler.register_callback(name, callback)

def set_context(context: Dict[str, Any]):
    """
    Set the current context.

    Args:
        context: Context information
    """
    interaction_handler.set_context(context)
