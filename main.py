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
from core.utils import browse_puzzles, get_puzzle_info, setup_logging
from web_agent import WebAgent
from code_agent import CodeAgent

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
    parser.add_argument("--iterations", type=int, default=5, help="Maximum number of analysis iterations")
    parser.add_argument("--provider", type=str, default="anthropic", 
                        choices=["anthropic", "openai", "huggingface", "local"],
                        help="LLM provider to use")
    parser.add_argument("--model", type=str, help="Specific model to use with provider")
    parser.add_argument("--api-key", type=str, help="API key for the LLM provider")
    parser.add_argument("--analyzer", type=str, help="Use a specific analyzer")
    parser.add_argument("--use-web", action="store_true", help="Enable web browsing agent")
    parser.add_argument("--use-code", action="store_true", help="Enable code generation agent")
    parser.add_argument("--tools-dir", type=str, default="./dynamic_tools", 
                        help="Directory for storing dynamic tools")
    
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

def interactive_menu():
    """Display the interactive menu."""
    console.print("Please select how you would like to proceed:")
    console.print("  1. Browse puzzle collection")
    console.print("  2. Interactive mode")
    console.print("  3. Advanced tools")
    console.print("  4. Exit")
    
    choice = Prompt.ask("Select an option [1/2/3/4]", choices=["1", "2", "3", "4"], default="1")
    
    if choice == "1":
        return "browse"
    elif choice == "2":
        return "interactive"
    elif choice == "3":
        return "advanced"
    else:
        return "exit"

def advanced_tools_menu():
    """Display the advanced tools menu."""
    console.print("\n[bold]Advanced Tools[/bold]")
    console.print("  1. Web browsing assistant")
    console.print("  2. Code generation assistant")
    console.print("  3. Create custom analyzer")
    console.print("  4. Back to main menu")
    
    choice = Prompt.ask("Select an option [1/2/3/4]", choices=["1", "2", "3", "4"], default="1")
    
    if choice == "1":
        run_web_assistant()
    elif choice == "2":
        run_code_assistant()
    elif choice == "3":
        create_custom_analyzer()
    
    return interactive_menu()

def run_web_assistant():
    """Run the web browsing assistant."""
    console.print("\n[bold]Web Browsing Assistant[/bold]")
    console.print("This tool allows you to search the web for information related to the puzzle.")
    
    # Initialize web agent
    web_agent = WebAgent()
    
    while True:
        query = Prompt.ask("\nEnter a search query (or 'exit' to return)")
        
        if query.lower() == "exit":
            break
        
        console.print("[yellow]Searching the web...[/yellow]")
        results = web_agent.search(query)
        
        if not results:
            console.print("[red]No results found.[/red]")
            continue
        
        # Display results
        console.print("\n[bold]Search Results:[/bold]")
        for i, result in enumerate(results, 1):
            console.print(f"[bold cyan]{i}. {result['title']}[/bold cyan]")
            console.print(f"   URL: {result['url']}")
            console.print(f"   {result['snippet']}\n")
        
        # Ask which result to analyze
        choice = Prompt.ask(
            "Enter result number to analyze (or 'n' to search again)",
            default="n"
        )
        
        if choice.lower() == "n":
            continue
        
        try:
            index = int(choice) - 1
            if 0 <= index < len(results):
                url = results[index]["url"]
                console.print(f"[yellow]Fetching content from {url}...[/yellow]")
                
                html = web_agent.fetch_url(url)
                if html:
                    text = web_agent.extract_text(html)
                    
                    # Print a summary
                    console.print("\n[bold]Content Summary:[/bold]")
                    summary = text[:800] + "..." if len(text) > 800 else text
                    console.print(summary)
                    
                    # Look for cryptographic techniques
                    crypto_patterns = [
                        (r'\b(aes|rijndael)\b', "AES Encryption"),
                        (r'\b(rsa)\b', "RSA Encryption"),
                        (r'\b(des|3des|triple des)\b', "DES Encryption"),
                        (r'\b(blowfish)\b', "Blowfish"),
                        (r'\b(twofish)\b', "Twofish"),
                        (r'\b(sha-?1|sha-?256|sha-?512|md5)\b', "Hash Functions"),
                        (r'\b(base64|base32|base16)\b', "Base Encoding"),
                        (r'\b(xor)\b', "XOR Cipher"),
                        (r'\b(caesar|rot13)\b', "Caesar/ROT Cipher"),
                        (r'\b(vigenere|vigenère)\b', "Vigenère Cipher"),
                        (r'\b(substitution cipher)\b', "Substitution Cipher"),
                        (r'\b(steganography)\b', "Steganography"),
                        (r'\b(blockchain|bitcoin|ethereum)\b', "Blockchain"),
                        (r'\b(pgp|gpg)\b', "PGP/GPG Encryption"),
                        (r'\b(hmac)\b', "HMAC"),
                        (r'\b(elliptic curve|ecc|ecdsa)\b', "Elliptic Curve Cryptography"),
                        (r'\b(diffie-hellman)\b', "Diffie-Hellman"),
                        (r'\b(one-time pad|otp)\b', "One-Time Pad"),
                        (r'\b(enigma)\b', "Enigma"),
                        (r'\b(morse code)\b', "Morse Code"),
                        (r'\b(binary|hexadecimal|hex dump)\b', "Binary/Hex Encoding"),
                        (r'\b(transposition|permutation)\b', "Transposition Cipher"),
                        (r'\b(ascii)\b', "ASCII Encoding"),
                        (r'\b(atbash)\b', "Atbash Cipher")
                    ]
                    
                    techniques = []
                    import re
                    for pattern, technique in crypto_patterns:
                        if re.search(pattern, text, re.IGNORECASE):
                            techniques.append(technique)
                    
                    if techniques:
                        console.print("\n[bold]Detected Cryptographic Techniques:[/bold]")
                        for technique in techniques:
                            console.print(f"- {technique}")
                    
                    # Ask to save to file
                    save = Prompt.ask(
                        "Save full content to file? (y/n)",
                        choices=["y", "n"],
                        default="n"
                    )
                    
                    if save.lower() == "y":
                        filename = f"web_content_{Path(url).name.split('.')[0]}.txt"
                        with open(filename, "w", encoding="utf-8") as f:
                            f.write(text)
                        console.print(f"[green]Content saved to {filename}[/green]")
                else:
                    console.print("[red]Failed to fetch content.[/red]")
        except (ValueError, IndexError):
            console.print("[red]Invalid selection.[/red]")

def run_code_assistant():
    """Run the code generation assistant."""
    console.print("\n[bold]Code Generation Assistant[/bold]")
    console.print("This tool allows you to create custom code to analyze puzzles.")
    
    # Initialize the core agent for LLM access
    agent_provider = Prompt.ask(
        "Select LLM provider",
        choices=["anthropic", "openai", "huggingface", "local"],
        default="local"
    )
    
    # Get API key if needed
    api_key = None
    if agent_provider != "local":
        env_var = f"{agent_provider.upper()}_API_KEY"
        if os.environ.get(env_var):
            use_env = Prompt.ask(f"Use {env_var} from environment?", choices=["y", "n"], default="y")
            if use_env.lower() == "n":
                api_key = Prompt.ask("Enter API key", password=True)
        else:
            api_key = Prompt.ask("Enter API key", password=True)
    
    core_agent = CryptoAgent(
        provider=agent_provider,
        api_key=api_key,
        verbose=True
    )
    
    # Initialize code agent
    code_agent = CodeAgent(
        llm_agent=core_agent,
        tools_dir="./dynamic_tools"
    )
    
    while True:
        console.print("\n[bold]Code Assistant Options:[/bold]")
        console.print("  1. Generate analysis code")
        console.print("  2. Create a new tool")
        console.print("  3. Run a tool")
        console.print("  4. List available tools")
        console.print("  5. Return to main menu")
        
        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5"], default="1")
        
        if choice == "1":
            # Generate and run analysis code
            task = Prompt.ask("Describe what you want the code to do")
            
            console.print("[yellow]Generating code...[/yellow]")
            code = code_agent.generate_code(task)
            
            console.print("\n[bold]Generated Code:[/bold]")
            console.print(code)
            
            run_it = Prompt.ask(
                "Run this code? (y/n)",
                choices=["y", "n"],
                default="n"
            )
            
            if run_it.lower() == "y":
                # Get inputs
                console.print("\n[bold]Code Inputs:[/bold]")
                inputs = {}
                
                add_input = Prompt.ask(
                    "Add input variables? (y/n)",
                    choices=["y", "n"],
                    default="n"
                )
                
                while add_input.lower() == "y":
                    var_name = Prompt.ask("Variable name")
                    var_value = Prompt.ask("Variable value")
                    
                    # Try to parse as JSON if possible
                    try:
                        inputs[var_name] = json.loads(var_value)
                    except:
                        inputs[var_name] = var_value
                    
                    add_input = Prompt.ask(
                        "Add another input? (y/n)",
                        choices=["y", "n"],
                        default="n"
                    )
                
                console.print("[yellow]Running code...[/yellow]")
                result = code_agent.execute_code(code, inputs)
                
                console.print("\n[bold]Execution Result:[/bold]")
                if result.get('success'):
                    console.print("[green]Execution successful![/green]")
                    console.print(json.dumps(result.get('result', {}), indent=2))
                else:
                    console.print("[red]Execution failed![/red]")
                    console.print(f"Error: {result.get('error', 'Unknown error')}")
                    if 'traceback' in result:
                        console.print("\n[bold]Traceback:[/bold]")
                        console.print(result['traceback'])
        
        elif choice == "2":
            # Create a new tool
            description = Prompt.ask("Describe the tool you want to create")
            
            console.print("[yellow]Generating and registering tool...[/yellow]")
            tool_id = code_agent.register_new_tool(description)
            
            if tool_id:
                console.print(f"[green]Tool created successfully! ID: {tool_id}[/green]")
                
                # Get the tool info
                tools = code_agent.tool_registry.list_tools()
                tool_info = next((t for t in tools if t['id'] == tool_id), None)
                
                if tool_info:
                    console.print(f"Tool Name: {tool_info['name']}")
                    console.print(f"Description: {tool_info['description']}")
            else:
                console.print("[red]Failed to create tool.[/red]")
        
        elif choice == "3":
            # Run an existing tool
            tools = code_agent.tool_registry.list_tools()
            
            if not tools:
                console.print("[yellow]No tools available. Create a tool first.[/yellow]")
                continue
            
            console.print("\n[bold]Available Tools:[/bold]")
            tool_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
            tool_table.add_column("#")
            tool_table.add_column("Name")
            tool_table.add_column("Description")
            tool_table.add_column("ID")
            
            for i, tool in enumerate(tools, 1):
                tool_table.add_row(
                    str(i),
                    tool['name'],
                    tool['description'],
                    tool['id'][:8] + "..."
                )
            
            console.print(tool_table)
            
            tool_choice = IntPrompt.ask(
                "Select a tool to run (number)",
                choices=[str(i) for i in range(1, len(tools) + 1)]
            )
            
            selected_tool = tools[tool_choice - 1]
            
            # Get inputs
            console.print(f"\n[bold]Running Tool: {selected_tool['name']}[/bold]")
            inputs = {}
            
            add_input = Prompt.ask(
                "Add input parameters? (y/n)",
                choices=["y", "n"],
                default="n"
            )
            
            while add_input.lower() == "y":
                param_name = Prompt.ask("Parameter name")
                param_value = Prompt.ask("Parameter value")
                
                # Try to parse as JSON if possible
                try:
                    inputs[param_name] = json.loads(param_value)
                except:
                    inputs[param_name] = param_value
                
                add_input = Prompt.ask(
                    "Add another parameter? (y/n)",
                    choices=["y", "n"],
                    default="n"
                )
            
            console.print("[yellow]Running tool...[/yellow]")
            result = code_agent.use_tool(selected_tool['id'], inputs)
            
            console.print("\n[bold]Tool Execution Result:[/bold]")
            if result.get('success'):
                console.print("[green]Execution successful![/green]")
                console.print(json.dumps(result.get('result', {}), indent=2))
            else:
                console.print("[red]Execution failed![/red]")
                console.print(f"Error: {result.get('error', 'Unknown error')}")
                if 'traceback' in result:
                    console.print("\n[bold]Traceback:[/bold]")
                    console.print(result['traceback'])
        
        elif choice == "4":
            # List available tools
            tools = code_agent.tool_registry.list_tools()
            
            if not tools:
                console.print("[yellow]No tools available.[/yellow]")
                continue
            
            console.print("\n[bold]Available Tools:[/bold]")
            tool_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
            tool_table.add_column("Name")
            tool_table.add_column("Description")
            tool_table.add_column("ID")
            
            for tool in tools:
                tool_table.add_row(
                    tool['name'],
                    tool['description'],
                    tool['id']
                )
            
            console.print(tool_table)
        
        elif choice == "5":
            break

def create_custom_analyzer():
    """Create a custom analyzer using the code assistant."""
    console.print("\n[bold]Create Custom Analyzer[/bold]")
    console.print("This tool helps you create a custom analyzer that can be integrated into the system.")
    
    # Initialize the core agent for LLM access
    agent_provider = Prompt.ask(
        "Select LLM provider",
        choices=["anthropic", "openai", "huggingface", "local"],
        default="local"
    )
    
    # Get API key if needed
    api_key = None
    if agent_provider != "local":
        env_var = f"{agent_provider.upper()}_API_KEY"
        if os.environ.get(env_var):
            use_env = Prompt.ask(f"Use {env_var} from environment?", choices=["y", "n"], default="y")
            if use_env.lower() == "n":
                api_key = Prompt.ask("Enter API key", password=True)
        else:
            api_key = Prompt.ask("Enter API key", password=True)
    
    core_agent = CryptoAgent(
        provider=agent_provider,
        api_key=api_key,
        verbose=True
    )
    
    # Initialize code agent
    code_agent = CodeAgent(
        llm_agent=core_agent,
        tools_dir="./dynamic_tools"
    )
    
    # Get analyzer description
    description = Prompt.ask("Describe what the analyzer should do")
    name = Prompt.ask("Name for the analyzer (use lowercase and underscores)")
    
    # Format the task description
    task = f"""
Create a custom analyzer for the Crypto Hunter tool. This analyzer will be used to analyze cryptographic puzzles.

Analyzer Name: {name}

Description: {description}

The analyzer should be a function with this signature:
```python
@register_analyzer("{name}")
def {name}(state: State) -> State:
    # Your code here
    return state
```

It should do the following:
1. Take a State object as input
2. Analyze the puzzle content in the state
3. Add insights and transformations to the state
4. Return the updated state

The state object has these important methods:
- state.puzzle_text: The text content of the puzzle
- state.binary_data: Binary data if it's a binary puzzle
- state.add_insight(text, analyzer): Add an insight to the state
- state.add_transformation(name, description, input_data, output_data, analyzer): Add a transformation
- state.set_solution(solution): Set the solution if found

Your analyzer should focus on: {description}
"""
    
    console.print("[yellow]Generating analyzer code...[/yellow]")
    code = code_agent.generate_code(task)
    
    console.print("\n[bold]Generated Analyzer:[/bold]")
    console.print(code)
    
    save = Prompt.ask(
        "Save this analyzer? (y/n)",
        choices=["y", "n"],
        default="y"
    )
    
    if save.lower() == "y":
        # Save to analyzers directory
        os.makedirs("analyzers", exist_ok=True)
        
        filename = f"analyzers/{name}.py"
        with open(filename, "w") as f:
            f.write(f"""
\"\"\"
Custom analyzer: {name}
{description}
\"\"\"

from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

{code}
""")
        
        # Create/update __init__.py to import the new analyzer
        init_file = "analyzers/__init__.py"
        if os.path.exists(init_file):
            with open(init_file, "a") as f:
                f.write(f"\nfrom analyzers.{name} import {name}\n")
        else:
            with open(init_file, "w") as f:
                f.write(f"""
\"\"\"
Analyzers module for Crypto Hunter.
\"\"\"

from analyzers.base import register_analyzer, analyzer_compatibility, get_analyzer, get_all_analyzers
from analyzers.{name} import {name}
""")
        
        console.print(f"[green]Analyzer saved to {filename}[/green]")
        console.print("[yellow]Restart the application to use this analyzer.[/yellow]")
    else:
        console.print("[yellow]Analyzer not saved.[/yellow]")

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

def process_all_files_in_folder(folder_path, agent, iterations=5, results_dir="./results", use_web=False, use_code=False):
    """
    Process all files in a puzzle folder as a single puzzle.
    
    Args:
        folder_path: Path to the puzzle folder
        agent: CryptoAgent instance for analysis
        iterations: Maximum number of iterations for the agent
        results_dir: Directory to store results
        use_web: Whether to use the web browsing agent
        use_code: Whether to use the code generation agent
    
    Returns:
        Final state of the puzzle analysis
    """
    # Create a state object that will hold all files
    state = State()
    
    # Load all files in the folder
    files = list(Path(folder_path).glob("*"))
    if not files:
        console.print(f"[bold red]No files found in {folder_path}[/bold red]")
        return None
    
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
    if not state.puzzle_file:
        first_file = files[0].name
        state.set_puzzle_file(first_file)
        
        # For binary files, we'll need to handle differently
        if state.is_binary():
            state.set_binary_data(state.related_files[first_file]["content"])
        else:
            state.set_puzzle_text(state.related_files[first_file]["content"].decode("utf-8", errors="replace"))
    
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
    
    # Add web browsing agent if requested
    if use_web:
        console.print("[bold]Initializing web browsing agent...[/bold]")
        web_agent = WebAgent()
        folder_name = Path(folder_path).name
        state = web_agent.integrate_with_state(state, f"cryptographic puzzle {folder_name}")
    
    # Add code generation agent if requested
    if use_code:
        console.print("[bold]Initializing code generation agent...[/bold]")
        code_agent = CodeAgent(llm_agent=agent)
        state = code_agent.integrate_with_state(state)
    
    # Run the analysis with all files loaded
    final_state = agent.analyze(state, max_iterations=iterations)
    
    # Save results
    result_path = os.path.join(results_dir, f"{Path(folder_path).name}_results.json")
    with open(result_path, "w") as f:
        json.dump({
            "status": "completed",
            "solution": final_state.solution,
            "insights": final_state.insights,
            "transformations": final_state.transformations
        }, f, indent=2)
    
    return final_state

def process_puzzle(puzzle_path, agent, output_dir="./output", iterations=5, results_dir="./results", use_web=False, use_code=False):
    """
    Process a single puzzle file or folder.
    
    Args:
        puzzle_path: Path to the puzzle file or folder
        agent: CryptoAgent instance
        output_dir: Directory to store output files
        iterations: Maximum number of analysis iterations
        results_dir: Directory to store results
        use_web: Whether to use the web browsing agent
        use_code: Whether to use the code generation agent
        
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    path = Path(puzzle_path)
    
    # Check if the path is a directory
    if path.is_dir():
        console.print(f"[bold]Processing puzzle folder: {path}[/bold]")
        final_state = process_all_files_in_folder(path, agent, iterations, results_dir)
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
                final_state = process_all_files_in_folder(parent_dir, agent, iterations, results_dir)
                return 0 if final_state and final_state.solution else 1
        
        # Process just the single file
        with open(path, "rb") as f:
            content = f.read()
        
        # Create state
        state = State(puzzle_file=path.name)
        
        # Set content based on file type
        if state.is_binary():
            state.set_binary_data(content)
        else:
            state.set_puzzle_text(content.decode("utf-8", errors="replace"))
        
        # Add web browsing agent if requested
        if use_web:
            console.print("[bold]Initializing web browsing agent...[/bold]")
            web_agent = WebAgent()
            state = web_agent.integrate_with_state(state, f"cryptographic puzzle {path.name}")
        
        # Add code generation agent if requested
        if use_code:
            console.print("[bold]Initializing code generation agent...[/bold]")
            code_agent = CodeAgent(llm_agent=agent)
            state = code_agent.integrate_with_state(state)
        
        # Run analysis
        final_state = agent.analyze(state, max_iterations=iterations)
        
        # Save results
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
    """Display the analysis results."""
    console.print("\n[bold]Analysis Results[/bold]")
    
    # Display puzzle info
    console.print("\n[bold]Puzzle Information[/bold]")
    info_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
    info_table.add_column("Property")
    info_table.add_column("Value")
    
    info_table.add_row("File", str(puzzle_path))
    info_table.add_row("Type", state.file_type or "Unknown")
    info_table.add_row("Size", f"{state.file_size} bytes" if state.file_size else "Unknown")
    info_table.add_row("Status", "Solved" if state.solution else "Unsolved")
    
    if state.solution:
        info_table.add_row("Solution", state.solution)
    
    console.print(info_table)
    
    # Display insights
    console.print("\n[bold]Analysis Insights[/bold]")
    if state.insights:
        insights_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
        insights_table.add_column("Time")
        insights_table.add_column("Analyzer")
        insights_table.add_column("Insight")
        
        for insight in state.insights:
            insights_table.add_row(
                insight.get("time", ""),
                insight.get("analyzer", ""),
                insight.get("text", "")
            )
        
        console.print(insights_table)
    else:
        console.print("[italic]No insights gathered.[/italic]")
    
    # Display transformations
    console.print("\n[bold]Transformations[/bold]")
    if state.transformations:
        for i, transform in enumerate(state.transformations):
            console.print(Panel(
                f"[bold]{transform.get('name', 'Transformation')}[/bold]\n"
                f"[italic]{transform.get('description', '')}[/italic]\n\n"
                f"Input: {transform.get('input_data', '')[:100]}...\n"
                f"Output: {transform.get('output_data', '')[:100]}...",
                title=f"Transformation {i+1}",
                title_align="left"
            ))
    else:
        console.print("[italic]No transformations applied.[/italic]")

def browse_puzzle_collection(puzzles_dir, agent, results_dir):
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
    
    # Check if it's a folder or file
    selected_path = Path(selected_puzzle)
    
    # Determine if we should process a folder or single file
    if selected_path.is_dir():
        console.print(f"[bold cyan]Selected puzzle folder: {selected_path}[/bold cyan]")
        return process_all_files_in_folder(selected_path, agent, results_dir=results_dir)
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
                return process_all_files_in_folder(parent_dir, agent, results_dir=results_dir)
        
        # Process just the selected file
        console.print(f"[bold cyan]Selected puzzle file: {selected_path}[/bold cyan]")
        return process_puzzle(selected_puzzle, agent, results_dir=results_dir)

def interactive_mode(agent):
    """Run in interactive mode."""
    console.print("[bold]Interactive Mode[/bold]")
    console.print("In this mode, you can interact with the agent to solve a puzzle step by step.")
    console.print("Type 'exit' to quit.")
    
    # Create an initial state
    state = State()
    
    while True:
        command = Prompt.ask("\n[bold]Enter command[/bold]", default="help")
        
        if command.lower() == "exit":
            break
        elif command.lower() == "help":
            console.print("[bold]Available commands:[/bold]")
            console.print("  load <file>: Load a puzzle file")
            console.print("  analyze: Analyze the current puzzle")
            console.print("  status: Show the current state")
            console.print("  insights: Show all insights")
            console.print("  transformations: Show all transformations")
            console.print("  solution: Show the solution (if found)")
            console.print("  exit: Quit interactive mode")
        elif command.lower().startswith("load "):
            file_path = command[5:].strip()
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                
                state = State(puzzle_file=Path(file_path).name)
                
                if state.is_binary():
                    state.set_binary_data(content)
                else:
                    state.set_puzzle_text(content.decode("utf-8", errors="replace"))
                
                console.print(f"[green]Loaded {file_path}[/green]")
                
                # Look for related files in the same directory
                parent_dir = Path(file_path).parent
                other_files = [f for f in parent_dir.glob("*") if f != Path(file_path) and f.is_file()]
                
                if other_files:
                    console.print(f"[yellow]Found {len(other_files)} other files in the same directory:[/yellow]")
                    for other_file in other_files:
                        console.print(f"  - {other_file.name}")
                    
                    load_all = Prompt.ask(
                        "Load all files as part of the puzzle?", 
                        choices=["y", "n"], 
                        default="y"
                    )
                    
                    if load_all.lower() == "y":
                        for other_file in other_files:
                            with open(other_file, "rb") as f:
                                content = f.read()
                            state.add_related_file(other_file.name, content)
                        console.print("[green]Loaded all related files.[/green]")
                
            except Exception as e:
                console.print(f"[bold red]Error loading file: {e}[/bold red]")
        elif command.lower() == "analyze":
            if not state.puzzle_file:
                console.print("[bold red]No puzzle loaded. Use 'load <file>' first.[/bold red]")
                continue
            
            iterations = IntPrompt.ask("Number of analysis iterations", default=3)
            console.print("[bold]Running analysis...[/bold]")
            
            state = agent.analyze(state, max_iterations=iterations)
            
            if state.solution:
                console.print(f"[bold green]Solution found: {state.solution}[/bold green]")
            else:
                console.print("[yellow]No solution found yet. Use 'insights' to see progress.[/yellow]")
        elif command.lower() == "status":
            if not state.puzzle_file:
                console.print("[bold red]No puzzle loaded.[/bold red]")
                continue
            
            console.print("[bold]Current State:[/bold]")
            console.print(f"Puzzle: {state.puzzle_file}")
            console.print(f"Type: {state.file_type}")
            console.print(f"Size: {state.file_size} bytes")
            console.print(f"Insights: {len(state.insights)}")
            console.print(f"Transformations: {len(state.transformations)}")
            console.print(f"Solution: {state.solution or 'Not found'}")
            
            if state.related_files:
                console.print("\n[bold]Related Files:[/bold]")
                for filename in state.related_files:
                    console.print(f"  - {filename}")
        elif command.lower() == "insights":
            if not state.insights:
                console.print("[italic]No insights gathered yet.[/italic]")
                continue
            
            console.print("[bold]Insights:[/bold]")
            for i, insight in enumerate(state.insights, 1):
                console.print(f"{i}. [{insight.get('time', '')}] {insight.get('analyzer', '')}: {insight.get('text', '')}")
        elif command.lower() == "transformations":
            if not state.transformations:
                console.print("[italic]No transformations applied yet.[/italic]")
                continue
            
            console.print("[bold]Transformations:[/bold]")
            for i, transform in enumerate(state.transformations, 1):
                console.print(f"{i}. [{transform.get('name', 'Transformation')}] {transform.get('description', '')}")
                console.print(f"   Input: {transform.get('input_data', '')[:50]}...")
                console.print(f"   Output: {transform.get('output_data', '')[:50]}...")
        elif command.lower() == "solution":
            if state.solution:
                console.print(f"[bold green]Solution: {state.solution}[/bold green]")
            else:
                console.print("[yellow]No solution found yet.[/yellow]")
        else:
            console.print("[italic]Unknown command. Type 'help' for available commands.[/italic]")

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
        elif mode == "advanced":
            return advanced_tools_menu()
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
        return browse_puzzle_collection(args.puzzle_dir, agent, args.results_dir)
    elif mode == "interactive":
        return interactive_mode(agent)
    else:  # Process a single puzzle
        return process_puzzle(
            args.puzzle_file,
            agent,
            args.output_dir,
            args.iterations,
            args.results_dir,
            args.use_web,
            args.use_code
        )

if __name__ == "__main__":
    sys.exit(main())
