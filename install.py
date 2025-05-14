#!/usr/bin/env python3
"""
Installation script for Crypto Hunter

This script helps with setting up Crypto Hunter and its dependencies.
"""
import os
import sys
import subprocess
import platform
import argparse
from pathlib import Path
from typing import List, Optional


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Install Crypto Hunter and its dependencies"
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help="Install development dependencies",
    )
    parser.add_argument(
        "--venv",
        type=str,
        default="venv",
        help="Path to virtual environment (default: venv)",
    )
    parser.add_argument(
        "--skip-venv",
        action="store_true",
        help="Skip creating a virtual environment",
    )
    parser.add_argument(
        "--api-keys",
        action="store_true",
        help="Configure API keys",
    )
    
    return parser.parse_args()


def run_command(command: List[str], cwd: Optional[str] = None) -> bool:
    """
    Run a shell command.
    
    Args:
        command: Command to run as a list of arguments
        cwd: Working directory
        
    Returns:
        True if command succeeded, False otherwise
    """
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {' '.join(command)}")
        print(f"Error: {e.stderr}")
        return False


def create_virtual_environment(venv_path: str) -> bool:
    """
    Create a Python virtual environment.
    
    Args:
        venv_path: Path for the virtual environment
        
    Returns:
        True if successful, False otherwise
    """
    print(f"Creating virtual environment at {venv_path}...")
    
    if os.path.exists(venv_path):
        print(f"Virtual environment already exists at {venv_path}")
        return True
    
    return run_command([sys.executable, "-m", "venv", venv_path])


def get_venv_python(venv_path: str) -> str:
    """
    Get the path to the Python interpreter in the virtual environment.
    
    Args:
        venv_path: Path to the virtual environment
        
    Returns:
        Path to the Python interpreter
    """
    if platform.system() == "Windows":
        return os.path.join(venv_path, "Scripts", "python.exe")
    else:
        return os.path.join(venv_path, "bin", "python")


def get_venv_pip(venv_path: str) -> str:
    """
    Get the path to pip in the virtual environment.
    
    Args:
        venv_path: Path to the virtual environment
        
    Returns:
        Path to pip
    """
    if platform.system() == "Windows":
        return os.path.join(venv_path, "Scripts", "pip.exe")
    else:
        return os.path.join(venv_path, "bin", "pip")


def install_dependencies(venv_path: str, dev: bool = False) -> bool:
    """
    Install dependencies.
    
    Args:
        venv_path: Path to the virtual environment
        dev: Whether to install development dependencies
        
    Returns:
        True if successful, False otherwise
    """
    pip = get_venv_pip(venv_path)
    
    print("Upgrading pip...")
    if not run_command([pip, "install", "--upgrade", "pip"]):
        return False
    
    print("Installing dependencies...")
    if not run_command([pip, "install", "-r", "requirements.txt"]):
        return False
    
    if dev:
        print("Installing development dependencies...")
        requirements_dev = "requirements-dev.txt"
        
        # Create a basic requirements-dev.txt if it doesn't exist
        if not os.path.exists(requirements_dev):
            with open(requirements_dev, "w") as f:
                f.write("# Development dependencies\n")
                f.write("pytest>=7.0.0\n")
                f.write("black>=23.1.0\n")
                f.write("isort>=5.12.0\n")
                f.write("pylint>=3.0.0\n")
                f.write("pre-commit>=3.3.2\n")
                f.write("pytest-cov>=4.1.0\n")
        
        if not run_command([pip, "install", "-r", requirements_dev]):
            return False
    
    return True


def configure_api_keys():
    """Configure API keys for the project."""
    print("\nAPI Key Configuration")
    print("====================")
    print("The following API keys are optional but recommended:")
    print("1. Anthropic API Key (for Claude integration)")
    print("2. OpenAI API Key (for GPT integration)")
    print("3. Etherscan API Key (for blockchain analysis)")
    
    # Create .env file
    env_file = ".env"
    if os.path.exists(env_file):
        with open(env_file, "r") as f:
            env_content = f.read()
    else:
        env_content = "# Crypto Hunter API Keys\n\n"
    
    # Check for existing keys
    anthropic_key = None
    openai_key = None
    etherscan_key = None
    
    if "ANTHROPIC_API_KEY" in env_content:
        anthropic_key = "Already configured"
    
    if "OPENAI_API_KEY" in env_content:
        openai_key = "Already configured"
    
    if "ETHERSCAN_API_KEY" in env_content:
        etherscan_key = "Already configured"
    
    # Prompt for keys
    print("\nEnter your API keys (press Enter to skip or keep existing):")
    
    if anthropic_key:
        print(f"Anthropic API Key: {anthropic_key}")
    else:
        anthropic_key = input("Anthropic API Key: ").strip()
    
    if openai_key:
        print(f"OpenAI API Key: {openai_key}")
    else:
        openai_key = input("OpenAI API Key: ").strip()
    
    if etherscan_key:
        print(f"Etherscan API Key: {etherscan_key}")
    else:
        etherscan_key = input("Etherscan API Key: ").strip()
    
    # Update .env file
    with open(env_file, "w") as f:
        f.write("# Crypto Hunter API Keys\n\n")
        
        if anthropic_key and anthropic_key != "Already configured":
            f.write(f"ANTHROPIC_API_KEY={anthropic_key}\n")
        elif "ANTHROPIC_API_KEY" in env_content:
            # Keep existing key
            lines = env_content.split("\n")
            for line in lines:
                if line.startswith("ANTHROPIC_API_KEY="):
                    f.write(f"{line}\n")
                    break
        
        if openai_key and openai_key != "Already configured":
            f.write(f"OPENAI_API_KEY={openai_key}\n")
        elif "OPENAI_API_KEY" in env_content:
            # Keep existing key
            lines = env_content.split("\n")
            for line in lines:
                if line.startswith("OPENAI_API_KEY="):
                    f.write(f"{line}\n")
                    break
        
        if etherscan_key and etherscan_key != "Already configured":
            f.write(f"ETHERSCAN_API_KEY={etherscan_key}\n")
        elif "ETHERSCAN_API_KEY" in env_content:
            # Keep existing key
            lines = env_content.split("\n")
            for line in lines:
                if line.startswith("ETHERSCAN_API_KEY="):
                    f.write(f"{line}\n")
                    break
    
    print(f"\nAPI keys saved to {env_file}")


def setup_project_structure():
    """Ensure the project structure is set up correctly."""
    print("Setting up project structure...")
    
    # Ensure directories exist
    directories = ["results", "examples/puzzle_samples"]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)


def main():
    """Main entry point."""
    args = parse_arguments()
    
    print("Crypto Hunter Installation")
    print("=========================")
    
    # Create virtual environment
    if not args.skip_venv:
        if not create_virtual_environment(args.venv):
            print("Failed to create virtual environment")
            return 1
    
    # Install dependencies
    if not args.skip_venv:
        if not install_dependencies(args.venv, args.dev):
            print("Failed to install dependencies")
            return 1
    
    # Set up project structure
    setup_project_structure()
    
    # Configure API keys
    if args.api_keys:
        configure_api_keys()
    
    print("\nInstallation complete!")
    
    if not args.skip_venv:
        venv_activate = os.path.join(args.venv, "bin", "activate")
        if platform.system() == "Windows":
            venv_activate = os.path.join(args.venv, "Scripts", "activate")
        
        print(f"\nTo activate the virtual environment:")
        if platform.system() == "Windows":
            print(f"    {args.venv}\\Scripts\\activate")
        else:
            print(f"    source {args.venv}/bin/activate")
    
    print("\nTo run Crypto Hunter:")
    print("    python main.py --interactive")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
