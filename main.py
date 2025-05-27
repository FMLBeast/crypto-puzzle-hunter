#!/usr/bin/env python3
"""
AI-powered Crypto Puzzle Hunter — entry point.
"""
import argparse
import logging
import os

from dotenv import load_dotenv
load_dotenv()  # loads OPENAI_API_KEY, ANTHROPIC_API_KEY, etc from .env

from enhanced_orchestrator import EnhancedOrchestrator

def parse_args():
    p = argparse.ArgumentParser("Crypto Puzzle Hunter")
    p.add_argument("puzzle_path", help="Path to puzzle file (binary, image, etc.)")
    p.add_argument("--provider",
                   choices=["openai", "anthropic", "local"],
                   default="openai",
                   help="LLM provider")
    p.add_argument("--model",
                   help="Model name (e.g. gpt-4o-2024-05-13 or claude-3.5-sonnet)")
    p.add_argument("--verbose",
                   action="store_true",
                   help="Enable debug logging")
    return p.parse_args()

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    fmt   = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt)

def main():
    args = parse_args()
    setup_logging(args.verbose)

    orch = EnhancedOrchestrator(
        provider=args.provider,
        api_key  = os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"),
        model    = args.model,
        verbose  = args.verbose
    )

    # run the workflow on the puzzle file
    orch.run(args.puzzle_path)


if __name__ == "__main__":
    main()
