#!/usr/bin/env python3
"""
AI-powered Crypto Puzzle Hunter — entry point.
"""
import argparse
import logging
import os

from enhanced_orchestrator import EnhancedOrchestrator
from core.agent         import CryptoAgent
from core.code_agent    import CodeAgent
from core.vision_agent  import VisionAgent
from core.web_agent     import WebAgent

def parse_args():
    p = argparse.ArgumentParser("Crypto Puzzle Hunter")
    p.add_argument("puzzle_file", help="Path to puzzle (binary or text)")
    p.add_argument("--provider",
                   choices=["openai","anthropic"],
                   default="openai",
                   help="Primary LLM provider")
    p.add_argument("--model",    help="LLM model name (e.g. gpt-4o-2024-05-13)")
    p.add_argument("--jobs",     type=int, default=4,   help="Parallel analyzers")
    p.add_argument("--iterations",
                   type=int, default=100,
                   help="Max AI iterations")
    p.add_argument("--timeout",
                   type=int, default=60,
                   help="Timeout in minutes")
    p.add_argument("--verbose",
                   action="store_true",
                   help="Verbose logging")
    return p.parse_args()

def setup_logging(verbose: bool, puzzle_file: str):
    root = logging.getLogger()
    level = logging.DEBUG if verbose else logging.INFO
    root.setLevel(level)
    fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter(fmt))
    root.addHandler(ch)
    base = os.path.splitext(os.path.basename(puzzle_file))[0]
    fh = logging.FileHandler(f"{base}.log", mode="a")
    fh.setFormatter(logging.Formatter(fmt))
    root.addHandler(fh)

def main():
    args = parse_args()
    setup_logging(args.verbose, args.puzzle_file)

    crypto = CryptoAgent(
        provider=args.provider,
        api_key=None,
        model=args.model,
        verbose=args.verbose
    )
    code   = CodeAgent(verbose=args.verbose)
    vision = VisionAgent(verbose=args.verbose)
    web    = WebAgent(verbose=args.verbose)

    state_file = os.path.splitext(args.puzzle_file)[0] + ".state.json"
    orch = EnhancedOrchestrator(
        puzzle_file=args.puzzle_file,
        crypto_agent=crypto,
        code_agent=code,
        vision_agent=vision,
        web_agent=web,
        state_file=state_file,
        max_workers=args.jobs,
        llm_interval=5,
        verbose=args.verbose
    )

    solved = orch.run(
        max_iterations=args.iterations,
        timeout_minutes=args.timeout
    )
    print("🎉 Puzzle solved!" if solved else "❌ No solution found.")

if __name__ == "__main__":
    main()
