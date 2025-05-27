#!/usr/bin/env python3
"""
enhanced_orchestrator.py

Central glue for Crypto Puzzle Hunter:
  • Manages WorkflowState
  • Runs FileHeader, TextExtractor, PrivateKeyConstructor,
    WalletVerifier, VM, PGP agents up front
  • Uses TaskFactory to generate analysis tasks
  • Loops through tasks, dispatching to analyzers & agents
  • Persists & logs every insight/finding/solution
"""
import os
import json
import time
import logging

from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from enhanced_state_management import WorkflowState
from task_factory               import TaskFactory

from core.agent                      import CryptoAgent
from core.code_agent                 import CodeAgent
from core.vision_agent               import VisionAgent
from core.web_agent                  import WebAgent
from core.wallet_verifier_agent      import WalletVerifierAgent
from core.vm_agent                   import VMAgent
from core.pgp_agent                  import PGPAgent
from core.fileheader_agent           import FileHeaderAgent
from core.text_extractor_agent       import TextExtractorAgent
from core.private_key_constructor_agent import PrivateKeyConstructorAgent

logger = logging.getLogger(__name__)

class EnhancedOrchestrator:
    def __init__(
        self,
        provider: str             = "openai",
        api_key:  str             = None,
        model:    str             = None,
        verbose:  bool            = False
    ):
        # logging is already configured by main.py
        logger.info("🔧 Initializing EnhancedOrchestrator")

        # 1) Core state
        self.state = WorkflowState()

        # 2) Agents
        self.crypto_agent         = CryptoAgent(provider, api_key, model, verbose)
        self.code_agent           = CodeAgent(verbose=verbose)
        self.vision_agent         = VisionAgent(verbose=verbose)
        self.web_agent            = WebAgent(verbose=verbose)
        self.wallet_verifier_agent = WalletVerifierAgent(verbose=verbose)
        self.vm_agent             = VMAgent(verbose=verbose)
        self.pgp_agent            = PGPAgent(verbose=verbose)
        self.fileheader_agent     = FileHeaderAgent(verbose=verbose)
        self.text_extractor_agent = TextExtractorAgent(verbose=verbose)
        self.pk_constructor_agent = PrivateKeyConstructorAgent(verbose=verbose)

        # 3) Task factory (needs state)
        self.factory = TaskFactory(self.state)

    def run(self, puzzle_path: str, timeout_minutes: int = 60):
        """
        1) Load root material
        2) Run all “pre-analysis” agents on it
        3) Generate initial tasks and loop until solution or timeout
        """
        logger.info(f"📁 Loading puzzle: {puzzle_path}")
        root = self.state.add_material(puzzle_path)

        # 3a) Pre-analysis: extract files, text, keys, wallets, VM, PGP
        for agent in (
            self.fileheader_agent,
            self.text_extractor_agent,
            self.pk_constructor_agent,
            self.wallet_verifier_agent,
            self.vm_agent,
            self.pgp_agent
        ):
            self.state = agent.run(self.state)

        # 3b) Initial tasks
        init_tasks = self.factory.generate_initial_tasks(root)
        for t in init_tasks:
            self.state.add_task(t)

        # 4) Main execution loop
        deadline = datetime.now() + timedelta(minutes=timeout_minutes)
        with ThreadPoolExecutor() as pool:
            futures = {}
            while not self.state.solution and datetime.now() < deadline:
                task = self.state.get_next_task()
                if not task:
                    break

                # dispatch
                futures[pool.submit(self._execute_task, task)] = task

                # collect immediately to maintain order
                for fut in as_completed(list(futures)):
                    t = futures.pop(fut)
                    try:
                        fut.result()
                        self.state.complete_task(t)
                    except Exception as e:
                        self.state.fail_task(t, str(e))

                time.sleep(0.1)

        # 5) Final LLM‐direct solution if still missing
        if not self.state.solution:
            sol = self.crypto_agent.attempt_direct(self.state)
            if sol:
                self.state.set_solution(sol)

        # 6) Summary
        logger.info("✅ Analysis complete")
        print("\n=== FINAL SUMMARY ===")
        print(self.state.get_summary())
        if self.state.solution:
            print("Solution:", self.state.solution)

    def _execute_task(self, task):
        """
        Map each Task.analyzer to its handler.
        """
        name = task.analyzer
        # First check custom agents
        if name == "vision_analyzer":
            self.vision_agent.run(self.state)
        elif name == "web_analyzer":
            self.web_agent.run(self.state)
        elif name == "wallet_verifier":
            self.wallet_verifier_agent.run(self.state)
        elif name == "vm_executor":
            self.vm_agent.run(self.state)
        elif name == "pgp_agent":
            self.pgp_agent.run(self.state)
        else:
            # Fallback to CryptoAgent orchestrating analyzers
            self.crypto_agent.run_analyzer(name, self.state)
