# enhanced_orchestrator.py
import logging
import time
import os
from pathlib import Path
from typing import Optional

from enhanced_state_management import (
    WorkflowState, TaskStatus, AnalysisPhase, Task
)
from core.agent             import CryptoAgent
from core.code_agent        import CodeAgent
from core.vision_agent      import VisionAgent
from core.web_agent         import WebAgent
from core.wallet_verifier_agent import WalletVerifierAgent
from core.vm_agent          import VMAgent
from core.pgp_agent         import PGPAgent
from task_factory           import TaskFactory

logger = logging.getLogger(__name__)


class EnhancedOrchestrator:
    def __init__(
        self,
        provider: str = "openai",
        api_key:  Optional[str] = None,
        model:    Optional[str] = None,
        verbose:  bool = False
    ):
        logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)
        logger.info("🔧 Initializing EnhancedOrchestrator")

        # Core state
        self.state = WorkflowState()

        # LLM‐driven analysis
        self.crypto_agent = CryptoAgent(provider, api_key, model, verbose)

        # Code + dynamic tooling
        self.code_agent = CodeAgent(verbose=verbose)

        # Other specialized agents
        self.vision_agent           = VisionAgent(verbose=verbose)
        self.web_agent              = WebAgent(verbose=verbose)
        self.wallet_verifier_agent  = WalletVerifierAgent(verbose=verbose)
        self.vm_agent               = VMAgent(verbose=verbose)
        self.pgp_agent              = PGPAgent(verbose=verbose)

        # Task factory (builds your Task objects)
        self.factory = TaskFactory(self.state)

    def run(self, puzzle_path: str):
        """
        Main entrypoint:
        1) register the root material
        2) generate initial tasks
        3) loop until completion or solution found
        """
        logger.info(f"📁 Loading puzzle from {puzzle_path}")
        root_material = self.state.add_material(puzzle_path)

        # Initial discovery tasks
        init_tasks = self.factory.generate_initial_tasks(root_material)
        for t in init_tasks:
            self.state.add_task(t)

        # Main execution loop
        while not self.state.is_complete():
            task = self.state.get_next_task()
            if not task:
                break

            try:
                logger.info(f"▶ Running task {task.id} ({task.analyzer})")
                self._execute_task(task)
                self.state.complete_task(task)
            except Exception as e:
                logger.error(f"❌ Task {task.id} failed: {e}")
                self.state.fail_task(task, str(e))

            # brief pause & logging
            time.sleep(0.1)

        # Final direct solution attempt if needed
        if not self.state.solution:
            logger.info("🎯 Attempting final direct solution via LLM")
            sol = self.crypto_agent.attempt_direct(self.state)
            if sol:
                self.state.set_solution(sol)

        # Report
        logger.info("✅ Analysis complete")
        print("\n=== FINAL SUMMARY ===")
        print(self.state.get_summary())
        if self.state.solution:
            print("Solution:", self.state.solution)
        else:
            print("No solution found.")


    def _execute_task(self, task: Task):
        """
        Dispatches each task to the appropriate agent.
        """
        # map analyzer names to methods
        a = task.analyzer
        if a.startswith("binary_") or a == "binary_analyzer":
            from analyzers.binary_analyzer import analyze as f; f(self.state, task)
        elif a == "text_analyzer":
            from analyzers.text_analyzer import analyze as f; f(self.state, task)
        elif a == "encoding_analyzer":
            from analyzers.encoding_analyzer import analyze_encodings as f; f(self.state)
        elif a == "cipher_analyzer":
            from analyzers.cipher_analyzer import analyze as f; f(self.state)
        elif a == "image_analyzer":
            from analyzers.image_analyzer import analyze as f; f(self.state, task)
        elif a == "vision_analyzer":
            self.vision_agent.analyze(task, self.state)
        elif a == "web_analyzer":
            self.web_agent.search(task, self.state)
        elif a == "crypto_analyzer":
            # fallback crypto tools via code agent
            self.code_agent.analyze_crypto(self.state, task)
        elif a == "wallet_verifier":
            self.wallet_verifier_agent.verify(task, self.state)
        elif a == "vm_executor":
            self.vm_agent.execute(task, self.state)
        elif a == "pgp_agent":
            self.pgp_agent.decrypt(task, self.state)
        else:
            # Catch any custom analyzers
            from analyzers import get_analyzer
            fn = get_analyzer(a)
            if fn:
                fn(self.state)
            else:
                raise RuntimeError(f"No handler for analyzer {a}")
