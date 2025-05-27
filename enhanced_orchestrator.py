#!/usr/bin/env python3
"""
enhanced_orchestrator.py

AI-driven workflow orchestrator:
  • Loads/resumes per-puzzle state
  • Runs FileHeader, TextExtractor, PrivateKeyConstructor,
    WalletVerifier, VM and PGP agents up front
  • Builds TaskFactory(state) once state is set
  • Schedules all analyzers on every material
  • Integrates CryptoAgent, WebAgent, VisionAgent, CodeAgent per loop
  • Logs & persists state after every mutation
"""
import os
import json
import time
import logging
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from enhanced_state_management               import WorkflowState
from task_factory                            import TaskFactory
from core.agent                              import CryptoAgent
from core.code_agent                         import CodeAgent
from core.vision_agent                       import VisionAgent
from core.web_agent                          import WebAgent
from core.fileheader_agent                   import FileHeaderAgent
from core.text_extractor_agent               import TextExtractorAgent
from core.private_key_constructor_agent      import PrivateKeyConstructorAgent
from core.wallet_verifier_agent              import WalletVerifierAgent
from core.vm_agent                           import VMAgent
from core.pgp_agent                          import PGPAgent
from analyzers                               import get_all_analyzers

logger = logging.getLogger(__name__)

class EnhancedOrchestrator:
    def __init__(
        self,
        puzzle_file:            str,
        crypto_agent:           CryptoAgent,
        code_agent:             CodeAgent,
        vision_agent:           VisionAgent,
        web_agent:              WebAgent,
        state_file:             str,
        eth_node_url:           str                        = None,
        fileheader_agent:       FileHeaderAgent            = None,
        text_extractor_agent:   TextExtractorAgent         = None,
        pk_constructor_agent:   PrivateKeyConstructorAgent = None,
        wallet_verifier_agent:  WalletVerifierAgent        = None,
        vm_agent:               VMAgent                    = None,
        pgp_agent:              PGPAgent                   = None,
        max_workers:            int                        = 4,
        llm_interval:           int                        = 5,
        verbose:                bool                       = False
    ):
        self.puzzle_file            = puzzle_file
        self.state_file             = state_file
        self.crypto_agent           = crypto_agent
        self.code_agent             = code_agent
        self.vision_agent           = vision_agent
        self.web_agent              = web_agent
        self.fileheader_agent       = fileheader_agent      or FileHeaderAgent(verbose=verbose)
        self.text_extractor_agent   = text_extractor_agent  or TextExtractorAgent(verbose=verbose)
        self.pk_constructor_agent   = pk_constructor_agent  or PrivateKeyConstructorAgent(verbose=verbose)
        self.wallet_verifier_agent  = wallet_verifier_agent or WalletVerifierAgent(verbose=verbose)
        self.vm_agent               = vm_agent             or VMAgent(verbose=verbose)
        self.pgp_agent              = pgp_agent            or PGPAgent(verbose=verbose)
        self.max_workers            = max_workers
        self.llm_interval           = llm_interval
        self.verbose                = verbose

        # ── 1) Load or initialize state ─────────────────────────────────────────
        if os.path.exists(self.state_file):
            data = json.load(open(self.state_file))
            self.state = WorkflowState.from_dict(data)
            logger.info(f"🔄 Resumed state from {self.state_file}")
        else:
            self.state = WorkflowState(puzzle_file)
            logger.info("🆕 Starting fresh state")

        # ── 2) Wrap state mutations for logging & persistence ───────────────────
        self._wrap_state_logging()

        # ── 3) Run initial “material” agents ───────────────────────────────────
        for agent in (
            self.fileheader_agent,
            self.text_extractor_agent,
            self.pk_constructor_agent,
            self.wallet_verifier_agent,
            self.vm_agent,
            self.pgp_agent
        ):
            self.state = agent.run(self.state)

        # ── 4) Now safe to create TaskFactory with state ───────────────────────
        self.factory = TaskFactory(self.state)

        # ── 5) Schedule every analyzer on each material ────────────────────────
        for mat in self.state.materials.values():
            for name in get_all_analyzers().keys():
                for task in self.factory.create_tasks_for_analyzer(name, mat):
                    self.state.add_task(task)

        self.tasks_done    = 0
        self.last_llm_call = 0

    def _wrap_state_logging(self):
        def wrap(orig, tag):
            def fn(*args, **kwargs):
                logger.info(f"[{tag}] args={args} kwargs={kwargs}")
                res = orig(*args, **kwargs)
                self._save_state()
                return res
            return fn

        self.state.add_insight  = wrap(self.state.add_insight,  "INSIGHT")
        self.state.add_finding  = wrap(self.state.add_finding,  "FINDING")
        if hasattr(self.state, "add_material"):
            self.state.add_material = wrap(self.state.add_material, "FILE")
        self.state.set_solution = wrap(self.state.set_solution, "SOLUTION")

    def _save_state(self):
        try:
            with open(self.state_file, "w") as f:
                json.dump(self.state.to_dict(), f, indent=2)
            logger.debug(f"State saved → {self.state_file}")
        except Exception as e:
            logger.error(f"Failed saving state: {e}")

    def run(self, max_iterations: int = 100, timeout_minutes: int = 60) -> bool:
        deadline = datetime.now() + timedelta(minutes=timeout_minutes)
        logger.info(f"🚀 Orchestrator start: workers={self.max_workers}, timeout={timeout_minutes}m")

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures  = {}
            iteration = 0

            while iteration < max_iterations and datetime.now() < deadline:
                # 1) Check for solution
                if self.state.final_solution:
                    return True

                # 2) Periodic LLM planning
                if self.tasks_done - self.last_llm_call >= self.llm_interval:
                    self._llm_plan()
                    self.last_llm_call = self.tasks_done

                # 3) Integrate core agents every loop
                self.state = self.web_agent.run(self.state)
                self.state = self.vision_agent.run(self.state)
                self._code_agent_integrate()
                self.state = self.wallet_verifier_agent.run(self.state)
                self.state = self.vm_agent.run(self.state)
                self.state = self.pgp_agent.run(self.state)

                # 4) Dispatch ready analyzer tasks
                for task in self.state.get_executable_tasks():
                    futures[pool.submit(self.state.execute_task, task)] = task

                # 5) Collect results
                for fut in as_completed(list(futures.keys())):
                    task = futures.pop(fut)
                    ok, _ = fut.result()
                    if not ok:
                        logger.warning(f"Task failed: {task.id}")
                    self.tasks_done += 1
                    iteration    += 1

                # 6) Persist & idle if nothing to do
                self._save_state()
                if not futures and not self.state.get_executable_tasks():
                    time.sleep(0.2)

            logger.warning("⌛ Iteration/time limit reached without solution")
            return False

    def _llm_plan(self):
        logger.info("🤖 LLM planning…")
        try:
            assessment = self.crypto_agent.assess_state(self.state)
            plan       = self.crypto_agent.select_strategy(self.state, assessment)
            self.code_agent.receive_llm_plan(plan)

            for s in plan.get("suggestions", []):
                t = s.get("type")
                if t == "run_analyzer":
                    for m in self.state.materials.values():
                        for task in self.factory.create_tasks_for_analyzer(s["analyzer"], m):
                            self.state.add_task(task)
                elif t == "direct_solution":
                    sol = self.crypto_agent.attempt_direct(self.state)
                    if sol:
                        self.state.set_solution(sol)
                        return
        except Exception:
            logger.exception("LLM planning failed")

    def _code_agent_integrate(self):
        try:
            tool_ids = self.code_agent.analyze_and_create_tools(self.state)
            for tid in tool_ids:
                out = self.code_agent.use_tool(tid, {"state": self.state.to_dict()})
                self.state.add_finding(out)
            self.crypto_agent.receive_tool_outputs(tool_ids)
        except Exception:
            logger.exception("CodeAgent integration failed")
