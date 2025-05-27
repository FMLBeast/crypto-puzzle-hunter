#!/usr/bin/env python3
"""
orchestrator.py

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
import inspect

from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from state_management import WorkflowState
from task_factory import TaskFactory

logger = logging.getLogger(__name__)


class EnhancedOrchestrator:
    def __init__(
            self,
            provider: str = "openai",
            api_key: str = None,
            model: str = None,
            verbose: bool = False
    ):
        # logging is already configured by main.py
        logger.info("🔧 Initializing EnhancedOrchestrator")

        # 1) Core state
        self.state = WorkflowState()

        # 2) Initialize agents safely
        self._initialize_agents(provider, api_key, model, verbose)

        # 3) Task factory (needs state)
        self.factory = TaskFactory(self.state)

    def _initialize_agents(self, provider, api_key, model, verbose):
        """Initialize agents with proper error handling and parameter checking"""
        self.agents = {}

        # Define agent configurations - Updated for agents folder
        agent_configs = [
            ('crypto_agent', 'agents.agent', 'CryptoAgent', (provider, api_key, model, verbose)),
            ('code_agent', 'agents.code_agent', 'CodeAgent', ()),
            ('vision_agent', 'agents.vision_agent', 'VisionAgent', ()),
            ('web_agent', 'agents.web_agent', 'WebAgent', ()),
            ('wallet_verifier_agent', 'agents.wallet_verifier_agent', 'WalletVerifierAgent', ()),
            ('vm_agent', 'agents.vm_agent', 'VMAgent', ()),
            ('pgp_agent', 'agents.pgp_agent', 'PGPAgent', ()),
            ('fileheader_agent', 'agents.fileheader_agent', 'FileHeaderAgent', ()),
            ('text_extractor_agent', 'agents.text_extractor_agent', 'TextExtractorAgent', ()),
            ('pk_constructor_agent', 'agents.private_key_constructor_agent', 'PrivateKeyConstructorAgent', ())
        ]

        for attr_name, module_name, class_name, args in agent_configs:
            try:
                # Import the module
                module = __import__(module_name, fromlist=[class_name])
                agent_class = getattr(module, class_name)

                # Check if the class accepts verbose parameter
                sig = inspect.signature(agent_class.__init__)
                params = list(sig.parameters.keys())

                # Try to instantiate with appropriate parameters
                if attr_name == 'crypto_agent':
                    # CryptoAgent has specific parameters
                    agent = agent_class(*args)
                elif 'verbose' in params:
                    # Agent accepts verbose parameter
                    agent = agent_class(verbose=verbose)
                else:
                    # Agent doesn't accept verbose parameter
                    agent = agent_class()

                setattr(self, attr_name, agent)
                self.agents[attr_name] = agent

                if verbose:
                    logger.info(f"✅ Initialized {attr_name}")

            except ImportError as e:
                logger.warning(f"⚠️  Could not import {class_name} from {module_name}: {e}")
                setattr(self, attr_name, None)
            except TypeError as e:
                logger.warning(f"⚠️  Could not initialize {attr_name}: {e}")
                # Try fallback initialization without verbose
                try:
                    if attr_name == 'crypto_agent':
                        agent = agent_class(*args)
                    else:
                        agent = agent_class()
                    setattr(self, attr_name, agent)
                    self.agents[attr_name] = agent
                    logger.info(f"✅ Initialized {attr_name} (fallback)")
                except Exception as fallback_error:
                    logger.error(f"❌ Failed to initialize {attr_name}: {fallback_error}")
                    setattr(self, attr_name, None)
            except Exception as e:
                logger.error(f"❌ Unexpected error initializing {attr_name}: {e}")
                setattr(self, attr_name, None)

    def run(self, puzzle_path: str, timeout_minutes: int = 60):
        """
        1) Load root material
        2) Run all "pre-analysis" agents on it
        3) Generate initial tasks and loop until solution or timeout
        """
        logger.info(f"📁 Loading puzzle: {puzzle_path}")
        root = self.state.add_material(puzzle_path)

        # 3a) Pre-analysis: extract files, text, keys, wallets, VM, PGP
        pre_analysis_agents = [
            self.fileheader_agent,
            self.text_extractor_agent,
            self.pk_constructor_agent,
            self.wallet_verifier_agent,
            self.vm_agent,
            self.pgp_agent
        ]

        for agent in pre_analysis_agents:
            if agent is not None:
                try:
                    self.state = agent.run(self.state)
                except Exception as e:
                    logger.error(f"Error running pre-analysis agent {type(agent).__name__}: {e}")

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
        if not self.state.solution and self.crypto_agent:
            try:
                if hasattr(self.crypto_agent, 'attempt_direct'):
                    sol = self.crypto_agent.attempt_direct(self.state)
                elif hasattr(self.crypto_agent, '_attempt_direct_solution'):
                    self.crypto_agent._attempt_direct_solution(self.state)
                    sol = self.state.solution
                else:
                    logger.warning("CryptoAgent has no direct solution method")
                    sol = None

                if sol:
                    self.state.set_solution(sol)
            except Exception as e:
                logger.error(f"Error in direct solution attempt: {e}")

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
        try:
            # First check custom agents
            if name == "vision_analyzer" and self.vision_agent:
                # Check if VisionAgent.run accepts state parameter
                sig = inspect.signature(self.vision_agent.run)
                if len(sig.parameters) > 0:
                    self.state = self.vision_agent.run(self.state)
                else:
                    # VisionAgent.run() takes no arguments, try different approach
                    self.vision_agent.state = self.state
                    self.vision_agent.run()
                    self.state = getattr(self.vision_agent, 'state', self.state)
            elif name == "web_analyzer" and self.web_agent:
                self.state = self.web_agent.run(self.state)
            elif name == "wallet_verifier" and self.wallet_verifier_agent:
                self.state = self.wallet_verifier_agent.run(self.state)
            elif name == "vm_executor" and self.vm_agent:
                self.state = self.vm_agent.run(self.state)
            elif name == "pgp_agent" and self.pgp_agent:
                self.state = self.pgp_agent.run(self.state)
            elif self.crypto_agent and hasattr(self.crypto_agent, 'run_analyzer'):
                # CryptoAgent orchestrating analyzers
                self.state = self.crypto_agent.run_analyzer(name, self.state)
            else:
                logger.warning(f"No available agent for task: {name}")
        except Exception as e:
            logger.error(f"Error executing task {name}: {e}")
            raise