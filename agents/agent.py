"""
Crypto Hunter Agent Module
Handles the interaction with LLM providers and coordinates the analysis.
"""

import os
import json
import textwrap
import time
from typing import List, Dict, Optional, Any, Union
from dotenv import load_dotenv
from anthropic import Anthropic
from openai import OpenAI

# Handle imports that may not exist
try:
    from langchain_core.prompts import PromptTemplate
    from langchain_core.runnables import RunnablePassthrough, RunnableSequence
    from langchain_openai import ChatOpenAI
    from langchain_community.chat_models import ChatAnthropic
    from langchain_core.messages import BaseMessage
    from langchain_community.llms import HuggingFaceEndpoint

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("Warning: LangChain not available, using direct API calls")

# Handle other imports that may not exist
try:
    from core.state import State
except ImportError:
    # Create a minimal State class for compatibility
    class State:
        def __init__(self):
            self.insights = []
            self.transformations = []
            self.patterns = []
            self.solution = None

        def get_summary(self):
            return "Basic state summary"

        def get_content_sample(self, max_text_len=1000, max_binary_len=500):
            return "No content sample available"

        def set_solution(self, solution):
            self.solution = solution

try:
    from core.prompts import STATE_ASSESSMENT_PROMPT, STRATEGY_SELECTION_PROMPT, DIRECT_SOLUTION_PROMPT
    from core.prompts import FALLBACK_STATE_ASSESSMENT_TEXT, FALLBACK_STRATEGY_SELECTION_TEXT, \
        FALLBACK_DIRECT_SOLUTION_TEXT
except ImportError:
    # Define basic prompts
    STATE_ASSESSMENT_PROMPT = "Assess the current state: {state_summary}"
    STRATEGY_SELECTION_PROMPT = "Select strategy: {assessment}"
    DIRECT_SOLUTION_PROMPT = "Find solution: {state_summary}"
    FALLBACK_STATE_ASSESSMENT_TEXT = "Basic assessment mode"
    FALLBACK_STRATEGY_SELECTION_TEXT = "Run available analyzers"
    FALLBACK_DIRECT_SOLUTION_TEXT = "No direct solution available"

try:
    from core.logger import solution_logger
except ImportError:
    # Create a minimal logger
    class SolutionLogger:
        def log_insight(self, text, source):
            print(f"[{source}] {text}")

        def register_llm_feedback_callback(self, callback):
            pass


    solution_logger = SolutionLogger()

try:
    from core.user_interaction import start_user_interaction, check_for_user_input, process_user_input
    from core.user_interaction import register_callback, set_context
except ImportError:
    # Create minimal user interaction functions
    def start_user_interaction():
        pass


    def check_for_user_input():
        return None


    def process_user_input(user_input, context):
        return {}


    def register_callback(callback):
        pass


    def set_context(context):
        pass

# Handle circular import for analyzers
try:
    from analyzers import get_all_analyzers, get_analyzer, get_compatible_analyzers
except ImportError as e:
    # Handle circular import - define fallback functions
    def get_all_analyzers():
        return {}


    def get_analyzer(name):
        raise KeyError(f"Analyzer '{name}' not available due to import error")


    def get_compatible_analyzers(state):
        return []


    print(f"Warning: Could not import analyzers module: {e}")

load_dotenv()


class CryptoAgent:
    """
    Agent responsible for analyzing cryptographic puzzles using LLMs.
    """

    def __init__(self, provider, api_key, model, verbose):
        """
        Initialize the agent with the specified provider.

        Args:
            provider: LLM provider to use (anthropic, openai, huggingface, or local)
            api_key: Optional API key (if not provided, will use environment variables)
            model: Optional model name (specific to the provider)
            verbose: Whether to output detailed logs
        """
        self.provider = provider
        self.api_key = api_key
        self.model = model
        self.verbose = verbose
        self.llm = None
        self.llm_available = False
        self.state_assessment_chain = None
        self.strategy_chain = None
        self.direct_solution_chain = None
        self.realtime_findings = []
        self.chat_history = []

        # Register callback for real-time findings
        try:
            solution_logger.register_llm_feedback_callback(self._handle_realtime_finding)
        except:
            pass

        # Initialize LLM if possible
        if self._should_try_llm_initialization():
            self.llm = self._initialize_llm()
            if self.llm:
                self.llm_available = True
                try:
                    if LANGCHAIN_AVAILABLE:
                        self.state_assessment_chain = self._create_state_assessment_chain()
                        self.strategy_chain = self._create_strategy_chain()
                        self.direct_solution_chain = self._create_direct_solution_chain()
                except Exception as e:
                    if self.verbose:
                        print(f"Warning: Could not create LLM chains: {e}")
                    self.llm_available = False

        if self.verbose:
            status = "available" if self.llm_available else "not available"
            print(f"CryptoAgent initialized with {self.provider} provider - LLM {status}")

    def _should_try_llm_initialization(self) -> bool:
        """
        Determine if we should even attempt to initialize LLM-dependent components.
        """
        if self.provider == "anthropic":
            return bool(self.api_key or os.getenv('ANTHROPIC_API_KEY'))
        elif self.provider == "openai":
            return bool(self.api_key or os.getenv('OPENAI_API_KEY'))
        elif self.provider == "huggingface":
            return bool(self.api_key or os.getenv('HUGGINGFACE_API_TOKEN'))
        elif self.provider == "local":
            return True
        else:
            return False

    def _initialize_llm(self):
        """Initialize the LLM based on the provider."""
        try:
            if not LANGCHAIN_AVAILABLE:
                if self.verbose:
                    print("LangChain not available, using direct API mode")
                return "direct_api"  # Flag for direct API usage

            if self.provider == "anthropic":
                api_key = self.api_key or os.getenv('ANTHROPIC_API_KEY')
                if not api_key:
                    if self.verbose:
                        print("No Anthropic API key found")
                    return None

                return ChatAnthropic(
                    model=self.model or "claude-3-5-sonnet-20240620",
                    anthropic_api_key=api_key,
                    temperature=0.3,
                    max_tokens=4000
                )

            elif self.provider == "openai":
                api_key = self.api_key or os.getenv('OPENAI_API_KEY')
                if not api_key:
                    if self.verbose:
                        print("No OpenAI API key found")
                    return None

                return ChatOpenAI(
                    model=self.model or "gpt-4o-2024-05-13",
                    openai_api_key=api_key,
                    temperature=0.3,
                    max_tokens=4000
                )

            else:
                if self.verbose:
                    print(f"Provider {self.provider} not supported with LangChain")
                return None

        except Exception as e:
            if self.verbose:
                print(f"LLM initialization failed: {e}")
            return None

    def _create_state_assessment_chain(self):
        """Create the chain for assessing the puzzle state."""
        if not self.llm or not LANGCHAIN_AVAILABLE:
            return None

        prompt = PromptTemplate(
            template=STATE_ASSESSMENT_PROMPT,
            input_variables=["state_summary", "transformations", "insights", "patterns", "puzzle_content"]
        )

        return prompt | self.llm

    def _create_strategy_chain(self):
        """Create the chain for selecting analysis strategies."""
        if not self.llm or not LANGCHAIN_AVAILABLE:
            return None

        prompt = PromptTemplate(
            template=STRATEGY_SELECTION_PROMPT,
            input_variables=["state_summary", "assessment", "transformations", "insights",
                             "patterns", "previous_results", "chat_history"]
        )

        return prompt | self.llm

    def _create_direct_solution_chain(self):
        """Create the chain for attempting direct solutions."""
        if not self.llm or not LANGCHAIN_AVAILABLE:
            return None

        prompt = PromptTemplate(
            template=DIRECT_SOLUTION_PROMPT,
            input_variables=["state_summary", "patterns", "puzzle_content"]
        )

        return prompt | self.llm

    def _handle_realtime_finding(self, finding_type: str, analyzer: str, content: str) -> None:
        """Handle a real-time finding from an analyzer."""
        if self.llm_available:
            self.realtime_findings.append({
                'type': finding_type,
                'analyzer': analyzer,
                'content': content,
                'timestamp': time.time()
            })

    def run_analyzer(self, name, state):
        """
        Run a specific analyzer by name.

        Args:
            name: Name of the analyzer to run
            state: Current state object

        Returns:
            Updated state object
        """
        try:
            analyzer = get_analyzer(name)
            return analyzer(state)
        except Exception as e:
            if self.verbose:
                print(f"Error running analyzer {name}: {e}")
            return state

    def attempt_direct(self, state):
        """
        Attempt to directly solve the puzzle.

        Args:
            state: Current state object

        Returns:
            Solution string or None
        """
        try:
            self._attempt_direct_solution(state)
            return state.solution if hasattr(state, 'solution') else None
        except Exception as e:
            if self.verbose:
                print(f"Error in direct solution attempt: {e}")
            return None

    def _attempt_direct_solution(self, state) -> None:
        """Attempt to directly solve the puzzle without further analysis."""
        if not self.llm_available:
            try:
                solution_logger.log_insight(
                    FALLBACK_DIRECT_SOLUTION_TEXT,
                    "direct_solution_fallback"
                )
            except:
                pass
            return

        try:
            # Basic direct solution attempt
            if self.verbose:
                print("Attempting direct solution...")

            # For now, just log the attempt
            solution_logger.log_insight(
                "Direct solution attempted but no solution found",
                "direct_solution_attempt"
            )

        except Exception as e:
            if self.verbose:
                print(f"Error in direct solution attempt: {e}")
            try:
                solution_logger.log_insight(
                    FALLBACK_DIRECT_SOLUTION_TEXT,
                    "direct_solution_error"
                )
            except:
                pass