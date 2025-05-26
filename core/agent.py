"""
Crypto Hunter Agent Module
Handles the interaction with LLM providers and coordinates the analysis.
"""
import os
import json
import textwrap
import time
from typing import List, Dict, Optional, Any, Union
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnablePassthrough, RunnableSequence
from langchain_openai import ChatOpenAI
from langchain_community.chat_models import ChatAnthropic
from langchain_core.messages import BaseMessage
from langchain_community.llms import HuggingFaceEndpoint

from core.state import State
from core.prompts import (
    STATE_ASSESSMENT_PROMPT,
    STRATEGY_SELECTION_PROMPT,
    DIRECT_SOLUTION_PROMPT,
    FALLBACK_STATE_ASSESSMENT_TEXT,
    FALLBACK_STRATEGY_SELECTION_TEXT,
    FALLBACK_DIRECT_SOLUTION_TEXT
)

class CryptoAgent:
    """
    Agent responsible for analyzing cryptographic puzzles using LLMs.
    """
    def __init__(self, provider="anthropic", api_key=None, model=None, verbose=False):
        """
        Initialize the agent with the specified provider.

        Args:
            provider: LLM provider to use (anthropic, openai, huggingface, or local)
            api_key: Optional API key (if not provided, will use environment variables)
            model: Optional model name (specific to the provider)
            verbose: Whether to output detailed logs
        """
        # Ensure environment variables are loaded from .env file
        from dotenv import load_dotenv
        load_dotenv()

        self.provider = provider
        self.api_key = api_key
        self.model = model
        self.verbose = verbose
        self.chat_history = []
        self.fallback_mode = False

        # For real-time LLM feedback
        self.realtime_findings = []

        # Register callback with solution logger
        from core.logger import solution_logger
        solution_logger.register_llm_feedback_callback(self._handle_realtime_finding)

        # Check environment variables for API keys
        if not self.api_key:
            if provider == "anthropic":
                self.api_key = os.environ.get("ANTHROPIC_API_KEY")
            elif provider == "openai":
                self.api_key = os.environ.get("OPENAI_API_KEY")
            elif provider == "huggingface":
                self.api_key = os.environ.get("HUGGINGFACE_API_KEY")

        # Check if we should even try to initialize LLM-dependent components
        should_try_llm = self._should_try_llm_initialization()

        if not should_try_llm:
            if verbose:
                print("Skipping LLM initialization as API access is likely unavailable")
            self.fallback_mode = True
            self.llm = None
            return

        # Test API access before initializing
        if not self._test_api_access():
            print("API credentials unavailable. Using fallback mode.")
            self.fallback_mode = True
            self.llm = None
            return

        # Initialize the LLM
        self.llm = self._initialize_llm()

        # Create the chains
        if self.llm:
            self.state_assessment_chain = self._create_state_assessment_chain()
            self.strategy_chain = self._create_strategy_chain()
            self.direct_solution_chain = self._create_direct_solution_chain()
        else:
            self.fallback_mode = True
            print("No LLM available. Using fallback mode.")

    def _should_try_llm_initialization(self) -> bool:
        """
        Determine if we should even attempt to initialize LLM-dependent components.
        This prevents unnecessary API calls when it's clear no API access is available.

        Returns:
            True if we should try to initialize LLM components, False otherwise
        """
        # Check if API keys are set in environment or provided directly
        if self.api_key:
            return True

        if self.provider == "anthropic" and os.environ.get("ANTHROPIC_API_KEY"):
            return True

        if self.provider == "openai" and os.environ.get("OPENAI_API_KEY"):
            return True

        if self.provider == "huggingface" and os.environ.get("HUGGINGFACE_API_KEY"):
            return True

        # If we're using a local provider, we can try
        if self.provider == "local":
            return True

        # No API keys available, don't try to initialize
        return False

    def _test_api_access(self):
        """Test if the API key is valid."""
        if not self.api_key:
            print("No API key provided. Cannot access LLM API.")
            return False

        try:
            if self.provider == "anthropic":
                # Test Anthropic API
                try:
                    from anthropic import Anthropic
                    client = Anthropic(auth_token=self.api_key)
                    response = client.messages.create(
                        model="claude-3-haiku-20240307",
                        max_tokens=10,
                        messages=[{"role": "user", "content": "Hello"}]
                    )
                    print("Successfully connected to Anthropic API.")
                    return True
                except Exception as e:
                    # Only ignore certain types of errors that don't indicate API key issues
                    error_str = str(e).lower()
                    if "rate limit" in error_str or "timeout" in error_str or "connection" in error_str:
                        print(f"Anthropic API access issue (but key seems valid): {e}")
                        return True
                    else:
                        print(f"Anthropic API authentication error: {e}")
                        print("Please check your ANTHROPIC_API_KEY in the .env file.")
                        return False

            elif self.provider == "openai":
                # Test OpenAI API
                try:
                    from openai import OpenAI
                    client = OpenAI(api_key=self.api_key)
                    response = client.chat.completions.create(
                        model="gpt-3.5-turbo",
                        messages=[{"role": "user", "content": "Hello"}],
                        max_tokens=10
                    )
                    print("Successfully connected to OpenAI API.")
                    return True
                except Exception as e:
                    # Only ignore certain types of errors that don't indicate API key issues
                    error_str = str(e).lower()
                    if "rate limit" in error_str or "timeout" in error_str or "connection" in error_str:
                        print(f"OpenAI API access issue (but key seems valid): {e}")
                        return True
                    else:
                        print(f"OpenAI API authentication error: {e}")
                        print("Please check your OPENAI_API_KEY in the .env file.")
                        return False

            return True  # Assume other providers are OK

        except Exception as e:
            print(f"Error testing API access: {e}")
            return False

    def _initialize_llm(self):
        """
        Initialize the LLM based on the provider.
        Returns the LLM or None if initialization fails.
        """
        try:
            if self.provider == "anthropic":
                print(f"Initializing Anthropic LLM with API key: {self.api_key[:5]}...{self.api_key[-5:] if self.api_key else ''}")

                # Explicitly set the environment variable as well
                os.environ["ANTHROPIC_API_KEY"] = self.api_key

                try:
                    llm = ChatAnthropic(
                        model_name=self.model or "claude-3-opus-20240229",
                        anthropic_api_key=self.api_key,
                        temperature=0.2
                    )
                    print("Successfully initialized Anthropic LLM.")
                    return llm
                except Exception as e:
                    print(f"Failed to initialize Anthropic LLM: {e}")
                    print("Please check your ANTHROPIC_API_KEY in the .env file.")
                    return None

            elif self.provider == "openai":
                print(f"Initializing OpenAI LLM with API key: {self.api_key[:5]}...{self.api_key[-5:] if self.api_key else ''}")

                # Explicitly set the environment variable as well
                os.environ["OPENAI_API_KEY"] = self.api_key

                try:
                    llm = ChatOpenAI(
                        model_name=self.model or "gpt-4o",
                        api_key=self.api_key,
                        temperature=0.2
                    )
                    print("Successfully initialized OpenAI LLM.")
                    return llm
                except Exception as e:
                    print(f"Failed to initialize OpenAI LLM: {e}")
                    print("Please check your OPENAI_API_KEY in the .env file.")
                    return None

            elif self.provider == "huggingface":
                # Use Hugging Face model (usually free for those with access)
                print(f"Initializing HuggingFace LLM with API key: {self.api_key[:5]}...{self.api_key[-5:] if self.api_key else ''}")

                # Explicitly set the environment variable as well
                os.environ["HUGGINGFACE_API_KEY"] = self.api_key

                try:
                    llm = HuggingFaceEndpoint(
                        repo_id=self.model or "mistralai/Mistral-7B-Instruct-v0.2",
                        huggingfacehub_api_token=self.api_key,
                        temperature=0.2
                    )
                    print("Successfully initialized HuggingFace LLM.")
                    return llm
                except Exception as e:
                    print(f"Failed to initialize HuggingFace LLM: {e}")
                    print("Please check your HUGGINGFACE_API_KEY in the .env file.")
                    return None

            elif self.provider == "local":
                # Support for local models like Ollama could be added here
                print("Local model support not yet implemented. Using fallback mode.")
                return None

            else:
                print(f"Unsupported provider: {self.provider}. Using fallback mode.")
                return None

        except Exception as e:
            print(f"Error initializing LLM: {e}")
            return None

    def _create_state_assessment_chain(self):
        """Create the chain for assessing the puzzle state."""
        if not self.llm:
            return None

        prompt = PromptTemplate(
            input_variables=["state_summary", "transformations", "insights", "puzzle_content"],
            template=STATE_ASSESSMENT_PROMPT,
        )

        chain = prompt | self.llm
        return chain

    def _create_strategy_chain(self):
        """Create the chain for selecting analysis strategies."""
        if not self.llm:
            return None

        prompt = PromptTemplate(
            input_variables=["state_summary", "assessment", "transformations", "insights", "chat_history"],
            template=STRATEGY_SELECTION_PROMPT,
        )

        chain = prompt | self.llm
        return chain

    def _create_direct_solution_chain(self):
        """Create the chain for attempting direct solutions."""
        if not self.llm:
            return None

        prompt = PromptTemplate(
            input_variables=["state_summary", "puzzle_content"],
            template=DIRECT_SOLUTION_PROMPT,
        )

        chain = prompt | self.llm
        return chain

    def _fallback_assessment(self, state):
        """
        Provide a basic assessment of the puzzle when in fallback mode.
        """
        return FALLBACK_STATE_ASSESSMENT_TEXT.format(
            file_type=state.file_type,
            file_size=state.file_size
        )

    def _fallback_strategy(self, state):
        """
        Provide basic strategy recommendations when in fallback mode.
        """
        return FALLBACK_STRATEGY_SELECTION_TEXT

    def _fallback_direct_solution(self, state):
        """
        Attempt basic solution approaches when in fallback mode.
        """
        return FALLBACK_DIRECT_SOLUTION_TEXT

    def _handle_realtime_finding(self, finding_type: str, analyzer: str, content: str) -> None:
        """
        Handle a real-time finding from an analyzer.

        Args:
            finding_type: Type of finding (insight or transformation)
            analyzer: Name of the analyzer that generated the finding
            content: Content of the finding
        """
        # Add to the list of real-time findings
        self.realtime_findings.append({
            "type": finding_type,
            "analyzer": analyzer,
            "content": content,
            "time": time.strftime("%H:%M:%S")
        })

        # Send to LLM if we're not in fallback mode
        if not self.fallback_mode and self.llm:
            self._send_realtime_findings_to_llm()

    def _send_realtime_findings_to_llm(self) -> None:
        """
        Send real-time findings to the LLM.
        """
        if not self.realtime_findings:
            return

        # Prepare the prompt with the real-time findings
        findings_text = "\n\n".join([
            f"[{finding['time']}] {finding['analyzer']} ({finding['type']}): {finding['content']}"
            for finding in self.realtime_findings
        ])

        prompt = f"""
        The following findings have been discovered during the analysis process:

        {findings_text}

        Please keep these findings in mind as you continue to analyze the puzzle.
        No response is needed at this time - this is just to keep you informed of the ongoing analysis.
        """

        # Send to LLM without expecting a response
        try:
            self._send_to_llm_without_response(prompt)
            # Clear the list of real-time findings
            self.realtime_findings = []
        except Exception as e:
            print(f"Error sending real-time findings to LLM: {e}")

    def _send_to_llm_without_response(self, prompt: str) -> None:
        """
        Send a prompt to the LLM without expecting a response.

        Args:
            prompt: Text prompt to send
        """
        if self.fallback_mode or not self.llm:
            return

        try:
            # Just invoke the LLM without processing the response
            self.llm.invoke(prompt)
        except Exception as e:
            error_str = str(e)
            print(f"Error sending to LLM: {error_str}")

            # Check for quota exceeded or rate limit errors
            if "429" in error_str or "rate limit" in error_str.lower() or "quota" in error_str.lower():
                print("API quota exceeded or rate limit reached. Disabling real-time feedback.")
                # Don't set fallback_mode to True, just disable real-time feedback
                self.realtime_findings = []

    def _send_to_llm(self, prompt):
        """
        Safely send a prompt to the LLM.

        Args:
            prompt: Text prompt to send

        Returns:
            Response text or None if failed
        """
        if self.fallback_mode or not self.llm:
            return None

        try:
            result = self.llm.invoke(prompt)
            if hasattr(result, 'content'):
                return result.content
            return str(result)
        except Exception as e:
            error_str = str(e)
            print(f"Error sending to LLM: {error_str}")

            # Check for context length exceeded errors
            if "context_length_exceeded" in error_str.lower() or "maximum context length" in error_str.lower():
                print("Context length exceeded. The input is too large for the model.")
                print("Switching to fallback mode with reduced content.")

                # Don't set fallback_mode to True here, as we might be able to retry with smaller content
                # Instead, return a message indicating the issue
                return "ERROR: Context length exceeded. Please reduce the size of the input or use a model with a larger context window."

            # Check for quota exceeded or rate limit errors
            if "429" in error_str or "rate limit" in error_str.lower() or "quota" in error_str.lower():
                print("API quota exceeded or rate limit reached. Switching to fallback mode.")
                self.fallback_mode = True

                # If this is OpenAI, provide more specific guidance
                if self.provider == "openai":
                    print("OpenAI API quota exceeded. Please check your billing details or try again later.")

            return None

    def analyze(self, state: State, max_iterations: int = 5) -> State:
        """
        Analyze the puzzle and attempt to solve it.

        The analysis process includes multiple strategies with enhanced LLM orchestration:
        1. Using LLM to assess the state and select appropriate analyzers
        2. Executing selected analyzers to gain insights
        3. LLM reviews results and decides next steps dynamically
        4. LLM can pass information between analyzers and create feedback loops
        5. Using code-based analysis when other approaches fail or get stuck
        6. Attempting direct solution as a last resort

        The LLM acts as the central orchestrator, making decisions at each step
        and steering the entire analysis process with continuous feedback loops.

        Findings from analyzers are fed back to the LLM in real-time to provide
        continuous feedback during the analysis process.

        Args:
            state: The current puzzle state
            max_iterations: Maximum number of analysis iterations

        Returns:
            Updated puzzle state
        """
        # Import solution_logger for accessing pending findings
        from core.logger import solution_logger
        # Import user interaction module
        try:
            from core.user_interaction import (
                start_user_interaction, check_for_user_input, 
                process_user_input, register_callback, set_context
            )
            user_interaction_available = True
        except ImportError:
            user_interaction_available = False
            print("User interaction module not available. Running without interactive capabilities.")

        # Setup user interaction if available
        if user_interaction_available:
            # Start listening for user input
            start_user_interaction()

            # Register callback for handling questions
            def handle_question(question: str, context: dict) -> str:
                """Handle user questions during analysis."""
                try:
                    # Generate a response using the LLM
                    prompt = f"""
                    The user has asked the following question during puzzle analysis:
                    "{question}"

                    Current puzzle state:
                    - Puzzle type: {context.get('puzzle_type', 'Unknown')}
                    - Current insights: {len(context.get('insights', []))} insights gathered
                    - Current transformations: {len(context.get('transformations', []))} transformations applied
                    - Solution found: {'Yes' if context.get('solution') else 'No'}

                    Please provide a helpful response to the user's question.
                    """

                    response = self._send_to_llm(prompt)
                    return response or "I'm sorry, I couldn't generate a response at this time."
                except Exception as e:
                    return f"Error processing your question: {str(e)}"

            register_callback("question_callback", handle_question)

        # Handle fallback mode
        if self.fallback_mode:
            print("Running in fallback mode without LLM assistance.")
            state.add_insight("Using fallback mode (no API access available). Running basic analyzers only.", analyzer="agent")

            # Run through available analyzers without LLM guidance
            from analyzers import get_all_analyzers, get_analyzer, get_compatible_analyzers

            # Get only analyzers that are compatible with the current state
            compatible_analyzer_names = get_compatible_analyzers(state)
            analyzers = {name: get_analyzer(name) for name in compatible_analyzer_names}

            # If the puzzle has binary data but no text, try to extract text
            if state.binary_data and not state.puzzle_text:
                try:
                    # Try to decode binary data as text
                    text = state.binary_data.decode('utf-8', errors='replace')
                    if any(c.isprintable() for c in text):
                        state.set_puzzle_text(text)
                        state.add_insight(
                            "Extracted text from binary data to enable text-based analyzers",
                            analyzer="agent"
                        )

                        # Update compatible analyzers after adding text
                        compatible_analyzer_names = get_compatible_analyzers(state)
                        analyzers = {name: get_analyzer(name) for name in compatible_analyzer_names}
                except Exception as e:
                    print(f"Error extracting text from binary data: {e}")

            # Track if we've made progress
            initial_insights_count = len(state.insights)

            # Print which analyzers will be run
            print(f"Running {len(analyzers)} compatible analyzers: {', '.join(analyzers.keys())}")

            for name, analyzer_func in analyzers.items():
                try:
                    print(f"Running {name}...")
                    state = analyzer_func(state)

                    # Check for user input if available
                    if user_interaction_available:
                        user_input = check_for_user_input()
                        if user_input:
                            context = {
                                "puzzle_type": state.puzzle_type,
                                "insights": state.insights,
                                "transformations": state.transformations,
                                "solution": state.solution,
                                "current_task": f"Running analyzer: {name}"
                            }
                            set_context(context)
                            process_user_input(user_input, context)

                except Exception as e:
                    print(f"Error in {name}: {e}")
                    state.add_insight(f"Error in {name}: {e}", analyzer="agent")

            # If we haven't made progress or found a solution, try code-based analysis
            if len(state.insights) == initial_insights_count or not state.solution:
                print("No progress made with basic analyzers. Trying code-based analysis...")
                code_analyzer = get_analyzer("code_analyzer")
                if code_analyzer:
                    try:
                        state.add_insight("No progress with basic analyzers. Switching to code-based analysis.", analyzer="agent")
                        state = code_analyzer(state, task_description="Generate and execute Python code to solve this puzzle when other analyzers have failed")
                    except Exception as e:
                        print(f"Error in code_analyzer: {e}")
                        state.add_insight(f"Error in code_analyzer: {e}", analyzer="agent")

            return state

        # Regular mode with LLM
        iteration = 0
        previous_insights_count = 0
        previous_transformations_count = 0
        analyzer_results_history = []  # Track results of each analyzer run

        while iteration < max_iterations:
            try:
                iteration += 1
                print(f"Iteration {iteration}/{max_iterations}")

                # Update context for user interaction
                if user_interaction_available:
                    context = {
                        "puzzle_type": state.puzzle_type,
                        "insights": state.insights,
                        "transformations": state.transformations,
                        "solution": state.solution,
                        "current_task": f"Analysis iteration {iteration}/{max_iterations}",
                        "progress": f"{iteration}/{max_iterations}"
                    }
                    set_context(context)

                # Check for user input
                if user_interaction_available:
                    user_input = check_for_user_input()
                    if user_input:
                        process_user_input(user_input, context)

                # Check if we've made progress
                if previous_insights_count == len(state.insights) and iteration > 1:
                    print("No new insights gained in this iteration. Consulting LLM for next steps...")

                    # Let the LLM decide what to do when we're stuck
                    stuck_prompt = f"""
                    You are the orchestrator for a cryptographic puzzle solving system.

                    We've reached iteration {iteration}/{max_iterations} and no new insights have been gained.

                    Current puzzle state summary:
                    {state.get_summary()}

                    What should we do next? Options include:
                    1. Try code-based analysis
                    2. Try a specific analyzer with specific parameters
                    3. Attempt a direct solution
                    4. Try a completely different approach

                    Available analyzers (ONLY use analyzers from this list):
                    - text_analyzer: For analyzing text patterns and encodings
                    - text_pattern_analyzer: For advanced pattern recognition in text
                    - binary_analyzer: For analyzing binary data
                    - image_analyzer: For analyzing images (steganography)
                    - cipher_analyzer: For detecting and solving classical ciphers
                    - encoding_analyzer: For detecting and decoding various encodings
                    - blockchain_analyzer: For analyzing crypto addresses and data
                    - crypto_analyzer: For analyzing cryptographic elements including hashes, keys, and signatures
                    - code_analyzer: For generating and executing Python code to solve the puzzle
                    - vision_analyzer: For analyzing images using computer vision techniques
                    - web_analyzer: For analyzing web-related content and URLs

                    IMPORTANT: Do NOT suggest analyzers that are not in the above list. If you need functionality that isn't covered by these analyzers, use code_analyzer to generate custom code instead.

                    Provide your decision in JSON format:
                    {{
                        "action": "code_analysis" or "specific_analyzer" or "direct_solution" or "new_approach",
                        "reasoning": "Your reasoning for this decision",
                        "analyzer": "Name of specific analyzer to run (if applicable)",
                        "params": {{}} // Parameters for the specific analyzer (if applicable)
                    }}
                    """

                    stuck_result = self._send_to_llm(stuck_prompt)

                    if stuck_result:
                        try:
                            # Extract JSON from the text
                            json_part = stuck_result
                            if "```json" in stuck_result:
                                json_part = stuck_result.split("```json")[1].split("```")[0].strip()
                            elif "```" in stuck_result:
                                json_part = stuck_result.split("```")[1].strip()

                            decision = json.loads(json_part)
                            action = decision.get("action", "code_analysis")
                            reasoning = decision.get("reasoning", "No progress made, trying a different approach")

                            state.add_insight(f"LLM decision when stuck: {reasoning}", analyzer="agent")

                            if action == "code_analysis":
                                # Try code-based analysis
                                from analyzers import get_analyzer
                                code_analyzer = get_analyzer("code_analyzer")
                                if code_analyzer:
                                    print("Running code-based analysis as suggested by LLM...")
                                    state.add_insight("LLM suggests code-based analysis.", analyzer="agent")
                                    state = code_analyzer(state, task_description="Analyze this puzzle and try to find a solution when other analyzers have failed")

                                    # Review the results of the code analyzer
                                    code_review = self._review_analyzer_results(
                                        state, 
                                        "code_analyzer", 
                                        previous_insights_count, 
                                        previous_transformations_count
                                    )

                                    if code_review.get("next_action") == "direct_solution" or not state.solution:
                                        print("Code-based analysis didn't find a solution. Trying direct solution...")
                                        self._attempt_direct_solution(state)
                                else:
                                    # Fallback to direct solution if code analyzer not available
                                    print("Code analyzer not available. Trying direct solution...")
                                    self._attempt_direct_solution(state)
                            elif action == "specific_analyzer":
                                # Run a specific analyzer
                                specific_analyzer = decision.get("analyzer")
                                specific_params = decision.get("params", {})

                                if specific_analyzer:
                                    from analyzers import get_analyzer
                                    analyzer_func = get_analyzer(specific_analyzer)
                                    if analyzer_func:
                                        print(f"Running specific analyzer {specific_analyzer} as suggested by LLM...")
                                        state.add_insight(f"LLM suggests running {specific_analyzer}.", analyzer="agent")
                                        state = analyzer_func(state, **specific_params)
                                    else:
                                        state.add_insight(f"Analyzer '{specific_analyzer}' suggested by LLM not found", analyzer="agent")
                                        self._attempt_direct_solution(state)
                                else:
                                    self._attempt_direct_solution(state)
                            elif action == "direct_solution":
                                # Try direct solution
                                print("Trying direct solution as suggested by LLM...")
                                state.add_insight("LLM suggests attempting direct solution.", analyzer="agent")
                                self._attempt_direct_solution(state)
                            else:
                                # Try a new approach (default to direct solution)
                                print("Trying direct solution as a new approach...")
                                state.add_insight("LLM suggests a new approach. Attempting direct solution.", analyzer="agent")
                                self._attempt_direct_solution(state)
                        except Exception as e:
                            print(f"Error processing LLM decision: {e}")
                            # Fall back to code analysis
                            from analyzers import get_analyzer
                            code_analyzer = get_analyzer("code_analyzer")
                            if code_analyzer:
                                print("Running code-based analysis...")
                                state.add_insight("No new insights gained. Switching to code-based analysis.", analyzer="agent")
                                state = code_analyzer(state, task_description="Analyze this puzzle and try to find a solution when other analyzers have failed")

                                if not state.solution:
                                    self._attempt_direct_solution(state)
                            else:
                                self._attempt_direct_solution(state)
                    else:
                        # If LLM fails, fall back to code analysis
                        from analyzers import get_analyzer
                        code_analyzer = get_analyzer("code_analyzer")
                        if code_analyzer:
                            print("Running code-based analysis...")
                            state.add_insight("No new insights gained. Switching to code-based analysis.", analyzer="agent")
                            state = code_analyzer(state, task_description="Analyze this puzzle and try to find a solution when other analyzers have failed")

                            if not state.solution:
                                self._attempt_direct_solution(state)
                        else:
                            self._attempt_direct_solution(state)

                # Store current counts for later comparison
                previous_insights_count = len(state.insights)
                previous_transformations_count = len(state.transformations)

                # Assess the current state
                print("Assessing current state...")
                assessment = self._assess_state(state)
                if assessment:
                    state.add_insight(f"Assessment: {assessment}", analyzer="agent")

                # Check for user input again
                if user_interaction_available:
                    user_input = check_for_user_input()
                    if user_input:
                        process_user_input(user_input, context)

                # Format previous analyzer results for the LLM
                previous_results = None
                if analyzer_results_history:
                    # Format the last few analyzer results
                    last_results = analyzer_results_history[-3:] if len(analyzer_results_history) > 3 else analyzer_results_history
                    previous_results = json.dumps(last_results, indent=2)

                # Select a strategy
                print("Selecting strategy...")
                strategy_result = self._select_strategy(state, assessment, previous_results)
                if not strategy_result:
                    print("Failed to select a strategy. Consulting LLM for next steps...")

                    # Let the LLM decide what to do when strategy selection fails
                    strategy_fail_prompt = f"""
                    You are the orchestrator for a cryptographic puzzle solving system.

                    We've failed to select a strategy in iteration {iteration}/{max_iterations}.

                    Current puzzle state summary:
                    {state.get_summary()}

                    What should we do next? Options include:
                    1. Try code-based analysis
                    2. Try a specific analyzer with specific parameters
                    3. Attempt a direct solution

                    Available analyzers (ONLY use analyzers from this list):
                    - text_analyzer: For analyzing text patterns and encodings
                    - text_pattern_analyzer: For advanced pattern recognition in text
                    - binary_analyzer: For analyzing binary data
                    - image_analyzer: For analyzing images (steganography)
                    - cipher_analyzer: For detecting and solving classical ciphers
                    - encoding_analyzer: For detecting and decoding various encodings
                    - blockchain_analyzer: For analyzing crypto addresses and data
                    - crypto_analyzer: For analyzing cryptographic elements including hashes, keys, and signatures
                    - code_analyzer: For generating and executing Python code to solve the puzzle
                    - vision_analyzer: For analyzing images using computer vision techniques
                    - web_analyzer: For analyzing web-related content and URLs

                    IMPORTANT: Do NOT suggest analyzers that are not in the above list. If you need functionality that isn't covered by these analyzers, use code_analyzer to generate custom code instead.

                    Provide your decision in JSON format:
                    {{
                        "action": "code_analysis" or "specific_analyzer" or "direct_solution",
                        "reasoning": "Your reasoning for this decision",
                        "analyzer": "Name of specific analyzer to run (if applicable)",
                        "params": {{}} // Parameters for the specific analyzer (if applicable)
                    }}
                    """

                    fail_result = self._send_to_llm(strategy_fail_prompt)

                    if fail_result:
                        try:
                            # Extract JSON from the text
                            json_part = fail_result
                            if "```json" in fail_result:
                                json_part = fail_result.split("```json")[1].split("```")[0].strip()
                            elif "```" in fail_result:
                                json_part = fail_result.split("```")[1].strip()

                            decision = json.loads(json_part)
                            action = decision.get("action", "code_analysis")
                            reasoning = decision.get("reasoning", "Strategy selection failed, trying a different approach")

                            state.add_insight(f"LLM decision after strategy failure: {reasoning}", analyzer="agent")

                            if action == "code_analysis" or action == "direct_solution":
                                # Try code-based analysis first
                                from analyzers import get_analyzer
                                code_analyzer = get_analyzer("code_analyzer")
                                if code_analyzer:
                                    print("Running code-based analysis as suggested by LLM...")
                                    state.add_insight("LLM suggests code-based analysis after strategy failure.", analyzer="agent")
                                    state = code_analyzer(state, task_description="Generate and execute Python code to solve this puzzle when no clear strategy is available")

                                    if not state.solution:
                                        print("Code-based analysis didn't find a solution. Trying direct solution...")
                                        self._attempt_direct_solution(state)
                                else:
                                    # Fallback to direct solution if code analyzer not available
                                    print("Code analyzer not available. Trying direct solution...")
                                    self._attempt_direct_solution(state)
                            elif action == "specific_analyzer":
                                # Run a specific analyzer
                                specific_analyzer = decision.get("analyzer")
                                specific_params = decision.get("params", {})

                                if specific_analyzer:
                                    from analyzers import get_analyzer
                                    analyzer_func = get_analyzer(specific_analyzer)
                                    if analyzer_func:
                                        print(f"Running specific analyzer {specific_analyzer} as suggested by LLM...")
                                        state.add_insight(f"LLM suggests running {specific_analyzer} after strategy failure.", analyzer="agent")
                                        state = analyzer_func(state, **specific_params)
                                    else:
                                        state.add_insight(f"Analyzer '{specific_analyzer}' suggested by LLM not found", analyzer="agent")
                                        self._attempt_direct_solution(state)
                                else:
                                    self._attempt_direct_solution(state)
                        except Exception as e:
                            print(f"Error processing LLM decision: {e}")
                            # Fall back to code analysis
                            from analyzers import get_analyzer
                            code_analyzer = get_analyzer("code_analyzer")
                            if code_analyzer:
                                print("Running code-based analysis...")
                                state.add_insight("Failed to select a strategy. Switching to code-based analysis.", analyzer="agent")
                                state = code_analyzer(state, task_description="Generate and execute Python code to solve this puzzle when no clear strategy is available")

                                if not state.solution:
                                    self._attempt_direct_solution(state)
                            else:
                                self._attempt_direct_solution(state)
                    else:
                        # If LLM fails, fall back to code analysis
                        from analyzers import get_analyzer
                        code_analyzer = get_analyzer("code_analyzer")
                        if code_analyzer:
                            print("Running code-based analysis...")
                            state.add_insight("Failed to select a strategy. Switching to code-based analysis.", analyzer="agent")
                            state = code_analyzer(state, task_description="Generate and execute Python code to solve this puzzle when no clear strategy is available")

                            if not state.solution:
                                self._attempt_direct_solution(state)
                        else:
                            self._attempt_direct_solution(state)
                    break

                # Extract and execute the strategy
                strategy = strategy_result.get("strategy", "")
                analyzer = strategy_result.get("analyzer", "")
                params = strategy_result.get("params", {})

                state.add_insight(f"Selected strategy: {strategy} using {analyzer}", analyzer="agent")

                # Check for user input again
                if user_interaction_available:
                    user_input = check_for_user_input()
                    if user_input:
                        process_user_input(user_input, context)

                # Execute the selected analyzer
                if analyzer:
                    print(f"Executing analyzer: {analyzer}")
                    from analyzers import get_analyzer
                    analyzer_func = get_analyzer(analyzer)
                    if analyzer_func:
                        # Update context for user interaction
                        if user_interaction_available:
                            context["current_task"] = f"Running analyzer: {analyzer}"
                            set_context(context)

                        # Store counts before running the analyzer
                        pre_insights_count = len(state.insights)
                        pre_transformations_count = len(state.transformations)

                        # Run the analyzer
                        state = analyzer_func(state, **params)

                        # Record the results of this analyzer run
                        analyzer_result = {
                            "analyzer": analyzer,
                            "params": params,
                            "new_insights_count": len(state.insights) - pre_insights_count,
                            "new_transformations_count": len(state.transformations) - pre_transformations_count,
                            "iteration": iteration
                        }
                        analyzer_results_history.append(analyzer_result)

                        # Let the LLM review the results and decide what to do next
                        review_result = self._review_analyzer_results(
                            state, 
                            analyzer, 
                            pre_insights_count, 
                            pre_transformations_count
                        )

                        # Log the review decision
                        state.add_insight(
                            f"LLM review of {analyzer} results: {review_result.get('reasoning', 'No reasoning provided')}",
                            analyzer="agent"
                        )

                        # If the LLM wants to run a specific analyzer next, do that immediately
                        if review_result.get("next_action") == "specific_analyzer":
                            specific_analyzer = review_result.get("analyzer")
                            specific_params = review_result.get("params", {})

                            if specific_analyzer:
                                analyzer_func = get_analyzer(specific_analyzer)
                                if analyzer_func:
                                    print(f"Running specific analyzer {specific_analyzer} as suggested by LLM review...")
                                    state.add_insight(f"LLM suggests running {specific_analyzer} based on review.", analyzer="agent")

                                    # Store counts before running the analyzer
                                    pre_insights_count = len(state.insights)
                                    pre_transformations_count = len(state.transformations)

                                    # Run the analyzer
                                    state = analyzer_func(state, **specific_params)

                                    # Record the results of this analyzer run
                                    analyzer_result = {
                                        "analyzer": specific_analyzer,
                                        "params": specific_params,
                                        "new_insights_count": len(state.insights) - pre_insights_count,
                                        "new_transformations_count": len(state.transformations) - pre_transformations_count,
                                        "iteration": iteration,
                                        "triggered_by_review": True
                                    }
                                    analyzer_results_history.append(analyzer_result)
                                else:
                                    state.add_insight(f"Analyzer '{specific_analyzer}' suggested by LLM review not found", analyzer="agent")
                        elif review_result.get("next_action") == "new_approach":
                            # LLM wants to try a completely different approach
                            state.add_insight("LLM suggests trying a new approach based on review.", analyzer="agent")

                            # Let the LLM decide what the new approach should be
                            new_approach_prompt = f"""
                            You are the orchestrator for a cryptographic puzzle solving system.

                            Based on your review of the {analyzer} results, you've decided to try a new approach.

                            Current puzzle state summary:
                            {state.get_summary()}

                            What specific new approach should we try? Options include:
                            1. Try code-based analysis
                            2. Try a specific analyzer with specific parameters
                            3. Attempt a direct solution
                            4. Combine insights from multiple analyzers

                            Available analyzers (ONLY use analyzers from this list):
                            - text_analyzer: For analyzing text patterns and encodings
                            - text_pattern_analyzer: For advanced pattern recognition in text
                            - binary_analyzer: For analyzing binary data
                            - image_analyzer: For analyzing images (steganography)
                            - cipher_analyzer: For detecting and solving classical ciphers
                            - encoding_analyzer: For detecting and decoding various encodings
                            - blockchain_analyzer: For analyzing crypto addresses and data
                            - crypto_analyzer: For analyzing cryptographic elements including hashes, keys, and signatures
                            - code_analyzer: For generating and executing Python code to solve the puzzle
                            - vision_analyzer: For analyzing images using computer vision techniques
                            - web_analyzer: For analyzing web-related content and URLs

                            IMPORTANT: Do NOT suggest analyzers that are not in the above list. If you need functionality that isn't covered by these analyzers, use code_analyzer to generate custom code instead.

                            Provide your decision in JSON format:
                            {{
                                "approach": "code_analysis" or "specific_analyzer" or "direct_solution" or "combine_insights",
                                "reasoning": "Your reasoning for this decision",
                                "analyzer": "Name of specific analyzer to run (if applicable)",
                                "params": {{}} // Parameters for the specific analyzer (if applicable)
                            }}
                            """

                            approach_result = self._send_to_llm(new_approach_prompt)

                            if approach_result:
                                try:
                                    # Extract JSON from the text
                                    json_part = approach_result
                                    if "```json" in approach_result:
                                        json_part = approach_result.split("```json")[1].split("```")[0].strip()
                                    elif "```" in approach_result:
                                        json_part = approach_result.split("```")[1].strip()

                                    decision = json.loads(json_part)
                                    approach = decision.get("approach", "code_analysis")
                                    reasoning = decision.get("reasoning", "Trying a new approach")

                                    state.add_insight(f"LLM new approach decision: {reasoning}", analyzer="agent")

                                    if approach == "code_analysis":
                                        # Try code-based analysis
                                        from analyzers import get_analyzer
                                        code_analyzer = get_analyzer("code_analyzer")
                                        if code_analyzer:
                                            print("Running code-based analysis as new approach...")
                                            state.add_insight("LLM suggests code-based analysis as new approach.", analyzer="agent")
                                            state = code_analyzer(state, task_description="Analyze this puzzle with a fresh perspective")
                                        else:
                                            self._attempt_direct_solution(state)
                                    elif approach == "specific_analyzer":
                                        # Run a specific analyzer
                                        specific_analyzer = decision.get("analyzer")
                                        specific_params = decision.get("params", {})

                                        if specific_analyzer:
                                            analyzer_func = get_analyzer(specific_analyzer)
                                            if analyzer_func:
                                                print(f"Running specific analyzer {specific_analyzer} as new approach...")
                                                state.add_insight(f"LLM suggests running {specific_analyzer} as new approach.", analyzer="agent")
                                                state = analyzer_func(state, **specific_params)
                                            else:
                                                state.add_insight(f"Analyzer '{specific_analyzer}' suggested as new approach not found", analyzer="agent")
                                    elif approach == "direct_solution":
                                        # Try direct solution
                                        print("Trying direct solution as new approach...")
                                        state.add_insight("LLM suggests attempting direct solution as new approach.", analyzer="agent")
                                        self._attempt_direct_solution(state)
                                    elif approach == "combine_insights":
                                        # Combine insights from multiple analyzers
                                        print("Combining insights from multiple analyzers as new approach...")
                                        state.add_insight("LLM suggests combining insights from multiple analyzers.", analyzer="agent")

                                        # Let the LLM combine insights
                                        combine_prompt = f"""
                                        You are the orchestrator for a cryptographic puzzle solving system.

                                        You need to combine insights from multiple analyzers to solve this puzzle.

                                        Current puzzle state summary:
                                        {state.get_summary()}

                                        All insights so far:
                                        {json.dumps(state.insights, indent=2)}

                                        All transformations so far:
                                        {json.dumps(state.transformations[-10:], indent=2)}

                                        Based on all this information, provide a combined analysis and potential solution.
                                        If you can determine the solution, include it after "SOLUTION:" on a new line.
                                        """

                                        combined_result = self._send_to_llm(combine_prompt)

                                        if combined_result:
                                            state.add_insight(f"Combined analysis: {combined_result[:500]}...", analyzer="agent")

                                            # Check if a solution was found
                                            if "SOLUTION:" in combined_result:
                                                solution = combined_result.split("SOLUTION:")[1].strip()
                                                state.set_solution(solution)
                                                print("Solution found through combined analysis!")
                                        else:
                                            self._attempt_direct_solution(state)
                                except Exception as e:
                                    print(f"Error processing new approach: {e}")
                                    self._attempt_direct_solution(state)
                            else:
                                self._attempt_direct_solution(state)
                    else:
                        state.add_insight(f"Analyzer '{analyzer}' not found", analyzer="agent")

                # Check if we've found a solution
                if state.solution:
                    print("Solution found!")
                    break

            except Exception as e:
                print(f"Error during analysis: {e}")
                state.add_insight(f"Error: {str(e)}", analyzer="agent")
                break

        return state

    def _assess_state(self, state: State) -> str:
        """
        Assess the current state of the puzzle.
        """
        if self.fallback_mode:
            return self._fallback_assessment(state)

        state_summary = state.get_summary()

        # Limit the number of transformations and insights to prevent context length issues
        max_items = 20  # Limit to the most recent items
        limited_transformations = state.transformations[-max_items:] if len(state.transformations) > max_items else state.transformations
        limited_insights = state.insights[-max_items:] if len(state.insights) > max_items else state.insights

        transformations = json.dumps(limited_transformations, indent=2)
        insights = json.dumps(limited_insights, indent=2)

        # Use a more conservative max_size for puzzle content to avoid context length issues
        puzzle_content = state.get_content_sample(max_size=2000, max_binary_size=500)

        # Include patterns in the assessment
        patterns = json.dumps([{
            "category": p.get("category", "Unknown"),
            "text": p.get("text", "")
        } for p in state.patterns], indent=2)

        try:
            result = self.state_assessment_chain.invoke({
                "state_summary": state_summary,
                "transformations": transformations,
                "insights": insights,
                "puzzle_content": puzzle_content,
                "patterns": patterns,
            })

            if hasattr(result, 'content'):
                response = result.content
            else:
                response = str(result)

            # Check if we got an error message about context length
            if response and response.startswith("ERROR: Context length exceeded"):
                print("Retrying with smaller content sample...")
                # Try again with an even smaller content sample
                puzzle_content = state.get_content_sample(max_size=1000, max_binary_size=200)

                try:
                    result = self.state_assessment_chain.invoke({
                        "state_summary": state_summary,
                        "transformations": transformations[:10],  # Use even fewer transformations
                        "insights": insights[:10],                # Use even fewer insights
                        "puzzle_content": puzzle_content,
                        "patterns": patterns,
                    })

                    if hasattr(result, 'content'):
                        return result.content
                    return str(result)
                except Exception as retry_e:
                    print(f"Error in retry attempt: {retry_e}")
                    return self._fallback_assessment(state)

            return response
        except Exception as e:
            print(f"Error assessing state: {e}")
            # Fall back to basic assessment if LLM fails
            return self._fallback_assessment(state)

    def _select_strategy(self, state: State, assessment: str, previous_results: str = None) -> Dict:
        """
        Select the next analysis strategy based on the current state.

        Args:
            state: Current puzzle state
            assessment: Assessment of the current state
            previous_results: Optional results from previous analyzer runs

        Returns:
            Dictionary with strategy information
        """
        if self.fallback_mode:
            return {"strategy": self._fallback_strategy(state), "analyzer": "text_analyzer", "params": {}}

        state_summary = state.get_summary()

        # Limit the number of transformations and insights to prevent context length issues
        max_items = 20  # Limit to the most recent items
        limited_transformations = state.transformations[-max_items:] if len(state.transformations) > max_items else state.transformations
        limited_insights = state.insights[-max_items:] if len(state.insights) > max_items else state.insights

        transformations = json.dumps(limited_transformations, indent=2)
        insights = json.dumps(limited_insights, indent=2)

        # Include patterns in the strategy selection
        patterns = json.dumps([{
            "category": p.get("category", "Unknown"),
            "text": p.get("text", "")
        } for p in state.patterns], indent=2)

        # Create context with previous_results always included
        context = {
            "state_summary": state_summary,
            "assessment": assessment,
            "transformations": transformations,
            "insights": insights,
            "patterns": patterns,
            "chat_history": self.chat_history,
            "previous_results": previous_results or "No previous results available"  # Always include this
        }

        try:
            result = self.strategy_chain.invoke(context)

            strategy_text = ""
            if hasattr(result, 'content'):
                strategy_text = result.content
            else:
                strategy_text = str(result)

            # Check if we got an error message about context length
            if strategy_text and strategy_text.startswith("ERROR: Context length exceeded"):
                print("Retrying strategy selection with smaller content...")
                # Try again with even fewer transformations and insights
                try:
                    result = self.strategy_chain.invoke({
                        "state_summary": state_summary,
                        "assessment": assessment[:500] if assessment else "",  # Truncate assessment
                        "transformations": json.dumps(limited_transformations[:5], indent=2),  # Use even fewer transformations
                        "insights": json.dumps(limited_insights[:5], indent=2),  # Use even fewer insights
                        "patterns": patterns,
                        "chat_history": [],  # Skip chat history to save tokens
                    })

                    if hasattr(result, 'content'):
                        strategy_text = result.content
                    else:
                        strategy_text = str(result)
                except Exception as retry_e:
                    print(f"Error in retry attempt: {retry_e}")
                    return {"strategy": "Fallback analysis after context length error", "analyzer": "text_analyzer", "params": {}}

            self.chat_history.append({"role": "assistant", "content": strategy_text})

            try:
                # Extract JSON from the text
                json_part = strategy_text
                if "```json" in strategy_text:
                    json_part = strategy_text.split("```json")[1].split("```")[0].strip()
                elif "```" in strategy_text:
                    json_part = strategy_text.split("```")[1].strip()

                return json.loads(json_part)
            except Exception as json_err:
                print(f"Error parsing strategy JSON: {json_err}")
                # Try to create a simple strategy if JSON parsing fails
                return {
                    "strategy": "Basic analysis",
                    "analyzer": "text_analyzer",
                    "params": {}
                }

        except Exception as e:
            print(f"Error selecting strategy: {e}")
            # Return a basic strategy if LLM fails
            return {"strategy": "Fallback analysis", "analyzer": "text_analyzer", "params": {}}

    def _review_analyzer_results(self, state: State, analyzer_name: str, previous_insights_count: int, previous_transformations_count: int) -> Dict:
        """
        Review the results of an analyzer run and decide what to do next.

        Args:
            state: Current puzzle state
            analyzer_name: Name of the analyzer that was just run
            previous_insights_count: Number of insights before the analyzer was run
            previous_transformations_count: Number of transformations before the analyzer was run

        Returns:
            Dictionary with review information and next steps
        """
        if self.fallback_mode:
            # In fallback mode, just continue with the next analyzer
            return {
                "continue": True,
                "next_action": "next_analyzer",
                "reasoning": "Continuing with next analyzer in fallback mode."
            }

        # Get new insights and transformations from this analyzer run
        new_insights = state.insights[previous_insights_count:]
        new_transformations = state.transformations[previous_transformations_count:]

        # If no new insights or transformations, not much to review
        if not new_insights and not new_transformations:
            return {
                "continue": True,
                "next_action": "next_analyzer",
                "reasoning": f"No new insights or transformations from {analyzer_name}. Moving to next analyzer."
            }

        # Prepare the review prompt
        state_summary = state.get_summary()

        # Format new insights and transformations for the LLM
        new_insights_text = json.dumps(new_insights, indent=2)
        new_transformations_text = json.dumps(new_transformations, indent=2)

        review_prompt = f"""
        You are the orchestrator for a cryptographic puzzle solving system.

        You need to review the results of the analyzer "{analyzer_name}" that was just run and decide what to do next.

        Current puzzle state summary:
        {state_summary}

        New insights from this analyzer run:
        {new_insights_text}

        New transformations from this analyzer run:
        {new_transformations_text}

        Based on these results, decide what to do next:
        1. Continue with the next analyzer
        2. Run a specific analyzer with specific parameters
        3. Try a different approach entirely

        Provide your decision in JSON format:
        {{
            "continue": true/false,
            "next_action": "next_analyzer" or "specific_analyzer" or "new_approach",
            "reasoning": "Your reasoning for this decision",
            "analyzer": "Name of specific analyzer to run (if applicable)",
            "params": {{}} // Parameters for the specific analyzer (if applicable)
        }}
        """

        try:
            result = self._send_to_llm(review_prompt)

            if not result:
                # If LLM fails, just continue with the next analyzer
                return {
                    "continue": True,
                    "next_action": "next_analyzer",
                    "reasoning": "LLM review failed. Continuing with next analyzer."
                }

            # Try to parse the JSON response
            try:
                # Extract JSON from the text
                json_part = result
                if "```json" in result:
                    json_part = result.split("```json")[1].split("```")[0].strip()
                elif "```" in result:
                    json_part = result.split("```")[1].strip()

                review_result = json.loads(json_part)
                return review_result
            except Exception as json_err:
                print(f"Error parsing review JSON: {json_err}")
                # If JSON parsing fails, just continue with the next analyzer
                return {
                    "continue": True,
                    "next_action": "next_analyzer",
                    "reasoning": "Error parsing LLM review. Continuing with next analyzer."
                }

        except Exception as e:
            print(f"Error in analyzer review: {e}")
            # If review fails, just continue with the next analyzer
            return {
                "continue": True,
                "next_action": "next_analyzer",
                "reasoning": f"Error in review: {str(e)}. Continuing with next analyzer."
            }

    def _attempt_direct_solution(self, state: State) -> None:
        """
        Attempt to directly solve the puzzle without further analysis.
        """
        if self.fallback_mode:
            state.add_insight(self._fallback_direct_solution(state), analyzer="agent")
            return

        state_summary = state.get_summary()

        # Use a more conservative max_size for puzzle content to avoid context length issues
        puzzle_content = state.get_content_sample(max_size=3000, max_binary_size=750)

        # Include patterns in the direct solution attempt
        patterns = json.dumps([{
            "category": p.get("category", "Unknown"),
            "text": p.get("text", "")
        } for p in state.patterns], indent=2)

        try:
            result = self.direct_solution_chain.invoke({
                "state_summary": state_summary,
                "puzzle_content": puzzle_content,
                "patterns": patterns,
            })

            solution_text = ""
            if hasattr(result, 'content'):
                solution_text = result.content
            else:
                solution_text = str(result)

            # Check if we got an error message about context length
            if solution_text and solution_text.startswith("ERROR: Context length exceeded"):
                print("Retrying direct solution with smaller content...")
                # Try again with an even smaller content sample
                puzzle_content = state.get_content_sample(max_size=1000, max_binary_size=200)

                try:
                    result = self.direct_solution_chain.invoke({
                        "state_summary": state_summary,
                        "puzzle_content": puzzle_content,
                        "patterns": patterns,
                    })

                    if hasattr(result, 'content'):
                        solution_text = result.content
                    else:
                        solution_text = str(result)
                except Exception as retry_e:
                    print(f"Error in retry attempt: {retry_e}")
                    solution_text = "Failed to attempt direct solution due to context length limitations."

            state.add_insight(f"Direct solution attempt: {solution_text}", analyzer="agent")

            # Try to extract a solution
            if "SOLUTION:" in solution_text:
                solution = solution_text.split("SOLUTION:")[1].strip()
                state.set_solution(solution)

            self.chat_history.append({"role": "assistant", "content": solution_text})

        except Exception as e:
            print(f"Error in direct solution attempt: {e}")
            state.add_insight("Failed to attempt direct solution due to an error.", analyzer="agent")
