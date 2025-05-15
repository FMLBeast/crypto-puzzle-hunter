"""
Crypto Hunter Agent Module
Handles the interaction with LLM providers and coordinates the analysis.
"""
import os
import json
import textwrap
from typing import List, Dict, Optional, Any, Union
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnablePassthrough, RunnableSequence
from langchain_community.chat_models import ChatOpenAI, ChatAnthropic
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
        self.provider = provider
        self.api_key = api_key
        self.model = model
        self.verbose = verbose
        self.chat_history = []
        self.fallback_mode = False

        # Check environment variables for API keys
        if not self.api_key:
            if provider == "anthropic":
                self.api_key = os.environ.get("ANTHROPIC_API_KEY")
            elif provider == "openai":
                self.api_key = os.environ.get("OPENAI_API_KEY")
            elif provider == "huggingface":
                self.api_key = os.environ.get("HUGGINGFACE_API_KEY")

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

    def _test_api_access(self):
        """Test if the API key is valid."""
        if not self.api_key:
            return False

        try:
            if self.provider == "anthropic":
                # Test Anthropic API
                try:
                    from anthropic import Anthropic
                    client = Anthropic(api_key=self.api_key)
                    response = client.messages.create(
                        model="claude-3-haiku-20240307",
                        max_tokens=10,
                        messages=[{"role": "user", "content": "Hello"}]
                    )
                    return True
                except Exception as e:
                    # We're removing credit balance checks as per requirements
                    # Other errors might indicate network issues, etc.
                    print(f"Anthropic API test error: {e}")
                    return True

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
                    return True
                except Exception as e:
                    # We're removing credit balance checks as per requirements
                    print(f"OpenAI API test error: {e}")
                    return True

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
                return ChatAnthropic(
                    model_name=self.model or "claude-3-opus-20240229",
                    anthropic_api_key=self.api_key,
                    temperature=0.2
                )

            elif self.provider == "openai":
                return ChatOpenAI(
                    model_name=self.model or "gpt-4o",
                    api_key=self.api_key,
                    temperature=0.2
                )

            elif self.provider == "huggingface":
                # Use Hugging Face model (usually free for those with access)
                return HuggingFaceEndpoint(
                    repo_id=self.model or "mistralai/Mistral-7B-Instruct-v0.2",
                    huggingfacehub_api_token=self.api_key,
                    temperature=0.2
                )

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
            print(f"Error sending to LLM: {e}")
            return None

    def analyze(self, state: State, max_iterations: int = 5) -> State:
        """
        Analyze the puzzle and attempt to solve it.

        Args:
            state: The current puzzle state
            max_iterations: Maximum number of analysis iterations

        Returns:
            Updated puzzle state
        """
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
            from analyzers import get_all_analyzers
            analyzers = get_all_analyzers()

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

            return state

        # Regular mode with LLM
        iteration = 0
        previous_insights_count = 0

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
                    print("No new insights gained in this iteration. Trying direct solution...")
                    self._attempt_direct_solution(state)

                previous_insights_count = len(state.insights)

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

                # Select a strategy
                print("Selecting strategy...")
                strategy_result = self._select_strategy(state, assessment)
                if not strategy_result:
                    print("Failed to select a strategy. Trying direct solution...")
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

                        state = analyzer_func(state, **params)
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
        transformations = json.dumps(state.transformations, indent=2)
        insights = json.dumps(state.insights, indent=2)
        puzzle_content = state.get_content_sample(max_size=4000)

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
                return result.content
            return str(result)
        except Exception as e:
            print(f"Error assessing state: {e}")
            # Fall back to basic assessment if LLM fails
            return self._fallback_assessment(state)

    def _select_strategy(self, state: State, assessment: str) -> Dict:
        """
        Select the next analysis strategy based on the current state.
        """
        if self.fallback_mode:
            return {"strategy": self._fallback_strategy(state), "analyzer": "text_analyzer", "params": {}}

        state_summary = state.get_summary()
        transformations = json.dumps(state.transformations, indent=2)
        insights = json.dumps(state.insights, indent=2)

        # Include patterns in the strategy selection
        patterns = json.dumps([{
            "category": p.get("category", "Unknown"),
            "text": p.get("text", "")
        } for p in state.patterns], indent=2)

        try:
            result = self.strategy_chain.invoke({
                "state_summary": state_summary,
                "assessment": assessment,
                "transformations": transformations,
                "insights": insights,
                "patterns": patterns,
                "chat_history": self.chat_history,
            })

            strategy_text = ""
            if hasattr(result, 'content'):
                strategy_text = result.content
            else:
                strategy_text = str(result)

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

    def _attempt_direct_solution(self, state: State) -> None:
        """
        Attempt to directly solve the puzzle without further analysis.
        """
        if self.fallback_mode:
            state.add_insight(self._fallback_direct_solution(state), analyzer="agent")
            return

        state_summary = state.get_summary()
        puzzle_content = state.get_content_sample(max_size=8000)

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

            state.add_insight(f"Direct solution attempt: {solution_text}", analyzer="agent")

            # Try to extract a solution
            if "SOLUTION:" in solution_text:
                solution = solution_text.split("SOLUTION:")[1].strip()
                state.set_solution(solution)

            self.chat_history.append({"role": "assistant", "content": solution_text})

        except Exception as e:
            print(f"Error in direct solution attempt: {e}")
            state.add_insight("Failed to attempt direct solution due to an error.", analyzer="agent")
