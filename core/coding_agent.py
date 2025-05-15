"""
Coding agent adapter for Crypto Hunter.
Provides an interface to the core/code_agent.py functionality.
"""

import os
import sys
import logging
import importlib
import time
from typing import Dict, List, Any, Optional, Tuple, Union

from core.state import State
from core.agent import CryptoAgent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import the actual CodeAgent - we want to use the implementation from code_agent.py
try:
    from core.code_agent import CodeAgent, DynamicToolRegistry, SafeExecutionEnvironment
    CODEAGENT_AVAILABLE = True
except ImportError as e:
    logger.error(f"Error importing CodeAgent: {e}")
    CODEAGENT_AVAILABLE = False

class CodingAgent:
    """
    Adapter class to integrate the CodeAgent functionality with the main application.
    """

    def __init__(self, provider: str = "openai", api_key: Optional[str] = None, 
                 model: Optional[str] = None, verbose: bool = False):
        """
        Initialize the coding agent adapter.

        Args:
            provider: LLM provider to use (anthropic, openai, etc.)
            api_key: Optional API key (if not provided, will use environment variables)
            model: Optional model name
            verbose: Whether to output verbose logs
        """
        self.provider = provider
        self.api_key = api_key
        self.model = model
        self.verbose = verbose
        self.fallback_mode = not CODEAGENT_AVAILABLE

        # Initialize the crypto agent for LLM interactions
        try:
            self.llm_agent = self._initialize_llm_agent()
        except Exception as e:
            logger.error(f"Error initializing LLM agent: {e}")
            self.llm_agent = None
            self.fallback_mode = True

        # Initialize the code agent if available
        if CODEAGENT_AVAILABLE and not self.fallback_mode:
            try:
                self.code_agent = CodeAgent(llm_agent=self.llm_agent)
                logger.info("CodeAgent initialized successfully")
            except Exception as e:
                logger.error(f"Error initializing CodeAgent: {e}")
                self.code_agent = None
                self.fallback_mode = True
        else:
            self.code_agent = None
            if not CODEAGENT_AVAILABLE:
                logger.warning("CodeAgent functionality not available")

    def _initialize_llm_agent(self) -> Optional[CryptoAgent]:
        """
        Initialize the LLM agent with provider fallback.

        Returns:
            Initialized CryptoAgent or None if initialization fails
        """
        # Try the specified provider first
        try:
            agent = CryptoAgent(provider=self.provider, api_key=self.api_key, 
                               model=self.model, verbose=self.verbose)

            # Check if the agent is in fallback mode
            if not agent.fallback_mode:
                logger.info(f"Successfully initialized {self.provider} agent")
                return agent
            else:
                logger.warning(f"{self.provider} in fallback mode, trying alternatives")
        except Exception as e:
            logger.warning(f"Error initializing {self.provider} agent: {e}")

        # Try alternative providers
        providers_to_try = ["openai", "anthropic"]
        providers_to_try.remove(self.provider) if self.provider in providers_to_try else None

        for alt_provider in providers_to_try:
            if is_api_key_set(f"{alt_provider.upper()}_API_KEY"):
                try:
                    logger.info(f"Trying {alt_provider} as alternative provider")
                    agent = CryptoAgent(provider=alt_provider, verbose=self.verbose)

                    if not agent.fallback_mode:
                        logger.info(f"Successfully initialized {alt_provider} agent as alternative")
                        return agent
                except Exception as e:
                    logger.warning(f"Error initializing {alt_provider} alternative: {e}")

        logger.warning("All LLM providers failed, using fallback mode")
        return None

    def analyze(self, state: State, max_iterations: int = 5) -> State:
        """
        Analyze the puzzle using code generation capabilities.

        Args:
            state: Current puzzle state
            max_iterations: Maximum number of analysis iterations

        Returns:
            Updated state after analysis
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
            logger.warning("User interaction module not available. Running without interactive capabilities.")

        # Setup user interaction if available
        if user_interaction_available:
            # Start listening for user input
            start_user_interaction()

            # Register callback for handling questions
            def handle_question(question: str, context: dict) -> str:
                """Handle user questions during code-based analysis."""
                try:
                    # Generate a response using the LLM
                    if self.llm_agent:
                        prompt = f"""
                        The user has asked the following question during code-based puzzle analysis:
                        "{question}"

                        Current puzzle state:
                        - Analyzing file: {context.get('current_file', 'Unknown')}
                        - Current task: {context.get('current_task', 'Unknown')}
                        - Current insights: {len(context.get('insights', []))} insights gathered
                        - Solution found: {'Yes' if context.get('solution') else 'No'}

                        Please provide a helpful response to the user's question.
                        """

                        response = self.llm_agent.send_message(prompt)
                        return response or "I'm sorry, I couldn't generate a response at this time."
                    else:
                        return "I'm sorry, the LLM agent is not available to answer questions at this time."
                except Exception as e:
                    return f"Error processing your question: {str(e)}"

            register_callback("question_callback", handle_question)

        # Check if we're in fallback mode
        if self.fallback_mode:
            logger.info("Running in fallback mode without LLM assistance.")
            return self._run_fallback_analysis(state)

        # Start analysis using the CodeAgent
        logger.info("Starting code-based analysis")

        try:
            # First, integrate with state to add code analysis tools
            logger.info("Integrating code analysis tools with state")
            state = self.code_agent.integrate_with_state(state, analyze_puzzle=True)

            # Update context for user interaction
            if user_interaction_available:
                context = {
                    "current_file": state.puzzle_file,
                    "current_task": "Integrating code analysis tools",
                    "insights": state.insights,
                    "solution": state.solution
                }
                set_context(context)

            # Check for user input
            if user_interaction_available:
                user_input = check_for_user_input()
                if user_input:
                    process_user_input(user_input, context)

            # Run analysis for each file in the puzzle
            if state.puzzle_file:
                logger.info(f"Analyzing main puzzle file: {state.puzzle_file}")

                # Update context for user interaction
                if user_interaction_available:
                    context["current_file"] = state.puzzle_file
                    context["current_task"] = "Analyzing main puzzle file"
                    set_context(context)

                state = self._analyze_file(state, state.puzzle_file)

                # Check for user input after file analysis
                if user_interaction_available:
                    user_input = check_for_user_input()
                    if user_input:
                        # Update context with latest insights
                        context["insights"] = state.insights
                        context["solution"] = state.solution
                        process_user_input(user_input, context)

            # Check related files
            for filename, file_info in state.related_files.items():
                logger.info(f"Analyzing related file: {filename}")

                # Update context for user interaction
                if user_interaction_available:
                    context["current_file"] = filename
                    context["current_task"] = "Analyzing related file"
                    set_context(context)

                # Check for user input before analyzing this file
                if user_interaction_available:
                    user_input = check_for_user_input()
                    if user_input:
                        process_user_input(user_input, context)

                # Create a temporary state for this file
                file_state = State(puzzle_file=filename)

                # Set content based on file type
                binary_content = file_info.get("content")
                if binary_content:
                    if self._is_text_file(filename, binary_content):
                        try:
                            text_content = binary_content.decode('utf-8', errors='replace')
                            file_state.set_puzzle_text(text_content)
                        except:
                            file_state.set_binary_data(binary_content)
                    else:
                        file_state.set_binary_data(binary_content)

                # Analyze this file
                file_state = self._analyze_file(file_state, filename)

                # Merge insights and transformations back to main state
                state.merge_related_state(file_state)

                # Check for user input after file analysis
                if user_interaction_available:
                    user_input = check_for_user_input()
                    if user_input:
                        # Update context with latest insights
                        context["insights"] = state.insights
                        context["solution"] = state.solution
                        process_user_input(user_input, context)

            # After individual file analysis, try to get a holistic view
            if len(state.related_files) > 0:
                logger.info("Performing combined analysis of all files")

                # Update context for user interaction
                if user_interaction_available:
                    context["current_file"] = "all files"
                    context["current_task"] = "Performing combined analysis"
                    set_context(context)

                # Check for user input before combined analysis
                if user_interaction_available:
                    user_input = check_for_user_input()
                    if user_input:
                        process_user_input(user_input, context)

                state = self._analyze_combined_files(state)

                # Check for user input after combined analysis
                if user_interaction_available:
                    user_input = check_for_user_input()
                    if user_input:
                        # Update context with latest insights
                        context["insights"] = state.insights
                        context["solution"] = state.solution
                        process_user_input(user_input, context)

            # If no solution found yet, attempt direct solution
            if not state.solution:
                logger.info("Attempting direct solution")

                # Update context for user interaction
                if user_interaction_available:
                    context["current_task"] = "Attempting direct solution"
                    set_context(context)

                # Check for user input before direct solution attempt
                if user_interaction_available:
                    user_input = check_for_user_input()
                    if user_input:
                        process_user_input(user_input, context)

                state = self._attempt_direct_solution(state)

            return state

        except Exception as e:
            logger.error(f"Error in code-based analysis: {e}")
            state.add_insight(f"Error in code-based analysis: {e}", analyzer="coding_agent")

            # Fall back to standard analysis
            return self._run_fallback_analysis(state)

    def _analyze_file(self, state: State, filename: str) -> State:
        """
        Analyze a single file using code generation.

        Args:
            state: Current state containing the file
            filename: Name of the file to analyze

        Returns:
            Updated state
        """
        # Skip if no CodeAgent available
        if not self.code_agent:
            return state

        # Add insight about starting analysis
        state.add_insight(f"Starting code-based analysis of {filename}", analyzer="coding_agent")

        # Generate task description based on file type
        file_ext = os.path.splitext(filename)[1].lower()

        if file_ext in ['.txt', '.md', '.log', '.csv', '.json', '.xml', '.html']:
            task = f"Analyze this text file ({filename}) to identify any encoded messages, ciphers, or hidden data"
        elif file_ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
            task = f"Analyze this image file ({filename}) for steganography or hidden visual patterns"
        elif file_ext in ['.bin', '.dat', '.exe', '.dll']:
            task = f"Analyze this binary file ({filename}) for hidden data or unusual patterns"
        else:
            task = f"Analyze this file ({filename}) for any cryptographic puzzles or hidden information"

        # Generate analysis code
        try:
            analysis_code = self.code_agent.generate_code(task, state)

            # Prepare inputs for code execution
            inputs = {
                "filename": filename,
                "text": state.puzzle_text if state.puzzle_text else "",
                "binary_data": state.binary_data if state.binary_data else b"",
                "state": state
            }

            # Execute the analysis code
            result = self.code_agent.execute_code(analysis_code, inputs)

            # Process execution results
            if result.get('success'):
                # Extract analysis results
                output = result.get('result', {})

                # Add insights from the analysis
                for key, value in output.items():
                    if key not in ['success', 'error'] and not key.startswith('_'):
                        state.add_insight(f"Code analysis of {filename} - {key}: {value}", 
                                         analyzer="coding_agent")

                # Check if solution was found
                if 'solution' in output:
                    solution = output['solution']
                    state.add_insight(f"Potential solution found in {filename}: {solution}", 
                                     analyzer="coding_agent")

                    # Attempt to verify the solution
                    if self._verify_solution(state, solution):
                        state.set_solution(solution)
            else:
                # Log execution error
                error = result.get('error', 'Unknown error')
                state.add_insight(f"Code analysis of {filename} failed: {error}", 
                                 analyzer="coding_agent")

        except Exception as e:
            logger.error(f"Error analyzing {filename}: {e}")
            state.add_insight(f"Error analyzing {filename}: {e}", analyzer="coding_agent")

        return state

    def _analyze_combined_files(self, state: State) -> State:
        """
        Analyze all files together for cross-file patterns.

        Args:
            state: Current state with multiple files

        Returns:
            Updated state
        """
        # Skip if no CodeAgent available
        if not self.code_agent:
            return state

        # Only proceed if we have multiple files
        if len(state.related_files) < 2:
            return state

        # Generate a task for combined analysis
        filenames = list(state.related_files.keys())
        task = f"Analyze these {len(filenames)} files together to find connections or patterns between them: {', '.join(filenames[:5])}"
        if len(filenames) > 5:
            task += f" and {len(filenames) - 5} more"

        # Generate combined analysis code
        try:
            analysis_code = self.code_agent.generate_code(task, state)

            # Prepare inputs for code execution
            inputs = {
                "filenames": filenames,
                "state": state,
                "files": {name: info.get("content", b"") for name, info in state.related_files.items()}
            }

            # Execute the analysis code
            result = self.code_agent.execute_code(analysis_code, inputs)

            # Process execution results
            if result.get('success'):
                # Extract analysis results
                output = result.get('result', {})

                # Add insights from the analysis
                for key, value in output.items():
                    if key not in ['success', 'error'] and not key.startswith('_'):
                        state.add_insight(f"Combined file analysis - {key}: {value}", 
                                         analyzer="coding_agent")

                # Check if solution was found
                if 'solution' in output:
                    solution = output['solution']
                    state.add_insight(f"Potential solution found in combined analysis: {solution}", 
                                     analyzer="coding_agent")

                    # Attempt to verify the solution
                    if self._verify_solution(state, solution):
                        state.set_solution(solution)
            else:
                # Log execution error
                error = result.get('error', 'Unknown error')
                state.add_insight(f"Combined file analysis failed: {error}", 
                                 analyzer="coding_agent")

        except Exception as e:
            logger.error(f"Error in combined file analysis: {e}")
            state.add_insight(f"Error in combined file analysis: {e}", analyzer="coding_agent")

        return state

    def _attempt_direct_solution(self, state: State) -> State:
        """
        Make a final attempt to directly solve the puzzle.

        Args:
            state: Current state after other analyses

        Returns:
            Updated state
        """
        # Skip if no CodeAgent available
        if not self.code_agent:
            return state

        # Skip if we already have a solution
        if state.solution:
            return state

        # Generate a task for direct solution attempt
        task = "Review all puzzle data and insights to determine the final solution"

        try:
            # Generate solution code
            solution_code = self.code_agent.generate_code(task, state)

            # Execute the solution code
            result = self.code_agent.execute_code(solution_code, {"state": state})

            # Check if execution was successful
            if result.get('success'):
                output = result.get('result', {})

                # Check if solution was found
                if 'solution' in output:
                    solution = output['solution']
                    state.add_insight(f"Direct solution attempt: {solution}", 
                                     analyzer="coding_agent")

                    # Attempt to verify the solution
                    if self._verify_solution(state, solution):
                        state.set_solution(solution)
            else:
                # Log execution error
                error = result.get('error', 'Unknown error')
                state.add_insight(f"Direct solution attempt failed: {error}", 
                                 analyzer="coding_agent")

        except Exception as e:
            logger.error(f"Error in direct solution attempt: {e}")
            state.add_insight(f"Error in direct solution attempt: {e}", analyzer="coding_agent")

        return state

    def _run_fallback_analysis(self, state: State) -> State:
        """
        Run fallback analysis when CodeAgent is not available.

        Args:
            state: Current puzzle state

        Returns:
            Updated state
        """
        # Import and run all available analyzers
        try:
            from analyzers import get_all_analyzers
            analyzers = get_all_analyzers()

            # Add insight about fallback mode
            state.add_insight(
                "Running in fallback mode without LLM assistance.",
                analyzer="coding_agent"
            )

            # Run available analyzers
            for name, analyzer_func in analyzers.items():
                try:
                    logger.info(f"Running {name}...")
                    state = analyzer_func(state)
                except Exception as e:
                    logger.error(f"Error in {name}: {e}")
                    state.add_insight(f"Error in {name}: {e}", analyzer="coding_agent")

        except Exception as e:
            logger.error(f"Error in fallback analysis: {e}")
            state.add_insight(f"Error in fallback analysis: {e}", analyzer="coding_agent")

        return state

    def _verify_solution(self, state: State, solution: str) -> bool:
        """
        Attempt to verify a potential solution.

        Args:
            state: Current puzzle state
            solution: Potential solution to verify

        Returns:
            True if the solution is verified, False otherwise
        """
        # Skip if no LLM agent available
        if not self.llm_agent:
            # In fallback mode, accept any potential solution
            return True

        # Ask the LLM to verify the solution
        prompt = f"""
        Verify if this is a valid solution to the puzzle:

        Potential solution: {solution}

        Puzzle information:
        {state.get_summary()}

        Is this solution valid and complete? Answer YES or NO, followed by a brief explanation.
        """

        try:
            response = self.llm_agent._send_to_llm(prompt)

            # Check if the response indicates verification
            if response and "YES" in response.upper():
                logger.info(f"Solution verified: {solution}")
                return True
            else:
                logger.info(f"Solution not verified: {solution}")
                return False
        except:
            # If verification fails, assume it might be correct
            logger.warning("Unable to verify solution, accepting provisionally")
            return True

    def generate_code(self, task_description: str, state: State) -> str:
        """
        Generate code for a given task description.

        Args:
            task_description: Description of the task to generate code for
            state: Current puzzle state

        Returns:
            Generated code as a string
        """
        # Check if code_agent is available
        if self.code_agent:
            try:
                return self.code_agent.generate_code(task_description, state)
            except Exception as e:
                logger.error(f"Error in code generation: {e}")
                # Fall back to a simple template if code generation fails

        # Fallback code template
        return f"""
# Task: {task_description}
# This is a fallback template as the code generation failed

def analyze(state, **kwargs):
    # Extract available data
    text = kwargs.get('text', '')
    binary_data = kwargs.get('binary_data', b'')
    filename = kwargs.get('filename', '')

    # Basic analysis results
    results = {{
        'analyzed': True,
        'message': 'Basic analysis completed (fallback mode)',
        'findings': []
    }}

    # Return results
    return results
"""

    def execute_code(self, code: str, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the generated code with the given inputs.

        Args:
            code: Code to execute
            inputs: Dictionary of inputs for the code

        Returns:
            Dictionary with execution results
        """
        # Check if code_agent is available
        if self.code_agent:
            try:
                return self.code_agent.execute_code(code, inputs)
            except Exception as e:
                logger.error(f"Error in code execution: {e}")
                # Return error information
                return {
                    'success': False,
                    'error': str(e)
                }

        # Fallback execution (very limited)
        try:
            # Create a safe namespace
            namespace = {
                'state': inputs.get('state'),
                'text': inputs.get('text', ''),
                'binary_data': inputs.get('binary_data', b''),
                'filename': inputs.get('filename', ''),
                'filenames': inputs.get('filenames', []),
                'files': inputs.get('files', {})
            }

            # Execute the code in a restricted environment
            exec_globals = {'__builtins__': __builtins__}
            exec(code, exec_globals, namespace)

            # Call the analyze function if it exists
            if 'analyze' in namespace:
                result = namespace['analyze'](inputs.get('state'), **inputs)
                return {
                    'success': True,
                    'result': result
                }
            else:
                return {
                    'success': False,
                    'error': 'No analyze function found in generated code'
                }
        except Exception as e:
            logger.error(f"Error in fallback execution: {e}")
            return {
                'success': False,
                'error': f"Fallback execution failed: {str(e)}"
            }

    def _is_text_file(self, filename: str, content: bytes) -> bool:
        """
        Determine if a file is likely a text file.

        Args:
            filename: Name of the file
            content: Binary content of the file

        Returns:
            True if likely a text file, False otherwise
        """
        # Check file extension
        ext = os.path.splitext(filename)[1].lower()
        text_extensions = ['.txt', '.md', '.csv', '.json', '.xml', '.html', '.log', '.py', '.js', '.c', '.cpp', '.h']

        if ext in text_extensions:
            return True

        # Check content by sampling bytes
        if not content:
            return False

        # Sample the first 1000 bytes
        sample = content[:1000]

        # Count printable ASCII and control characters
        printable = sum(32 <= b <= 126 or b in (9, 10, 13) for b in sample)

        # If >80% of bytes are printable or common control chars, likely text
        return printable / len(sample) > 0.8 if sample else False

def is_api_key_set(key_name: str) -> bool:
    """
    Check if an API key is set in the environment.

    Args:
        key_name: Name of the environment variable for the API key

    Returns:
        True if the key is set, False otherwise
    """
    return bool(os.environ.get(key_name))
