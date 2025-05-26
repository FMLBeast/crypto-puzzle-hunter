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
from core.prompts import (STATE_ASSESSMENT_PROMPT, STRATEGY_SELECTION_PROMPT,
                         DIRECT_SOLUTION_PROMPT, FALLBACK_STATE_ASSESSMENT_TEXT,
                         FALLBACK_STRATEGY_SELECTION_TEXT, FALLBACK_DIRECT_SOLUTION_TEXT)
from dotenv import load_dotenv
from core.logger import solution_logger
from core.user_interaction import (start_user_interaction, check_for_user_input,
                                 process_user_input, register_callback, set_context)
from analyzers import get_all_analyzers, get_analyzer, get_compatible_analyzers

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# Load environment variables
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

        # Initialize components
        if self._should_try_llm_initialization():
            try:
                self.llm = self._initialize_llm()
                if self.llm:
                    self.llm_available = True
                    self._create_chains()
                    if self.verbose:
                        print(f"Successfully initialized {provider} LLM.")
                else:
                    if self.verbose:
                        print(f"Failed to initialize {provider} LLM - using fallback mode.")
            except Exception as e:
                if self.verbose:
                    print(f"LLM initialization failed: {e} - using fallback mode.")
                self.llm = None
                self.llm_available = False
        else:
            if self.verbose:
                print("No API keys available - using fallback mode.")

        # Set up real-time feedback
        solution_logger.register_llm_feedback_callback(self._handle_realtime_finding)

    def _should_try_llm_initialization(self) -> bool:
        """
        Determine if we should even attempt to initialize LLM-dependent components.
        This prevents unnecessary API calls when it's clear no API access is available.

        Returns:
            True if we should try to initialize LLM components, False otherwise
        """
        # Check if API keys are available
        api_keys_available = {
            'anthropic': self.api_key or os.getenv('ANTHROPIC_API_KEY'),
            'openai': self.api_key or os.getenv('OPENAI_API_KEY'),
            'huggingface': self.api_key or os.getenv('HUGGINGFACE_API_KEY')
        }

        # Check if the specified provider has an API key
        if self.provider in api_keys_available:
            return bool(api_keys_available[self.provider])

        # For 'local' provider, always try (no API key needed)
        if self.provider == 'local':
            return True

        # If no specific provider or unknown provider, check if any API key is available
        return any(api_keys_available.values())

    def _test_api_access(self):
        """Test if the API key is valid."""
        if not self.llm:
            return False

        try:
            if self.provider == 'anthropic' and Anthropic:
                client = Anthropic(api_key=self.api_key or os.getenv('ANTHROPIC_API_KEY'))
                # Test with a minimal request
                response = client.messages.create(
                    model=self.model or "claude-3-5-sonnet-20240620",
                    max_tokens=10,
                    messages=[{"role": "user", "content": "Test"}]
                )
                return True
            elif self.provider == 'openai' and OpenAI:
                client = OpenAI(api_key=self.api_key or os.getenv('OPENAI_API_KEY'))
                # Test with a minimal request
                response = client.chat.completions.create(
                    model=self.model or "gpt-4o-2024-05-13",
                    max_tokens=10,
                    messages=[{"role": "user", "content": "Test"}]
                )
                return True
            else:
                # For other providers, assume it's working if we got this far
                return True
        except Exception as e:
            if self.verbose:
                print(f"API access test failed: {e}")
            return False

    def _initialize_llm(self):
        """
        Initialize the LLM based on the provider.
        Returns the LLM or None if initialization fails.
        """
        try:
            if self.provider == 'anthropic':
                if not Anthropic:
                    raise ImportError("anthropic package not available")

                api_key = self.api_key or os.getenv('ANTHROPIC_API_KEY')
                if not api_key:
                    raise ValueError("No Anthropic API key found")

                # Test API access first
                client = Anthropic(api_key=api_key)
                test_response = client.messages.create(
                    model=self.model or "claude-3-5-sonnet-20240620",
                    max_tokens=10,
                    messages=[{"role": "user", "content": "Test"}]
                )
                print("Successfully connected to Anthropic API.")

                return ChatAnthropic(
                    anthropic_api_key=api_key,
                    model_name=self.model or "claude-3-5-sonnet-20240620",
                    temperature=0.3,
                    max_tokens=4000
                )

            elif self.provider == 'openai':
                if not OpenAI:
                    raise ImportError("openai package not available")

                api_key = self.api_key or os.getenv('OPENAI_API_KEY')
                if not api_key:
                    raise ValueError("No OpenAI API key found")

                # Test API access first
                client = OpenAI(api_key=api_key)
                test_response = client.chat.completions.create(
                    model=self.model or "gpt-4o-2024-05-13",
                    max_tokens=10,
                    messages=[{"role": "user", "content": "Test"}]
                )
                print("Successfully connected to OpenAI API.")
                print(f"Initializing OpenAI LLM with API key: {api_key[:5]}...{api_key[-5:]}")

                return ChatOpenAI(
                    openai_api_key=api_key,
                    model_name=self.model or "gpt-4o-2024-05-13",
                    temperature=0.3,
                    max_tokens=4000
                )

            elif self.provider == 'huggingface':
                api_key = self.api_key or os.getenv('HUGGINGFACE_API_KEY')
                if not api_key:
                    raise ValueError("No Hugging Face API key found")

                return HuggingFaceEndpoint(
                    endpoint_url=self.model or "https://api-inference.huggingface.co/models/microsoft/DialoGPT-medium",
                    huggingfacehub_api_token=api_key,
                    temperature=0.3,
                    max_new_tokens=4000
                )

            elif self.provider == 'local':
                # For local models, we'd need to implement a local LLM interface
                # For now, return None to use fallback mode
                return None

            else:
                raise ValueError(f"Unsupported LLM provider: {self.provider}")

        except Exception as e:
            if self.verbose:
                print(f"Failed to initialize {self.provider} LLM: {e}")
            return None

    def _create_chains(self):
        """Create LLM chains if LLM is available."""
        if not self.llm:
            return

        try:
            self._create_state_assessment_chain()
            self._create_strategy_chain()
            self._create_direct_solution_chain()
        except Exception as e:
            if self.verbose:
                print(f"Failed to create LLM chains: {e}")

    def _create_state_assessment_chain(self):
        """Create the chain for assessing the puzzle state."""
        if not self.llm:
            return
        try:
            prompt = PromptTemplate.from_template(STATE_ASSESSMENT_PROMPT)
            self.state_assessment_chain = prompt | self.llm
        except Exception as e:
            if self.verbose:
                print(f"Failed to create state assessment chain: {e}")

    def _create_strategy_chain(self):
        """Create the chain for selecting analysis strategies."""
        if not self.llm:
            return
        try:
            prompt = PromptTemplate.from_template(STRATEGY_SELECTION_PROMPT)
            self.strategy_chain = prompt | self.llm
        except Exception as e:
            if self.verbose:
                print(f"Failed to create strategy chain: {e}")

    def _create_direct_solution_chain(self):
        """Create the chain for attempting direct solutions."""
        if not self.llm:
            return
        try:
            prompt = PromptTemplate.from_template(DIRECT_SOLUTION_PROMPT)
            self.direct_solution_chain = prompt | self.llm
        except Exception as e:
            if self.verbose:
                print(f"Failed to create direct solution chain: {e}")

    def _fallback_assessment(self, state):
        """
        Provide a basic assessment of the puzzle when in fallback mode.
        """
        file_type = "binary" if state.is_binary() else "text"
        file_size = len(state.binary_data) if state.binary_data else len(state.puzzle_text or "")
        return FALLBACK_STATE_ASSESSMENT_TEXT.format(file_type=file_type, file_size=file_size)

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
        finding = {
            'type': finding_type,
            'analyzer': analyzer,
            'content': content,
            'timestamp': time.time()
        }
        self.realtime_findings.append(finding)

        # If we have too many findings, send them to the LLM
        if len(self.realtime_findings) >= 5:
            self._send_realtime_findings_to_llm()

    def _send_realtime_findings_to_llm(self) -> None:
        """
        Send real-time findings to the LLM.
        """
        if not self.llm_available or not self.realtime_findings:
            return

        try:
            findings_text = "\n".join([
                f"[{finding['analyzer']}] {finding['type']}: {finding['content']}"
                for finding in self.realtime_findings
            ])

            prompt = f"""
            Real-time analysis findings from puzzle solving:
            
            {findings_text}
            
            Please provide guidance on:
            1. Which findings are most significant
            2. What patterns you notice
            3. Next steps to pursue
            4. Any connections between findings
            
            Keep response concise and actionable.
            """

            self._send_to_llm_without_response(prompt)

        except Exception as e:
            if self.verbose:
                print(f"Failed to send real-time findings to LLM: {e}")
        finally:
            # Clear the findings regardless of success/failure
            self.realtime_findings.clear()

    def _send_to_llm_without_response(self, prompt: str) -> None:
        """
        Send a prompt to the LLM without expecting a response.

        Args:
            prompt: Text prompt to send
        """
        if not self.llm_available:
            return

        try:
            # Send the prompt but don't wait for or process the response
            if hasattr(self.llm, 'invoke'):
                self.llm.invoke(prompt)
            elif hasattr(self.llm, 'predict'):
                self.llm.predict(prompt)
        except Exception as e:
            if self.verbose:
                print(f"Failed to send prompt to LLM: {e}")

    def _send_to_llm(self, prompt):
        """
        Safely send a prompt to the LLM.

        Args:
            prompt: Text prompt to send

        Returns:
            Response text or None if failed
        """
        if not self.llm_available:
            return None

        try:
            if hasattr(self.llm, 'invoke'):
                response = self.llm.invoke(prompt)
                if hasattr(response, 'content'):
                    return response.content
                else:
                    return str(response)
            elif hasattr(self.llm, 'predict'):
                return self.llm.predict(prompt)
            else:
                return None
        except Exception as e:
            if self.verbose:
                print(f"LLM request failed: {e}")
            return None

    def analyze(self, state: State, max_iterations: int) -> State:
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
        try:
            # Start user interaction if not already started
            start_user_interaction()

            # Set context for user interaction
            set_context({
                'state': state,
                'agent': self,
                'max_iterations': max_iterations
            })

            if self.verbose:
                print(f"\n🔍 Starting analysis with {max_iterations} max iterations")
                print(f"📊 LLM Available: {self.llm_available}")
                print(f"🎯 Provider: {self.provider}")

            iteration = 0
            previous_results = ""

            while iteration < max_iterations:
                if self.verbose:
                    print(f"\n📈 Advanced to phase: {'assessment' if iteration == 0 else 'analysis'}")

                # Check for user input
                user_input = check_for_user_input()
                if user_input:
                    context = {
                        'state': state,
                        'iteration': iteration,
                        'max_iterations': max_iterations
                    }
                    result = process_user_input(user_input, context)
                    if result.get('action') == 'stop':
                        break
                    elif result.get('action') == 'skip_iteration':
                        iteration += 1
                        continue

                # Store state before analysis
                previous_insights_count = len(state.insights)
                previous_transformations_count = len(state.transformations)

                try:
                    # Phase 1: Assess current state
                    assessment = self._assess_state(state)

                    # Phase 2: Select strategy
                    strategy_info = self._select_strategy(state, assessment, previous_results)

                    if not strategy_info or 'analyzer' not in strategy_info:
                        if self.verbose:
                            print("⚠️ No valid strategy selected, ending analysis")
                        break

                    analyzer_name = strategy_info['analyzer']

                    # Phase 3: Execute the selected analyzer
                    if self.verbose:
                        print(f"🔧 Running {analyzer_name} analyzer...")

                    try:
                        analyzer = get_analyzer(analyzer_name)
                        if analyzer:
                            # Pass any parameters from the strategy
                            params = strategy_info.get('params', {})
                            state = analyzer(state, **params)
                        else:
                            if self.verbose:
                                print(f"❌ Analyzer {analyzer_name} not found")
                            break

                    except Exception as e:
                        if self.verbose:
                            print(f"❌ Analyzer {analyzer_name} failed: {e}")
                        # Continue with next iteration instead of breaking
                        iteration += 1
                        continue

                    # Phase 4: Review results and plan next steps
                    review_info = self._review_analyzer_results(
                        state, analyzer_name, previous_insights_count, previous_transformations_count
                    )

                    # Update previous results for next iteration
                    if review_info:
                        previous_results = review_info.get('summary', '')

                    # Check if we should continue
                    if review_info and review_info.get('should_stop', False):
                        if self.verbose:
                            print("✅ Analysis complete based on LLM review")
                        break

                    # Check if solution was found
                    if state.solution:
                        if self.verbose:
                            print("🎉 Solution found!")
                        break

                except Exception as e:
                    if self.verbose:
                        print(f"❌ Analysis iteration {iteration} failed: {e}")
                    # Continue to next iteration

                iteration += 1
                time.sleep(0.1)  # Brief pause between iterations

            # Send any remaining real-time findings
            if self.realtime_findings:
                self._send_realtime_findings_to_llm()

            # Final attempt at direct solution if no solution found
            if not state.solution:
                if self.verbose:
                    print("\n🎯 Attempting direct solution...")
                self._attempt_direct_solution(state)

            if self.verbose:
                print(f"\n📊 Analysis completed after {iteration} iterations")
                print(f"💡 Insights: {len(state.insights)}")
                print(f"🔄 Transformations: {len(state.transformations)}")
                if state.solution:
                    print(f"✅ Solution: {state.solution}")

            return state

        except Exception as e:
            if self.verbose:
                print(f"❌ Critical analysis error: {e}")
            # Add error information to state
            state.add_insight(f"Analysis failed with error: {str(e)}", "agent")
            return state

    def _assess_state(self, state: State) -> str:
        """
        Assess the current state of the puzzle.
        """
        try:
            if self.llm_available and self.state_assessment_chain:
                # Prepare context for LLM assessment
                context = {
                    'state_summary': state.get_summary(),
                    'transformations': '\n'.join([
                        f"- {t['name']}: {t['description']}"
                        for t in state.transformations[-10:]  # Last 10 transformations
                    ]) if state.transformations else "None",
                    'insights': '\n'.join([
                        f"- {i['text']}"
                        for i in state.insights[-10:]  # Last 10 insights
                    ]) if state.insights else "None",
                    'patterns': '\n'.join([
                        f"- {p['text']} (from {p['source']})"
                        for p in state.patterns
                    ]) if state.patterns else "None",
                    'puzzle_content': state.get_content_sample(500, 100)
                }

                try:
                    response = self.state_assessment_chain.invoke(context)
                    if hasattr(response, 'content'):
                        return response.content
                    else:
                        return str(response)
                except Exception as e:
                    if self.verbose:
                        print(f"LLM state assessment failed: {e}")
                    return self._fallback_assessment(state)
            else:
                return self._fallback_assessment(state)

        except Exception as e:
            if self.verbose:
                print(f"State assessment failed: {e}")
            return self._fallback_assessment(state)

    def _select_strategy(self, state: State, assessment: str, previous_results: str) -> Dict:
        """
        Select the next analysis strategy based on the current state.

        Args:
            state: Current puzzle state
            assessment: Assessment of the current state
            previous_results: Optional results from previous analyzer runs

        Returns:
            Dictionary with strategy information
        """
        try:
            if self.llm_available and self.strategy_chain:
                # Get compatible analyzers
                compatible_analyzers = get_compatible_analyzers(state)

                context = {
                    'state_summary': state.get_summary(),
                    'assessment': assessment,
                    'transformations': '\n'.join([
                        f"- {t['name']}: {t['description']}"
                        for t in state.transformations[-5:]  # Last 5 transformations
                    ]) if state.transformations else "None",
                    'insights': '\n'.join([
                        f"- {i['text']}"
                        for i in state.insights[-5:]  # Last 5 insights
                    ]) if state.insights else "None",
                    'patterns': '\n'.join([
                        f"- {p['text']} (from {p['source']})"
                        for p in state.patterns
                    ]) if state.patterns else "None",
                    'previous_results': previous_results or "None",
                    'chat_history': "None"  # Could be extended later
                }

                try:
                    response = self.strategy_chain.invoke(context)
                    response_text = response.content if hasattr(response, 'content') else str(response)

                    # Try to parse JSON response
                    import re
                    json_match = re.search(r'```json\s*(\{.*?\})\s*```', response_text, re.DOTALL)
                    if json_match:
                        try:
                            strategy_info = json.loads(json_match.group(1))
                            # Validate analyzer exists
                            if strategy_info.get('analyzer') in [name for name, _ in get_all_analyzers().items()]:
                                return strategy_info
                        except json.JSONDecodeError:
                            pass

                    # Fallback: try to extract analyzer name from response
                    available_analyzers = list(get_all_analyzers().keys())
                    for analyzer_name in available_analyzers:
                        if analyzer_name in response_text:
                            return {
                                'strategy': f"Run {analyzer_name}",
                                'analyzer': analyzer_name,
                                'params': {},
                                'reasoning': "Selected from LLM response"
                            }

                except Exception as e:
                    if self.verbose:
                        print(f"LLM strategy selection failed: {e}")

            # Fallback strategy selection
            compatible_analyzers = get_compatible_analyzers(state)
            if compatible_analyzers:
                # Choose first compatible analyzer
                analyzer_name = compatible_analyzers[0]
                return {
                    'strategy': f"Run {analyzer_name}",
                    'analyzer': analyzer_name,
                    'params': {},
                    'reasoning': "Fallback selection"
                }
            else:
                # Default to text analyzer if possible
                all_analyzers = get_all_analyzers()
                if 'text_analyzer' in all_analyzers:
                    return {
                        'strategy': "Run text_analyzer",
                        'analyzer': 'text_analyzer',
                        'params': {},
                        'reasoning': "Default fallback"
                    }

            return {}

        except Exception as e:
            if self.verbose:
                print(f"Strategy selection failed: {e}")
            return {}

    def _review_analyzer_results(self, state: State, analyzer_name: str,
                               previous_insights_count: int, previous_transformations_count: int) -> Dict:
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
        try:
            new_insights = len(state.insights) - previous_insights_count
            new_transformations = len(state.transformations) - previous_transformations_count

            # Basic assessment without LLM
            summary = f"Analyzer {analyzer_name} completed. "
            summary += f"Generated {new_insights} new insights and {new_transformations} new transformations."

            # Determine if we should continue
            should_stop = False
            if state.solution:
                should_stop = True
                summary += " Solution found!"
            elif new_insights == 0 and new_transformations == 0:
                summary += " No new information generated."
            else:
                summary += " Analysis progressing."

            return {
                'summary': summary,
                'should_stop': should_stop,
                'new_insights': new_insights,
                'new_transformations': new_transformations
            }

        except Exception as e:
            if self.verbose:
                print(f"Results review failed: {e}")
            return {
                'summary': f"Analyzer {analyzer_name} completed with errors.",
                'should_stop': False,
                'new_insights': 0,
                'new_transformations': 0
            }

    def _attempt_direct_solution(self, state: State) -> None:
        """
        Attempt to directly solve the puzzle without further analysis.
        """
        try:
            if self.llm_available and self.direct_solution_chain:
                context = {
                    'state_summary': state.get_summary(),
                    'patterns': '\n'.join([
                        f"- {p['text']} (from {p['source']})"
                        for p in state.patterns
                    ]) if state.patterns else "None",
                    'puzzle_content': state.get_content_sample(1000, 200)
                }

                try:
                    response = self.direct_solution_chain.invoke(context)
                    response_text = response.content if hasattr(response, 'content') else str(response)

                    # Look for solution marker
                    import re
                    solution_match = re.search(r'SOLUTION:\s*(.+)', response_text, re.IGNORECASE)
                    if solution_match:
                        potential_solution = solution_match.group(1).strip()
                        state.set_solution(potential_solution)
                        state.add_insight(f"Direct solution attempt: {potential_solution}", "agent")
                    else:
                        state.add_insight("Direct solution attempt made but no clear solution identified", "agent")

                except Exception as e:
                    if self.verbose:
                        print(f"LLM direct solution failed: {e}")
                    state.add_insight(self._fallback_direct_solution(state), "agent")
            else:
                state.add_insight(self._fallback_direct_solution(state), "agent")

        except Exception as e:
            if self.verbose:
                print(f"Direct solution attempt failed: {e}")
            state.add_insight("Direct solution attempt failed due to error", "agent")
