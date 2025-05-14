"""
Agent module for Crypto Hunter

This module provides the AI agent capabilities for cryptographic analysis,
leveraging LangChain and LLMs for intelligent puzzle solving.
"""
import logging
import time
from typing import Dict, List, Any, Optional, Callable, Union, Tuple

from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from langchain_core.runnables import RunnablePassthrough

import config
from core.state import State
from analyzers.base import get_all_analyzers, run_analyzer, get_compatible_analyzers

logger = logging.getLogger(__name__)


class CryptoAgent:
    """
    AI agent for cryptographic analysis and puzzle solving.
    Uses LLMs to guide the analysis process and interpret results.
    """

    def __init__(self, provider: str = "anthropic"):
        """
        Initialize the crypto agent.

        Args:
            provider: LLM provider to use (anthropic or openai)
        """
        self.provider = provider
        self.llm = self._initialize_llm(provider)
        self.analyzers = get_all_analyzers()
        
        # Initialize the chat history
        self.chat_history = []
        
        logger.info(f"Initialized CryptoAgent with {provider} provider")
        logger.debug(f"Available analyzers: {list(self.analyzers.keys())}")

    def _initialize_llm(self, provider: str):
        """
        Initialize the language model based on provider.

        Args:
            provider: LLM provider (anthropic or openai)

        Returns:
            Initialized LLM
        """
        if provider == "anthropic":
            if not config.ANTHROPIC_API_KEY:
                logger.warning("ANTHROPIC_API_KEY not set. Some features may not work.")
                
            return ChatAnthropic(
                api_key=config.ANTHROPIC_API_KEY,
                model=config.LLM_CONFIG["anthropic"]["model"],
                temperature=config.LLM_CONFIG["anthropic"]["temperature"],
                max_tokens=config.LLM_CONFIG["anthropic"]["max_tokens"],
            )
        
        elif provider == "openai":
            if not config.OPENAI_API_KEY:
                logger.warning("OPENAI_API_KEY not set. Some features may not work.")
                
            return ChatOpenAI(
                api_key=config.OPENAI_API_KEY,
                model=config.LLM_CONFIG["openai"]["model"],
                temperature=config.LLM_CONFIG["openai"]["temperature"],
                max_tokens=config.LLM_CONFIG["openai"]["max_tokens"],
            )
        
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")

    def analyze(
        self,
        state: State,
        analyzers: Optional[Dict[str, Callable]] = None,
        max_iterations: int = 10,
    ) -> State:
        """
        Analyze a puzzle using multiple analyzers and AI guidance.

        Args:
            state: Current puzzle state
            analyzers: Dictionary of analyzers to use (defaults to all compatible)
            max_iterations: Maximum number of analysis iterations

        Returns:
            Updated state after analysis
        """
        if not analyzers:
            # Use all compatible analyzers
            analyzers = get_compatible_analyzers(state)
        
        if not analyzers:
            logger.warning("No compatible analyzers found for the current state")
            state.add_insight("No compatible analyzers found for the current state")
            return state
        
        logger.info(f"Starting analysis with {len(analyzers)} analyzers")
        logger.debug(f"Using analyzers: {list(analyzers.keys())}")
        
        # Initialize iteration counter
        iteration = 0
        
        # Strategy chain for determining next steps
        strategy_chain = self._create_strategy_chain()
        
        # Main analysis loop
        while iteration < max_iterations and state.status != "solved":
            iteration += 1
            logger.info(f"Analysis iteration {iteration}/{max_iterations}")
            
            # Get current state summary
            state_summary = self._create_state_summary(state)
            
            # Determine strategy for this iteration
            strategy_result = strategy_chain.invoke({
                "state_summary": state_summary,
                "available_analyzers": list(analyzers.keys()),
                "iteration": iteration,
                "max_iterations": max_iterations,
                "chat_history": self.chat_history,
            })
            
            # Parse the strategy result
            next_analyzer, params = self._parse_strategy(strategy_result)
            
            if next_analyzer == "SOLUTION_FOUND":
                # Solution found - extract from params
                solution = params.get("solution", "Unknown solution")
                confidence = float(params.get("confidence", 0.9))
                state.set_solution(solution, confidence=confidence, analyzer="agent")
                break
                
            elif next_analyzer == "NO_FURTHER_ANALYSIS":
                # No further analysis possible
                logger.info("No further analysis possible")
                state.add_insight("Agent determined no further analysis would be beneficial")
                break
                
            elif next_analyzer in analyzers:
                # Run the selected analyzer
                logger.info(f"Running analyzer: {next_analyzer}")
                updated_state = run_analyzer(next_analyzer, state, **params)
                
                # Update state
                state = updated_state
                
                # Update chat history with results
                self._update_chat_history(next_analyzer, state)
                
            else:
                # Invalid analyzer selected
                logger.warning(f"Invalid analyzer selected: {next_analyzer}")
                state.add_insight(f"Agent selected invalid analyzer: {next_analyzer}")
        
        # Check if max iterations reached
        if iteration >= max_iterations and state.status != "solved":
            logger.info(f"Reached maximum iterations ({max_iterations}) without solution")
            state.add_insight(f"Analysis stopped after {max_iterations} iterations without solution")
        
        return state

    def _create_strategy_chain(self):
        """
        Create a chain for determining the analysis strategy.

        Returns:
            Strategy chain
        """
        system_prompt = """
        You are an expert cryptanalyst and puzzle solver. Your task is to analyze cryptographic puzzles
        and determine the best approach to solve them. Based on the current state of the analysis and
        available analyzers, you will decide the next step in the analysis process.

        Available analyzers and their capabilities:

        1. text_analyzer: Analyzes text for patterns, encodings, and potential cryptographic schemes.
           Good for: Base64, hex encoding, Caesar cipher, substitution ciphers, etc.

        2. binary_analyzer: Analyzes binary files for hidden data, file headers, and embedded content.
           Good for: Steganography in files, embedded data, file structure analysis.

        3. image_analyzer: Analyzes images for steganography and hidden data.
           Good for: LSB steganography, metadata analysis, visual cryptography.

        4. blockchain_analyzer: Analyzes blockchain addresses and transactions.
           Good for: Ethereum/Bitcoin puzzles, transaction data, smart contract analysis.

        5. cipher_analyzer: Specialized analysis for specific cipher types.
           Good for: AES, RSA, Vigenère, and other structured encryption schemes.

        6. encoding_analyzer: Detects and decodes various encoding schemes.
           Good for: Multi-layered encodings, custom encoding schemes.

        For each analysis iteration, you should:
        1. Review the current state summary and history of insights
        2. Determine the most promising analyzer to use next
        3. Specify any parameters needed for that analyzer
        4. If you believe a solution has been found, respond with SOLUTION_FOUND and the solution
        5. If no further analysis would be beneficial, respond with NO_FURTHER_ANALYSIS

        Your response should be in the following format:
        ```
        ANALYZER: <analyzer_name>
        PARAMS: <JSON dictionary of parameters>
        REASONING: <explanation of your choice>
        ```
        """

        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content=system_prompt),
            MessagesPlaceholder(variable_name="chat_history"),
            HumanMessage(content="""
            Current analysis state:
            {state_summary}
            
            Available analyzers: {available_analyzers}
            
            This is iteration {iteration} of {max_iterations}.
            
            Determine the next analyzer to use or if we should stop analysis.
            """),
        ])

        return prompt | self.llm | StrOutputParser()

    def _create_state_summary(self, state: State) -> str:
        """
        Create a summary of the current state for the AI.

        Args:
            state: Current puzzle state

        Returns:
            Text summary of the state
        """
        summary = []
        
        # Basic puzzle info
        summary.append(f"Puzzle File: {state.puzzle_file}")
        summary.append(f"File Type: {state.file_type}")
        summary.append(f"File Size: {state.file_size} bytes")
        
        # Add insights
        summary.append("\nInsights:")
        if state.insights:
            for i, insight in enumerate(state.insights[-10:], 1):  # Last 10 insights
                summary.append(f"{i}. [{insight['analyzer'] or 'Unknown'}] {insight['message']}")
        else:
            summary.append("No insights yet.")
        
        # Add transformations
        summary.append("\nTransformations:")
        if state.transformations:
            for i, transform in enumerate(state.transformations[-5:], 1):  # Last 5 transformations
                summary.append(f"{i}. [{transform['analyzer'] or 'Unknown'}] {transform['name']}: {transform['description']}")
        else:
            summary.append("No transformations yet.")
        
        # Add puzzle text if available (truncated)
        if state.puzzle_text:
            text = state.puzzle_text
            if len(text) > 1000:
                text = text[:1000] + "... (truncated)"
            summary.append("\nPuzzle Text Preview:")
            summary.append(text)
        
        # Add solution if available
        if state.solution:
            summary.append(f"\nSolution: {state.solution}")
        
        return "\n".join(summary)

    def _parse_strategy(self, strategy_result: str) -> Tuple[str, Dict[str, Any]]:
        """
        Parse the strategy result from the AI.

        Args:
            strategy_result: Strategy output from the LLM

        Returns:
            Tuple of (analyzer_name, parameters)
        """
        lines = strategy_result.strip().split("\n")
        analyzer = "NO_FURTHER_ANALYSIS"
        params = {}
        
        for line in lines:
            line = line.strip()
            
            if line.startswith("ANALYZER:"):
                analyzer = line[9:].strip()
            
            elif line.startswith("PARAMS:"):
                try:
                    # Try to parse as JSON if possible
                    import json
                    params_str = line[7:].strip()
                    if params_str:
                        params = json.loads(params_str)
                except:
                    # If not valid JSON, parse the params manually
                    params_str = line[7:].strip()
                    if params_str:
                        for param in params_str.split(","):
                            if ":" in param:
                                key, value = param.split(":", 1)
                                params[key.strip()] = value.strip()
        
        # Special cases handling
        if analyzer.upper() == "SOLUTION_FOUND":
            return "SOLUTION_FOUND", params
            
        if analyzer.upper() == "NO_FURTHER_ANALYSIS":
            return "NO_FURTHER_ANALYSIS", {}
        
        return analyzer, params

    def _update_chat_history(self, analyzer_name: str, state: State):
        """
        Update the chat history with the results from an analyzer.

        Args:
            analyzer_name: Name of the analyzer
            state: Updated state after analysis
        """
        # Get the most recent insights and transformations
        recent_insights = state.insights[-5:] if state.insights else []
        recent_transforms = state.transformations[-3:] if state.transformations else []
        
        # Create a message with the results
        message = f"Results from {analyzer_name}:\n\n"
        
        if recent_insights:
            message += "New insights:\n"
            for insight in recent_insights:
                message += f"- {insight['message']}\n"
        else:
            message += "No new insights.\n"
        
        if recent_transforms:
            message += "\nTransformations:\n"
            for transform in recent_transforms:
                message += f"- {transform['name']}: {transform['description']}\n"
        
        # Add to chat history
        self.chat_history.append(AIMessage(content=message))
        
        # Limit chat history length
        if len(self.chat_history) > 10:
            self.chat_history = self.chat_history[-10:]

    def ask_llm(self, question: str, context: Optional[str] = None) -> str:
        """
        Ask a direct question to the LLM.

        Args:
            question: Question to ask
            context: Optional context to provide

        Returns:
            LLM response
        """
        # Create prompt
        messages = []
        
        # Add system message
        system_message = """
        You are an expert cryptanalyst and puzzle solver. Your task is to help
        analyze and solve cryptographic puzzles and encoded data. Provide clear,
        concise, and accurate information based on your knowledge.
        """
        messages.append(SystemMessage(content=system_message))
        
        # Add context if provided
        if context:
            messages.append(SystemMessage(content=f"Context: {context}"))
        
        # Add question
        messages.append(HumanMessage(content=question))
        
        # Get response
        try:
            response = self.llm.invoke(messages)
            return response.content
        except Exception as e:
            logger.error(f"Error asking LLM: {e}")
            return f"Error: Could not get a response from the LLM. {str(e)}"

    def interpret_data(self, data: Union[str, bytes], state: Optional[State] = None) -> str:
        """
        Interpret data using the LLM.

        Args:
            data: Data to interpret
            state: Optional state for context

        Returns:
            Interpretation result
        """
        # Convert bytes to string if needed
        if isinstance(data, bytes):
            # Try to decode as UTF-8
            try:
                data_str = data.decode("utf-8")
            except UnicodeDecodeError:
                # If not UTF-8, convert to hex
                data_str = f"Hex data: {data.hex()[:1000]}"
                if len(data) > 500:
                    data_str += "... (truncated)"
        else:
            data_str = data
            
            # Truncate if too long
            if len(data_str) > 2000:
                data_str = data_str[:2000] + "... (truncated)"
        
        # Create context from state if provided
        context = ""
        if state:
            context = f"Puzzle file: {state.puzzle_file}\n"
            context += f"File type: {state.file_type}\n"
            if state.insights:
                context += "Recent insights:\n"
                for insight in state.insights[-5:]:
                    context += f"- {insight['message']}\n"
        
        # Create prompt
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content="""
            You are an expert cryptanalyst and puzzle solver. Your task is to analyze 
            and interpret the given data. Look for patterns, encodings, ciphers,
            or any other cryptographic techniques that might be present.
            
            For text data, consider:
            - Common encodings (Base64, hex, etc.)
            - Simple substitution ciphers
            - Caesar/ROT ciphers
            - Transposition ciphers
            - Hidden messages or steganography
            - Common patterns in cryptographic puzzles
            
            For binary or hex data, consider:
            - File signatures and formats
            - Hidden data in binary structures
            - Bit-level patterns or manipulations
            
            Provide your best interpretation of what this data represents and any
            potential next steps for analysis.
            """),
            HumanMessage(content=f"""
            {context}
            
            Please analyze the following data:
            
            {data_str}
            """),
        ])
        
        # Get response
        try:
            chain = prompt | self.llm | StrOutputParser()
            return chain.invoke({})
        except Exception as e:
            logger.error(f"Error interpreting data: {e}")
            return f"Error: Could not interpret the data. {str(e)}"
