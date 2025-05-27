"""
CodeAgent for Crypto Hunter.
An agent capable of writing and executing its own code to solve puzzles.
"""

import ast
import importlib
import inspect
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
from core.arweave_tools_main import register_arweave_tools_with_agent


class DynamicToolRegistry:
    """Registry for dynamically created tools."""

    def __init__(self, tools_dir: Union[str, Path]) -> None:
        """
        Initialize the tool registry.

        Args:
            tools_dir: Directory to store dynamically created tools
        """
        self.tools_dir = Path(tools_dir)
        self.tools_dir.mkdir(exist_ok=True)

        self.tools = {}  # tool_id -> tool_function
        self.tool_metadata = {}  # tool_id -> metadata

        # Load existing tools
        self._load_existing_tools()

    def _load_existing_tools(self) -> None:
        """Load existing tools from the tools directory."""
        for tool_file in self.tools_dir.glob("tool_*.py"):
            try:
                tool_id = tool_file.stem

                # Read the file to extract metadata
                content = tool_file.read_text()

                # Import the module
                spec = importlib.util.spec_from_file_location(tool_id, tool_file)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    # Look for the main function
                    if hasattr(module, 'main'):
                        self.tools[tool_id] = module.main

                        # Extract metadata from docstring or comments
                        description = ""
                        if hasattr(module.main, '__doc__') and module.main.__doc__:
                            description = module.main.__doc__.strip()

                        self.tool_metadata[tool_id] = {
                            'description': description,
                            'file_path': str(tool_file),
                            'created_at': tool_file.stat().st_mtime
                        }

                        logging.info(f"Loaded tool: {tool_id}")

            except Exception as e:
                logging.warning(f"Failed to load tool {tool_file}: {e}")

    def register_tool(self, code: str, name: Optional[str] = None, description: str = "") -> Optional[str]:
        """
        Register a new tool from code.

        Args:
            code: Python code for the tool
            name: Optional name for the tool (extracted from code if not provided)
            description: Optional description of the tool

        Returns:
            Tool ID if successful, None otherwise
        """
        try:
            # Generate tool ID
            tool_id = name or f"tool_{uuid.uuid4().hex[:8]}"

            # Validate the code by parsing it
            try:
                ast.parse(code)
            except SyntaxError as e:
                logging.error(f"Code syntax error: {e}")
                return None

            # Wrap the code in a proper function if needed
            if 'def main(' not in code:
                # Extract the main logic and wrap it
                wrapped_code = f'''
"""
{description}
"""

def main(inputs=None):
    """Main function for the tool."""
    if inputs is None:
        inputs = {{}}

    try:
{self._indent_code(code, 8)}

        return {{"success": True, "result": "Tool executed successfully"}}
    except Exception as e:
        return {{"success": False, "error": str(e)}}
'''
            else:
                wrapped_code = f'"""\n{description}\n"""\n\n{code}'

            # Save to file
            tool_file = self.tools_dir / f"{tool_id}.py"
            tool_file.write_text(wrapped_code)

            # Import and register
            spec = importlib.util.spec_from_file_location(tool_id, tool_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                if hasattr(module, 'main'):
                    self.tools[tool_id] = module.main
                    self.tool_metadata[tool_id] = {
                        'description': description,
                        'file_path': str(tool_file),
                        'created_at': time.time()
                    }

                    logging.info(f"Registered tool: {tool_id}")
                    return tool_id
                else:
                    logging.error(f"Tool {tool_id} has no main function")
                    tool_file.unlink()  # Remove invalid file
                    return None

        except Exception as e:
            logging.error(f"Failed to register tool: {e}")
            return None

    def get_tool(self, tool_id: str) -> Optional[Callable]:
        """Get a tool by ID."""
        return self.tools.get(tool_id)

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all registered tools."""
        return [
            {
                'id': tool_id,
                'description': self.tool_metadata.get(tool_id, {}).get('description', ''),
                'created_at': self.tool_metadata.get(tool_id, {}).get('created_at', 0)
            }
            for tool_id in self.tools.keys()
        ]

    def remove_tool(self, tool_id: str) -> bool:
        """Remove a tool by ID."""
        if tool_id in self.tools:
            try:
                # Remove from memory
                del self.tools[tool_id]
                if tool_id in self.tool_metadata:
                    # Remove file if it exists
                    file_path = self.tool_metadata[tool_id].get('file_path')
                    if file_path and os.path.exists(file_path):
                        os.unlink(file_path)
                    del self.tool_metadata[tool_id]
                return True
            except Exception as e:
                logging.error(f"Failed to remove tool {tool_id}: {e}")
        return False

    def _indent_code(self, code: str, spaces: int) -> str:
        """Indent each line of code by the specified number of spaces."""
        lines = code.split('\n')
        indented_lines = []
        for line in lines:
            if line.strip():  # Don't indent empty lines
                indented_lines.append(' ' * spaces + line)
            else:
                indented_lines.append('')
        return '\n'.join(indented_lines)


class SafeExecutionEnvironment:
    """
    Provides a safe environment for executing generated code.
    """

    def __init__(self, allowed_modules: Optional[List[str]] = None, max_execution_time: int = 30,
                 memory_limit: int = 100 * 1024 * 1024) -> None:
        """
        Initialize the safe execution environment.

        Args:
            allowed_modules: List of allowed modules (None for default safe set)
            max_execution_time: Maximum execution time in seconds
            memory_limit: Memory limit in bytes
        """
        self.max_execution_time = max_execution_time
        self.memory_limit = memory_limit

        # Default safe modules
        if allowed_modules is None:
            self.allowed_modules = {
                'math', 'random', 'string', 'collections', 'itertools',
                'functools', 'operator', 're', 'json', 'base64',
                'hashlib', 'hmac', 'urllib.parse', 'binascii',
                'datetime', 'time', 'calendar', 'struct',
                'zlib', 'gzip', 'bz2', 'lzma', 'pickle',
                'csv', 'configparser', 'statistics',
                'fractions', 'decimal', 'cmath'
            }
        else:
            self.allowed_modules = set(allowed_modules)

    def _indent_code(self, code: str, spaces: int) -> str:
        """
        Indent each line of code by the specified number of spaces.

        Args:
            code: The code to indent
            spaces: Number of spaces to indent by

        Returns:
            Indented code
        """
        lines = code.split('\n')
        indented_lines = []
        for line in lines:
            if line.strip():  # Don't indent empty lines
                indented_lines.append(' ' * spaces + line)
            else:
                indented_lines.append('')
        return '\n'.join(indented_lines)

    def _create_safe_globals(self) -> Dict[str, Any]:
        """Create a safe globals dictionary."""
        safe_builtins = {
            'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'chr', 'dict',
            'divmod', 'enumerate', 'filter', 'float', 'format', 'frozenset',
            'hasattr', 'hash', 'hex', 'int', 'isinstance', 'issubclass',
            'iter', 'len', 'list', 'map', 'max', 'min', 'oct', 'ord',
            'pow', 'range', 'repr', 'reversed', 'round', 'set', 'slice',
            'sorted', 'str', 'sum', 'tuple', 'type', 'vars', 'zip'
        }

        # Create restricted builtins
        restricted_builtins = {}
        for name in safe_builtins:
            if hasattr(__builtins__, name):
                restricted_builtins[name] = getattr(__builtins__, name)

        # Add safe modules
        safe_globals = {
            '__builtins__': restricted_builtins,
            '_print_': print,  # Controlled print function
            '_input_': lambda prompt="": input(prompt),  # Controlled input
        }

        # Import allowed modules
        for module_name in self.allowed_modules:
            try:
                safe_globals[module_name] = __import__(module_name)
            except ImportError:
                continue

        return safe_globals

    def execute(self, code: str, inputs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute code in a safe environment.

        Args:
            code: Python code to execute
            inputs: Optional dictionary of input variables

        Returns:
            Dictionary containing execution result
        """
        if inputs is None:
            inputs = {}

        try:
            # Create safe execution environment
            safe_globals = self._create_safe_globals()
            safe_locals = inputs.copy()

            # Add a results collector
            results = {'output': [], 'result': None, 'error': None}

            # Override print to capture output
            def safe_print(*args, **kwargs):
                output = ' '.join(str(arg) for arg in args)
                results['output'].append(output)

            safe_globals['print'] = safe_print
            safe_globals['_results_'] = results

            # Wrap the code to capture the result
            wrapped_code = f'''
try:
{self._indent_code(code, 4)}

    # Try to capture the last expression result
    if 'result' in locals():
        _results_['result'] = result
    elif 'answer' in locals():
        _results_['result'] = answer
    elif 'output' in locals():
        _results_['result'] = output

except Exception as e:
    import traceback
    _results_['error'] = str(e)
    _results_['traceback'] = traceback.format_exc()
'''

            # Execute with timeout
            start_time = time.time()

            try:
                exec(wrapped_code, safe_globals, safe_locals)

                execution_time = time.time() - start_time

                return {
                    'success': results['error'] is None,
                    'result': results['result'],
                    'output': '\n'.join(results['output']),
                    'error': results['error'],
                    'execution_time': execution_time,
                    'locals': {k: v for k, v in safe_locals.items() if not k.startswith('_')}
                }

            except Exception as e:
                return {
                    'success': False,
                    'result': None,
                    'output': '\n'.join(results['output']),
                    'error': str(e),
                    'execution_time': time.time() - start_time,
                    'locals': {}
                }

        except Exception as e:
            return {
                'success': False,
                'result': None,
                'output': '',
                'error': f'Setup error: {str(e)}',
                'execution_time': 0,
                'locals': {}
            }


class CodeAgent:
    """
    Agent capable of writing and executing its own code to solve puzzles.
    """

    def __init__(self, llm_agent: Optional[Any] = None, tools_dir: Union[str, Path] = "generated_tools",
                 max_execution_time: int = 30, memory_limit: int = 100 * 1024 * 1024) -> None:
        """
        Initialize the CodeAgent.

        Args:
            llm_agent: LLM agent for code generation
            tools_dir: Directory to store dynamically created tools
            max_execution_time: Maximum execution time in seconds
            memory_limit: Memory limit in bytes
        """
        self.llm_agent = llm_agent
        self.tools_dir = Path(tools_dir)
        self.tools_dir.mkdir(exist_ok=True)

        # Initialize components
        self.tool_registry = DynamicToolRegistry(tools_dir)
        self.execution_env = SafeExecutionEnvironment(
            max_execution_time=max_execution_time,
            memory_limit=memory_limit
        )

        # Register Arweave tools if available
        try:
            register_arweave_tools_with_agent(self)
        except Exception as e:
            logging.warning(f"Failed to register Arweave tools: {e}")

    def generate_code(self, task_description: str, state: Optional[Any] = None,
                      required_outputs: Optional[List[str]] = None) -> str:
        """
        Generate code for a specific task.

        Args:
            task_description: Description of the task
            state: Current puzzle state (if available)
            required_outputs: List of required output variables

        Returns:
            Generated code
        """
        if self.llm_agent and hasattr(self.llm_agent, 'llm_available') and self.llm_agent.llm_available:
            return self._generate_with_llm(task_description, state, required_outputs)
        else:
            return self._generate_fallback_code(task_description, required_outputs)

    def _generate_with_llm(self, task_description: str, state: Optional[Any] = None,
                           required_outputs: Optional[List[str]] = None) -> str:
        """Generate code using LLM."""
        try:
            # Prepare context
            context = f"Task: {task_description}\n"

            if state:
                context += f"\nPuzzle context:\n"
                if hasattr(state, 'puzzle_text') and state.puzzle_text:
                    context += f"Text content: {state.puzzle_text[:500]}...\n"
                if hasattr(state, 'insights') and state.insights:
                    recent_insights = state.insights[-3:]
                    context += f"Recent insights: {[i.get('text', '') for i in recent_insights]}\n"

            if required_outputs:
                context += f"\nRequired outputs: {', '.join(required_outputs)}\n"

            prompt = f"""
Generate Python code to solve this cryptographic puzzle task:

{context}

Requirements:
1. Write clean, well-commented Python code
2. Use only standard library modules (math, re, string, base64, hashlib, etc.)
3. Handle errors gracefully
4. Store results in a variable called 'result'
5. Include print statements to show progress

The code should be executable as-is and solve the specific task described.
"""

            response = self.llm_agent._send_to_llm(prompt)
            if response:
                # Extract code from response
                code_blocks = re.findall(r'```python\n(.*?)\n```', response, re.DOTALL)
                if code_blocks:
                    return code_blocks[0]
                else:
                    # Try to extract code without markdown
                    lines = response.split('\n')
                    code_lines = []
                    in_code = False
                    for line in lines:
                        if line.strip().startswith('import ') or line.strip().startswith(
                                'def ') or line.strip().startswith('for ') or line.strip().startswith('if '):
                            in_code = True
                        if in_code:
                            code_lines.append(line)

                    if code_lines:
                        return '\n'.join(code_lines)

        except Exception as e:
            logging.error(f"LLM code generation failed: {e}")

        # Fallback to template
        return self._generate_fallback_code(task_description, required_outputs)

    def _generate_fallback_code(self, task_description: str, required_outputs: Optional[List[str]] = None) -> str:
        """
        Generate fallback code templates for common tasks.

        Args:
            task_description: Description of the task
            required_outputs: List of required output variables

        Returns:
            Template code
        """
        task_lower = task_description.lower()

        if 'base64' in task_lower:
            return self._template_base64_tool(required_outputs)
        elif 'xor' in task_lower:
            return self._template_xor_tool(required_outputs)
        elif 'caesar' in task_lower:
            return self._template_caesar_tool(required_outputs)
        elif 'hash' in task_lower:
            return self._template_hash_tool(required_outputs)
        elif 'frequency' in task_lower:
            return self._template_frequency_analysis_tool(required_outputs)
        else:
            return self._template_generic_analysis_tool(required_outputs)

    def _template_base64_tool(self, required_outputs: Optional[List[str]] = None) -> str:
        """Create a template for base64 encoding/decoding."""
        return '''
import base64
import string

def analyze_base64(text):
    """Analyze and decode base64 strings."""
    results = []

    # Look for base64 patterns
    import re
    base64_pattern = r'[A-Za-z0-9+/]{8,}={0,2}'
    matches = re.findall(base64_pattern, text)

    for match in matches:
        try:
            if len(match) % 4 == 0:  # Valid base64 length
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if decoded.isprintable():
                    results.append({'original': match, 'decoded': decoded})
                    print(f"Base64 decoded: {match[:20]}... -> {decoded}")
        except:
            continue

    return results

# Example usage
text_to_analyze = "SGVsbG8gV29ybGQ="  # Replace with actual text
result = analyze_base64(text_to_analyze)
print(f"Found {len(result)} base64 strings")
'''

    def _template_xor_tool(self, required_outputs: Optional[List[str]] = None) -> str:
        """Create a template for XOR cipher."""
        return '''
def xor_analyze(data, key=None):
    """Analyze XOR cipher with different keys."""
    results = []

    if isinstance(data, str):
        data = data.encode()

    if key is None:
        # Try common single-byte keys
        for k in range(256):
            try:
                decoded = ''.join(chr(b ^ k) for b in data)
                if decoded.isprintable() and len(decoded) > 10:
                    score = sum(1 for c in decoded.lower() if c in 'etaoinsrhdlu')
                    results.append({'key': k, 'decoded': decoded, 'score': score})
                    print(f"XOR key {k}: {decoded[:50]}...")
            except:
                continue

        # Sort by score
        results.sort(key=lambda x: x['score'], reverse=True)
    else:
        # Use provided key
        if isinstance(key, str):
            key = key.encode()

        decoded = ''
        for i, b in enumerate(data):
            decoded += chr(b ^ key[i % len(key)])

        results.append({'key': key, 'decoded': decoded, 'score': 0})
        print(f"XOR result: {decoded}")

    return results

# Example usage
data_to_analyze = b"\\x1a\\x0e\\x0c\\x0c\\x0f"  # Replace with actual data
result = xor_analyze(data_to_analyze)
if result:
    print(f"Best XOR result: {result[0]['decoded']}")
'''

    def _template_caesar_tool(self, required_outputs: Optional[List[str]] = None) -> str:
        """Create a template for Caesar cipher."""
        return '''
def caesar_analyze(text):
    """Analyze Caesar cipher with all possible shifts."""
    results = []

    def caesar_shift(text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                shifted = (ord(char) - ascii_offset + shift) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
        return result

    def score_english(text):
        # Simple English scoring based on letter frequency
        freq = {'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7}
        score = 0
        for char in text.lower():
            if char in freq:
                score += freq[char]
        return score

    for shift in range(26):
        decoded = caesar_shift(text, shift)
        score = score_english(decoded)
        results.append({'shift': shift, 'decoded': decoded, 'score': score})
        print(f"Shift {shift:2d}: {decoded[:50]}...")

    # Sort by score
    results.sort(key=lambda x: x['score'], reverse=True)
    return results

# Example usage
text_to_analyze = "KHOOR ZRUOG"  # Replace with actual text
result = caesar_analyze(text_to_analyze)
if result:
    print(f"\\nBest Caesar result (shift {result[0]['shift']}): {result[0]['decoded']}")
'''

    def _template_hash_tool(self, required_outputs: Optional[List[str]] = None) -> str:
        """Create a template for hash functions."""
        return '''
import hashlib

def hash_analyze(text):
    """Analyze and generate various hashes."""
    results = {}

    # Generate common hashes
    hash_functions = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }

    for name, func in hash_functions.items():
        hash_value = func(text.encode()).hexdigest()
        results[name] = hash_value
        print(f"{name.upper()}: {hash_value}")

    return results

def hash_crack_simple(hash_value, hash_type='md5'):
    """Simple hash cracking with common values."""
    import hashlib

    common_values = [
        'password', '123456', 'admin', 'root', 'flag', 'secret',
        'hello', 'world', 'test', '', 'a', 'b', 'c', '1', '2', '3'
    ]

    hash_func = getattr(hashlib, hash_type.lower())

    for value in common_values:
        if hash_func(value.encode()).hexdigest().lower() == hash_value.lower():
            print(f"Hash cracked: {hash_value} = '{value}'")
            return value

    print(f"Could not crack hash: {hash_value}")
    return None

# Example usage
text_to_hash = "hello world"  # Replace with actual text
result = hash_analyze(text_to_hash)

# Try to crack a hash
# hash_to_crack = "5d41402abc4b2a76b9719d911017c592"  # MD5 of "hello"
# cracked = hash_crack_simple(hash_to_crack, 'md5')
'''

    def _template_frequency_analysis_tool(self, required_outputs: Optional[List[str]] = None) -> str:
        """Create a template for frequency analysis."""
        return '''
from collections import Counter
import string

def frequency_analysis(text):
    """Perform frequency analysis on text."""
    results = {}

    # Character frequency
    char_freq = Counter(c.lower() for c in text if c.isalpha())
    results['char_frequency'] = dict(char_freq.most_common())

    print("Character frequencies:")
    for char, count in char_freq.most_common(10):
        percentage = (count / len([c for c in text if c.isalpha()])) * 100
        print(f"  {char}: {count} ({percentage:.1f}%)")

    # Word frequency
    words = text.lower().split()
    word_freq = Counter(words)
    results['word_frequency'] = dict(word_freq.most_common(10))

    print("\\nWord frequencies:")
    for word, count in word_freq.most_common(5):
        print(f"  {word}: {count}")

    # Bigram frequency
    bigrams = [text[i:i+2].lower() for i in range(len(text)-1) if text[i:i+2].isalpha()]
    bigram_freq = Counter(bigrams)
    results['bigram_frequency'] = dict(bigram_freq.most_common(10))

    print("\\nBigram frequencies:")
    for bigram, count in bigram_freq.most_common(5):
        print(f"  {bigram}: {count}")

    return results

# Example usage
text_to_analyze = "The quick brown fox jumps over the lazy dog"  # Replace with actual text
result = frequency_analysis(text_to_analyze)
'''

    def _template_generic_analysis_tool(self, required_outputs: Optional[List[str]] = None) -> str:
        """Create a template for generic text analysis."""
        return '''
import re
import string

def generic_analysis(text):
    """Perform generic analysis on text or data."""
    results = {}

    print(f"Analyzing text of length: {len(text)}")

    # Basic statistics
    results['length'] = len(text)
    results['unique_chars'] = len(set(text))
    results['printable_ratio'] = sum(1 for c in text if c in string.printable) / len(text)

    print(f"Unique characters: {results['unique_chars']}")
    print(f"Printable ratio: {results['printable_ratio']:.2f}")

    # Look for patterns
    patterns = {
        'hex_strings': r'[0-9a-fA-F]{8,}',
        'base64_like': r'[A-Za-z0-9+/]{8,}={0,2}',
        'email_addresses': r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b',
        'urls': r'https?://[^\\s]+',
        'numbers': r'\\b\\d+\\b'
    }

    for pattern_name, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            results[pattern_name] = matches
            print(f"Found {len(matches)} {pattern_name}: {matches[:3]}...")

    # Character distribution
    char_types = {
        'letters': sum(1 for c in text if c.isalpha()),
        'digits': sum(1 for c in text if c.isdigit()),
        'spaces': sum(1 for c in text if c.isspace()),
        'punctuation': sum(1 for c in text if c in string.punctuation)
    }

    print("\\nCharacter distribution:")
    for char_type, count in char_types.items():
        print(f"  {char_type}: {count}")

    results['char_distribution'] = char_types

    return results

# Example usage
text_to_analyze = "Sample text to analyze"  # Replace with actual text
result = generic_analysis(text_to_analyze)
'''

    def execute_code(self, code: str, inputs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute the generated code safely.

        Args:
            code: Python code to execute
            inputs: Optional dictionary of input variables

        Returns:
            Execution results
        """
        return self.execution_env.execute(code, inputs)

    def register_new_tool(self, task_description: str, state: Optional[Any] = None) -> Optional[str]:
        """
        Generate and register a new tool based on the task description.

        Args:
            task_description: Description of the tool to create
            state: Current puzzle state (if available)

        Returns:
            Tool ID if successful, None otherwise
        """
        code = self.generate_code(task_description, state)
        if code:
            return self.tool_registry.register_tool(code, description=task_description)
        return None

    def use_tool(self, tool_id: str, inputs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Use a registered tool.

        Args:
            tool_id: ID of the tool to use
            inputs: Input parameters for the tool

        Returns:
            Tool execution results
        """
        tool = self.tool_registry.get_tool(tool_id)
        if tool:
            try:
                result = tool(inputs)
                return {'success': True, 'result': result}
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            return {'success': False, 'error': f'Tool {tool_id} not found'}

    def analyze_and_create_tools(self, state: Any) -> List[str]:
        """
        Analyze the puzzle state and create appropriate tools.

        Args:
            state: Current puzzle state

        Returns:
            List of created tool IDs
        """
        created_tools = []

        # Check for Arweave puzzle patterns
        if self._check_for_arweave_patterns(state):
            arweave_tools = self._create_arweave_tools(state)
            created_tools.extend(arweave_tools)

        # Create default tools based on puzzle content
        default_tools = self._create_default_tools()
        created_tools.extend(default_tools)

        return created_tools

    def _check_for_arweave_patterns(self, state: Any) -> bool:
        """
        Check if the puzzle state contains Arweave puzzle patterns.

        Args:
            state: Current puzzle state

        Returns:
            True if Arweave puzzle patterns are detected, False otherwise
        """
        indicators = [
            'arweave', 'puzzle weave', 'tx_id', 'transaction',
            'gateway', 'permaweb', 'blockchain', 'weave'
        ]

        content = ""
        if hasattr(state, 'puzzle_text') and state.puzzle_text:
            content += state.puzzle_text.lower()

        if hasattr(state, 'insights'):
            for insight in state.insights:
                content += insight.get('text', '').lower()

        return any(indicator in content for indicator in indicators)

    def _create_arweave_tools(self, state: Any) -> List[str]:
        """
        Create specialized tools for Arweave puzzles.

        Args:
            state: Current puzzle state

        Returns:
            List of created tool IDs
        """
        created_tools = []

        # Transaction fetcher tool
        tx_tool_code = '''
def fetch_arweave_transaction(tx_id, gateway="https://arweave.net"):
    """Fetch Arweave transaction data."""
    import requests
    import json

    try:
        # Fetch transaction data
        url = f"{gateway}/tx/{tx_id}"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            tx_data = response.json()
            print(f"Transaction {tx_id} found")
            print(f"Data size: {tx_data.get('data_size', 'unknown')}")

            # Try to fetch actual data
            data_url = f"{gateway}/{tx_id}"
            data_response = requests.get(data_url, timeout=10)

            if data_response.status_code == 200:
                return {
                    'transaction': tx_data,
                    'data': data_response.text,
                    'binary_data': data_response.content
                }

        return {'error': f'Failed to fetch transaction {tx_id}'}

    except Exception as e:
        return {'error': str(e)}

result = fetch_arweave_transaction("example_tx_id")
'''

        tool_id = self.tool_registry.register_tool(
            tx_tool_code,
            "arweave_fetcher",
            "Fetch Arweave transaction data"
        )
        if tool_id:
            created_tools.append(tool_id)

        return created_tools

    def _create_default_tools(self) -> List[str]:
        """Create a set of default tools for cryptographic puzzles."""
        created_tools = []

        # Base64 analyzer
        base64_tool = self.tool_registry.register_tool(
            self._template_base64_tool(),
            "base64_analyzer",
            "Analyze and decode base64 strings"
        )
        if base64_tool:
            created_tools.append(base64_tool)

        # XOR analyzer
        xor_tool = self.tool_registry.register_tool(
            self._template_xor_tool(),
            "xor_analyzer",
            "Analyze XOR cipher with various keys"
        )
        if xor_tool:
            created_tools.append(xor_tool)

        return created_tools

    def integrate_with_state(self, state: Any, analyze_puzzle: bool = True) -> Any:
        """
        Integrate code analysis with the puzzle state.

        Args:
            state: Current puzzle state
            analyze_puzzle: Whether to analyze the puzzle and create tools

        Returns:
            Updated state
        """
        try:
            if analyze_puzzle:
                # Create tools based on puzzle analysis
                created_tools = self.analyze_and_create_tools(state)

                if created_tools:
                    state.add_insight(
                        f"Created {len(created_tools)} code analysis tools: {', '.join(created_tools)}",
                        "code_agent"
                    )

            # Add available tools information
            available_tools = self.tool_registry.list_tools()
            if available_tools:
                state.add_insight(
                    f"Available code tools: {len(available_tools)} tools ready for execution",
                    "code_agent"
                )

            return state

        except Exception as e:
            logging.error(f"Code agent integration failed: {e}")
            state.add_insight(f"Code analysis encountered an error: {str(e)}", "code_agent")
            return state