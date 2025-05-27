"""
VM Agent Module
Handles virtual machine execution and code analysis for crypto puzzles.
"""

import logging
import re
import ast
import base64
import subprocess
import tempfile
import os
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class VMAgent:
    """
    Agent responsible for virtual machine execution and code analysis.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.name = "VMAgent"
        logger.debug("VMAgent initialized")

    def run(self, state):
        try:
            if self.verbose:
                logger.info("🔍 Running VM analysis...")

            findings_count = 0

            # Analyze all materials for executable content
            for material_id, material in state.materials.items():
                findings_count += self._analyze_material(state, material)

            # Look for code in existing findings
            findings_count += self._analyze_findings(state)

            logger.info(f"VM analysis completed - found {findings_count} insights")
            return state

        except Exception as e:
            logger.error(f"Error in VMAgent.run: {e}")
            return state

    def _analyze_material(self, state, material):
        """Analyze material for executable content."""
        findings_count = 0

        try:
            content = material.content

            # Check if material is an executable file
            if isinstance(content, bytes):
                findings_count += self._analyze_binary_executable(state, material, content)

                # Try to extract embedded scripts
                findings_count += self._extract_embedded_scripts(state, material, content)

            # Check for script content
            findings_count += self._analyze_script_content(state, material, content)

        except Exception as e:
            logger.error(f"Error analyzing material {material.name}: {e}")

        return findings_count

    def _analyze_binary_executable(self, state, material, data):
        """Analyze binary executable files."""
        findings_count = 0

        try:
            # Check for executable file signatures
            if data.startswith(b'\x7fELF'):
                state.add_insight(f"{material.name} is a Linux ELF executable", "vm_agent")
                findings_count += 1
                findings_count += self._analyze_elf_file(state, material, data)

            elif data.startswith(b'MZ'):
                state.add_insight(f"{material.name} is a Windows PE executable", "vm_agent")
                findings_count += 1
                findings_count += self._analyze_pe_file(state, material, data)

            elif data.startswith(b'\xCA\xFE\xBA\xBE'):
                state.add_insight(f"{material.name} is a Java class file", "vm_agent")
                findings_count += 1

            # Check for script interpreters
            elif data.startswith(b'#!/'):
                state.add_insight(f"{material.name} is a script with shebang", "vm_agent")
                findings_count += 1
                findings_count += self._analyze_script_file(state, material, data)

        except Exception as e:
            logger.error(f"Error analyzing binary executable: {e}")

        return findings_count

    def _analyze_elf_file(self, state, material, data):
        """Analyze ELF executable file."""
        findings_count = 0

        try:
            # Extract strings from ELF file
            strings = self._extract_strings(data)
            crypto_strings = [s for s in strings if self._is_crypto_related_string(s)]

            if crypto_strings:
                state.add_insight(f"ELF file contains {len(crypto_strings)} crypto-related strings", "vm_agent")
                findings_count += 1

                for crypto_str in crypto_strings[:5]:
                    state.add_insight(f"Crypto string in ELF: {crypto_str[:50]}", "vm_agent")
                    findings_count += 1

            # Look for URLs or network-related strings
            urls = [s for s in strings if self._is_url(s)]
            if urls:
                state.add_insight(f"ELF file contains {len(urls)} URLs", "vm_agent")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing ELF file: {e}")

        return findings_count

    def _analyze_pe_file(self, state, material, data):
        """Analyze PE (Windows) executable file."""
        findings_count = 0

        try:
            # Extract strings from PE file
            strings = self._extract_strings(data)

            # Look for interesting patterns
            registry_keys = [s for s in strings if 'HKEY_' in s or 'Registry' in s]
            if registry_keys:
                state.add_insight(f"PE file accesses {len(registry_keys)} registry keys", "vm_agent")
                findings_count += 1

            # Look for crypto libraries
            crypto_libs = [s for s in strings if
                           any(lib in s.lower() for lib in ['crypto', 'openssl', 'bcrypt', 'advapi32'])]
            if crypto_libs:
                state.add_insight(f"PE file uses {len(crypto_libs)} crypto libraries", "vm_agent")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing PE file: {e}")

        return findings_count

    def _analyze_script_file(self, state, material, data):
        """Analyze script files with shebang."""
        findings_count = 0

        try:
            # Extract shebang line
            lines = data.decode('utf-8', errors='ignore').split('\n')
            if lines and lines[0].startswith('#!'):
                interpreter = lines[0][2:].strip()
                state.add_insight(f"Script uses interpreter: {interpreter}", "vm_agent")
                findings_count += 1

                # Analyze script content based on interpreter
                if 'python' in interpreter.lower():
                    findings_count += self._analyze_python_script(state, material, '\n'.join(lines[1:]))
                elif 'bash' in interpreter.lower() or 'sh' in interpreter.lower():
                    findings_count += self._analyze_shell_script(state, material, '\n'.join(lines[1:]))
                elif 'node' in interpreter.lower():
                    findings_count += self._analyze_javascript_script(state, material, '\n'.join(lines[1:]))

        except Exception as e:
            logger.error(f"Error analyzing script file: {e}")

        return findings_count

    def _extract_embedded_scripts(self, state, material, data):
        """Extract embedded scripts from binary data."""
        findings_count = 0

        try:
            # Look for common script patterns in binary data
            text_data = data.decode('utf-8', errors='ignore')

            # Python code patterns
            if re.search(r'import\s+\w+|def\s+\w+\s*\(|print\s*\(', text_data):
                state.add_insight(f"Found embedded Python code in {material.name}", "vm_agent")
                findings_count += 1
                findings_count += self._analyze_python_script(state, material, text_data)

            # JavaScript patterns
            if re.search(r'function\s+\w+\s*\(|console\.log|require\s*\(', text_data):
                state.add_insight(f"Found embedded JavaScript code in {material.name}", "vm_agent")
                findings_count += 1
                findings_count += self._analyze_javascript_script(state, material, text_data)

            # Shell script patterns
            if re.search(r'#!/bin/|echo\s+|grep\s+|curl\s+', text_data):
                state.add_insight(f"Found embedded shell script in {material.name}", "vm_agent")
                findings_count += 1
                findings_count += self._analyze_shell_script(state, material, text_data)

        except Exception as e:
            logger.error(f"Error extracting embedded scripts: {e}")

        return findings_count

    def _analyze_script_content(self, state, material, content):
        """Analyze content for script-like patterns."""
        findings_count = 0

        try:
            if isinstance(content, bytes):
                text_content = content.decode('utf-8', errors='ignore')
            else:
                text_content = str(content)

            # Check for various script languages
            if self._looks_like_python(text_content):
                state.add_insight(f"{material.name} contains Python-like code", "vm_agent")
                findings_count += 1
                findings_count += self._analyze_python_script(state, material, text_content)

            elif self._looks_like_javascript(text_content):
                state.add_insight(f"{material.name} contains JavaScript-like code", "vm_agent")
                findings_count += 1
                findings_count += self._analyze_javascript_script(state, material, text_content)

            elif self._looks_like_shell(text_content):
                state.add_insight(f"{material.name} contains shell script-like code", "vm_agent")
                findings_count += 1
                findings_count += self._analyze_shell_script(state, material, text_content)

        except Exception as e:
            logger.error(f"Error analyzing script content: {e}")

        return findings_count

    def _analyze_python_script(self, state, material, code):
        """Analyze Python script code."""
        findings_count = 0

        try:
            # Look for crypto-related imports
            crypto_imports = re.findall(r'import\s+(hashlib|cryptography|Crypto|ecdsa|bitcoin|web3)', code)
            if crypto_imports:
                state.add_insight(f"Python code imports crypto libraries: {', '.join(crypto_imports)}", "vm_agent")
                findings_count += 1

            # Look for key generation or crypto operations
            crypto_functions = re.findall(r'(sha256|md5|encrypt|decrypt|sign|verify|generate_key)', code)
            if crypto_functions:
                state.add_insight(f"Python code calls crypto functions: {', '.join(set(crypto_functions))}", "vm_agent")
                findings_count += 1

            # Look for base64 operations
            if re.search(r'base64\.(encode|decode|b64encode|b64decode)', code):
                state.add_insight("Python code performs base64 encoding/decoding", "vm_agent")
                findings_count += 1

            # Try safe execution of simple expressions
            findings_count += self._safe_execute_python(state, code)

        except Exception as e:
            logger.error(f"Error analyzing Python script: {e}")

        return findings_count

    def _analyze_javascript_script(self, state, material, code):
        """Analyze JavaScript code."""
        findings_count = 0

        try:
            # Look for crypto operations
            if re.search(r'crypto\.|CryptoJS|bitcoin|ethereum', code):
                state.add_insight("JavaScript code contains crypto operations", "vm_agent")
                findings_count += 1

            # Look for base64 operations
            if re.search(r'btoa\(|atob\(|Buffer\.from.*base64', code):
                state.add_insight("JavaScript code performs base64 operations", "vm_agent")
                findings_count += 1

            # Look for HTTP requests that might fetch crypto data
            if re.search(r'fetch\(|XMLHttpRequest|axios|blockchain\.info|blockchair', code):
                state.add_insight("JavaScript code makes external HTTP requests", "vm_agent")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing JavaScript: {e}")

        return findings_count

    def _analyze_shell_script(self, state, material, code):
        """Analyze shell script code."""
        findings_count = 0

        try:
            # Look for crypto tools
            crypto_tools = re.findall(r'(openssl|gpg|sha256sum|md5sum|bitcoin-cli)', code)
            if crypto_tools:
                state.add_insight(f"Shell script uses crypto tools: {', '.join(set(crypto_tools))}", "vm_agent")
                findings_count += 1

            # Look for network operations
            if re.search(r'curl|wget|nc\s|netcat', code):
                state.add_insight("Shell script performs network operations", "vm_agent")
                findings_count += 1

            # Look for file operations that might reveal crypto data
            if re.search(r'cat\s+.*\.(key|pem|wallet)|grep.*private', code):
                state.add_insight("Shell script accesses crypto-related files", "vm_agent")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing shell script: {e}")

        return findings_count

    def _analyze_findings(self, state):
        """Analyze existing findings for executable content."""
        findings_count = 0

        try:
            for finding in state.findings:
                # Look for code-like content in findings
                if any(keyword in finding.description.lower() for keyword in ['code', 'script', 'function', 'execute']):
                    # Re-analyze this finding for executable content
                    if self._looks_like_python(finding.description):
                        findings_count += self._analyze_python_script(state, None, finding.description)

        except Exception as e:
            logger.error(f"Error analyzing findings: {e}")

        return findings_count

    def _safe_execute_python(self, state, code):
        """Safely execute simple Python expressions."""
        findings_count = 0

        try:
            # Only execute very simple, safe expressions
            safe_patterns = [
                r'print\s*\(\s*["\']([^"\']+)["\']\s*\)',  # print("string")
                r'(\d+)\s*\+\s*(\d+)',  # simple arithmetic
                r'hex\s*\(\s*(\d+)\s*\)',  # hex conversion
                r'int\s*\(\s*["\']([a-fA-F0-9]+)["\']\s*,\s*16\s*\)',  # hex to int
            ]

            for pattern in safe_patterns:
                matches = re.findall(pattern, code)
                for match in matches:
                    if isinstance(match, tuple):
                        if pattern.endswith(r'(\d+)\s*\)'):  # hex conversion
                            try:
                                result = hex(int(match[0]))
                                state.add_insight(f"Python expression hex({match[0]}) = {result}", "vm_agent")
                                findings_count += 1
                            except:
                                pass
                        elif pattern.endswith(r'(\d+)'):  # arithmetic
                            try:
                                result = int(match[0]) + int(match[1])
                                state.add_insight(f"Python arithmetic: {match[0]} + {match[1]} = {result}", "vm_agent")
                                findings_count += 1
                            except:
                                pass
                    else:
                        state.add_insight(f"Python output: {match}", "vm_agent")
                        findings_count += 1

        except Exception as e:
            logger.error(f"Error in safe Python execution: {e}")

        return findings_count

    def _extract_strings(self, data, min_length=4):
        """Extract printable strings from binary data."""
        strings = []
        current_string = ""

        try:
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                    current_string = ""

            if len(current_string) >= min_length:
                strings.append(current_string)

        except Exception as e:
            logger.error(f"Error extracting strings: {e}")

        return strings

    def _is_crypto_related_string(self, text):
        """Check if string is crypto-related."""
        crypto_keywords = [
            'bitcoin', 'btc', 'ethereum', 'eth', 'crypto', 'wallet', 'private',
            'key', 'hash', 'sha256', 'md5', 'encrypt', 'decrypt', 'signature',
            'blockchain', 'address', 'satoshi', 'wei', 'gwei'
        ]
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in crypto_keywords)

    def _is_url(self, text):
        """Check if string is a URL."""
        return re.match(r'https?://[^\s]+', text) is not None

    def _looks_like_python(self, text):
        """Check if text looks like Python code."""
        python_keywords = ['import', 'def ', 'class ', 'if __name__', 'print(', 'for ', 'while ', 'try:', 'except:']
        return any(keyword in text for keyword in python_keywords)

    def _looks_like_javascript(self, text):
        """Check if text looks like JavaScript code."""
        js_keywords = ['function', 'var ', 'let ', 'const ', 'console.log', 'document.', 'window.', '=>']
        return any(keyword in text for keyword in js_keywords)

    def _looks_like_shell(self, text):
        """Check if text looks like shell script."""
        shell_keywords = ['#!/bin/', 'echo ', 'grep ', 'sed ', 'awk ', 'curl ', 'wget ', 'cat ', 'ls ']
        return any(keyword in text for keyword in shell_keywords)