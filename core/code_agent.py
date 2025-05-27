"""
Code Agent Module
Handles code analysis and execution for crypto puzzles.
"""

import logging
import re
import ast
import base64
import hashlib
import json
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class CodeAgent:
    """
    Agent responsible for analyzing and executing code found in crypto puzzles.
    """

    def __init__(self, verbose=False):
        """
        Initialize the CodeAgent.
        """
        self.verbose = verbose
        self.name = "CodeAgent"
        logger.debug("CodeAgent initialized")

    def run(self, state):
        """
        Run code analysis on the current state.

        Args:
            state: Current workflow state

        Returns:
            Updated state object
        """
        try:
            if self.verbose:
                logger.info("🔍 Running code analysis...")

            findings_count = 0

            # Analyze all materials for code patterns
            for material_id, material in state.materials.items():
                findings_count += self._analyze_material_code(state, material)

            # Analyze existing findings for code patterns
            findings_count += self._analyze_findings_code(state)

            logger.info(f"Code analysis completed - found {findings_count} insights")

            return state

        except Exception as e:
            logger.error(f"Error in CodeAgent.run: {e}")
            return state

    def _analyze_material_code(self, state, material):
        """Analyze material content for code patterns."""
        findings_count = 0

        try:
            content = material.content

            # Convert to text for analysis
            if isinstance(content, bytes):
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                except:
                    text_content = content.decode('latin-1', errors='ignore')
            else:
                text_content = str(content)

            # Detect different programming languages
            findings_count += self._detect_python_code(state, material, text_content)
            findings_count += self._detect_javascript_code(state, material, text_content)
            findings_count += self._detect_shell_code(state, material, text_content)
            findings_count += self._detect_sql_code(state, material, text_content)
            findings_count += self._detect_assembly_code(state, material, text_content)

            # Look for encoded code
            findings_count += self._detect_encoded_code(state, material, text_content)

            # Analyze crypto-specific code patterns
            findings_count += self._analyze_crypto_code_patterns(state, material, text_content)

        except Exception as e:
            logger.error(f"Error analyzing material code {material.name}: {e}")

        return findings_count

    def _detect_python_code(self, state, material, text):
        """Detect and analyze Python code."""
        findings_count = 0

        try:
            # Python indicators
            python_patterns = [
                r'import\s+\w+',
                r'from\s+\w+\s+import',
                r'def\s+\w+\s*\(',
                r'class\s+\w+\s*\(',
                r'if\s+__name__\s*==\s*["\']__main__["\']',
                r'print\s*\(',
                r'input\s*\(',
            ]

            python_score = 0
            for pattern in python_patterns:
                if re.search(pattern, text):
                    python_score += 1

            if python_score >= 2:
                state.add_insight(f"Python code detected in {material.name} (confidence: {python_score}/7)", "code_agent")
                findings_count += 1

                # Analyze specific Python crypto patterns
                findings_count += self._analyze_python_crypto(state, material, text)

                # Try to extract and execute safe Python code
                findings_count += self._extract_python_expressions(state, text)

        except Exception as e:
            logger.error(f"Error detecting Python code: {e}")

        return findings_count

    def _detect_javascript_code(self, state, material, text):
        """Detect and analyze JavaScript code."""
        findings_count = 0

        try:
            js_patterns = [
                r'function\s+\w+\s*\(',
                r'var\s+\w+\s*=',
                r'let\s+\w+\s*=',
                r'const\s+\w+\s*=',
                r'console\.log\s*\(',
                r'document\.\w+',
                r'window\.\w+',
                r'=>',
            ]

            js_score = 0
            for pattern in js_patterns:
                if re.search(pattern, text):
                    js_score += 1

            if js_score >= 2:
                state.add_insight(f"JavaScript code detected in {material.name} (confidence: {js_score}/8)", "code_agent")
                findings_count += 1

                # Analyze JavaScript crypto patterns
                findings_count += self._analyze_javascript_crypto(state, material, text)

        except Exception as e:
            logger.error(f"Error detecting JavaScript code: {e}")

        return findings_count

    def _detect_shell_code(self, state, material, text):
        """Detect and analyze shell script code."""
        findings_count = 0

        try:
            shell_patterns = [
                r'#!/bin/(?:bash|sh)',
                r'echo\s+',
                r'grep\s+',
                r'sed\s+',
                r'awk\s+',
                r'curl\s+',
                r'wget\s+',
                r'\$\{\w+\}',
            ]

            shell_score = 0
            for pattern in shell_patterns:
                if re.search(pattern, text):
                    shell_score += 1

            if shell_score >= 2:
                state.add_insight(f"Shell script detected in {material.name} (confidence: {shell_score}/8)", "code_agent")
                findings_count += 1

                # Look for crypto-related shell commands
                crypto_commands = re.findall(r'(openssl|gpg|sha256sum|md5sum|bitcoin-cli)\s+[^\n]+', text)
                if crypto_commands:
                    state.add_insight(f"Found {len(crypto_commands)} crypto shell commands", "code_agent")
                    findings_count += 1
                    for cmd in crypto_commands[:3]:
                        state.add_insight(f"Crypto command: {cmd[:50]}...", "code_agent")
                        findings_count += 1

        except Exception as e:
            logger.error(f"Error detecting shell code: {e}")

        return findings_count

    def _detect_sql_code(self, state, material, text):
        """Detect SQL code that might contain crypto data."""
        findings_count = 0

        try:
            sql_patterns = [
                r'SELECT\s+.*FROM',
                r'INSERT\s+INTO',
                r'UPDATE\s+.*SET',
                r'CREATE\s+TABLE',
                r'DROP\s+TABLE',
            ]

            sql_score = 0
            for pattern in sql_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    sql_score += 1

            if sql_score >= 1:
                state.add_insight(f"SQL code detected in {material.name}", "code_agent")
                findings_count += 1

                # Look for crypto-related table/column names
                crypto_sql_terms = ['wallet', 'address', 'private_key', 'public_key', 'hash', 'signature']
                found_terms = [term for term in crypto_sql_terms if term in text.lower()]
                if found_terms:
                    state.add_insight(f"SQL contains crypto terms: {', '.join(found_terms)}", "code_agent")
                    findings_count += 1

        except Exception as e:
            logger.error(f"Error detecting SQL code: {e}")

        return findings_count

    def _detect_assembly_code(self, state, material, text):
        """Detect assembly code that might be relevant."""
        findings_count = 0

        try:
            asm_patterns = [
                r'\b(mov|add|sub|mul|div|jmp|call|ret|push|pop)\s+',
                r'\b(eax|ebx|ecx|edx|rax|rbx|rcx|rdx)\b',
                r'\.section\s+',
                r'\.global\s+',
            ]

            asm_score = 0
            for pattern in asm_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    asm_score += 1

            if asm_score >= 2:
                state.add_insight(f"Assembly code detected in {material.name}", "code_agent")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error detecting assembly code: {e}")

        return findings_count

    def _detect_encoded_code(self, state, material, text):
        """Detect base64 or hex encoded code."""
        findings_count = 0

        try:
            # Look for base64 encoded content that might be code
            base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
            base64_matches = re.findall(base64_pattern, text)

            for match in base64_matches:
                try:
                    decoded = base64.b64decode(match)
                    decoded_text = decoded.decode('utf-8', errors='ignore')

                    # Check if decoded content looks like code
                    if self._looks_like_code(decoded_text):
                        state.add_insight(f"Base64 encoded code found: {decoded_text[:50]}...", "code_agent")
                        findings_count += 1

                        # Recursively analyze the decoded code
                        findings_count += self._analyze_material_code(state, type('obj', (object,), {
                            'name': f"{material.name}_decoded",
                            'content': decoded_text
                        })())

                except:
                    pass  # Not valid base64 or not text

            # Look for hex encoded content
            hex_pattern = r'\b[0-9a-fA-F]{40,}\b'
            hex_matches = re.findall(hex_pattern, text)

            for match in hex_matches:
                try:
                    if len(match) % 2 == 0:  # Even length for valid hex
                        decoded = bytes.fromhex(match)
                        decoded_text = decoded.decode('utf-8', errors='ignore')

                        if self._looks_like_code(decoded_text):
                            state.add_insight(f"Hex encoded code found: {decoded_text[:50]}...", "code_agent")
                            findings_count += 1

                except:
                    pass  # Not valid hex or not text

        except Exception as e:
            logger.error(f"Error detecting encoded code: {e}")

        return findings_count

    def _analyze_python_crypto(self, state, material, text):
        """Analyze Python code for crypto operations."""
        findings_count = 0

        try:
            # Look for crypto library imports
            crypto_imports = re.findall(r'import\s+(hashlib|cryptography|Crypto|ecdsa|bitcoin|web3|eth_account)', text)
            if crypto_imports:
                state.add_insight(f"Python imports crypto libraries: {', '.join(crypto_imports)}", "code_agent")
                findings_count += 1

            # Look for hash operations
            hash_operations = re.findall(r'(sha256|md5|blake2b|keccak)\s*\([^)]*\)', text)
            if hash_operations:
                state.add_insight(f"Python performs hash operations: {len(hash_operations)} found", "code_agent")
                findings_count += 1

            # Look for key generation
            if re.search(r'generate.*key|new.*key|create.*key', text, re.IGNORECASE):
                state.add_insight("Python code generates cryptographic keys", "code_agent")
                findings_count += 1

            # Look for Bitcoin/Ethereum specific operations
            if re.search(r'bitcoin|btc|satoshi', text, re.IGNORECASE):
                state.add_insight("Python code contains Bitcoin-related operations", "code_agent")
                findings_count += 1

            if re.search(r'ethereum|eth|wei|gwei', text, re.IGNORECASE):
                state.add_insight("Python code contains Ethereum-related operations", "code_agent")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing Python crypto: {e}")

        return findings_count

    def _analyze_javascript_crypto(self, state, material, text):
        """Analyze JavaScript code for crypto operations."""
        findings_count = 0

        try:
            # Look for crypto libraries
            if re.search(r'crypto-js|bitcoinjs|web3|ethers', text, re.IGNORECASE):
                state.add_insight("JavaScript uses crypto libraries", "code_agent")
                findings_count += 1

            # Look for browser crypto API usage
            if re.search(r'crypto\.subtle|window\.crypto', text):
                state.add_insight("JavaScript uses Web Crypto API", "code_agent")
                findings_count += 1

            # Look for base64 operations
            if re.search(r'btoa\(|atob\(', text):
                state.add_insight("JavaScript performs base64 encoding/decoding", "code_agent")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing JavaScript crypto: {e}")

        return findings_count

    def _analyze_crypto_code_patterns(self, state, material, text):
        """Analyze general crypto-related code patterns."""
        findings_count = 0

        try:
            # Look for common crypto constants
            crypto_constants = [
                r'0x[a-fA-F0-9]{64}',  # 256-bit hex values
                r'[a-fA-F0-9]{64}',    # 64 character hex strings
                r'secp256k1',          # Elliptic curve
                r'P-256|P-384|P-521',  # NIST curves
            ]

            for pattern in crypto_constants:
                matches = re.findall(pattern, text)
                if matches:
                    state.add_insight(f"Found {len(matches)} crypto constants matching {pattern}", "code_agent")
                    findings_count += 1

            # Look for wallet-related code patterns
            wallet_patterns = [
                r'private.*key',
                r'public.*key',
                r'mnemonic.*phrase',
                r'seed.*phrase',
                r'derivation.*path',
                r'address.*generation',
            ]

            for pattern in wallet_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    state.add_insight(f"Code contains wallet-related pattern: {pattern}", "code_agent")
                    findings_count += 1

            # Look for encoding/decoding operations
            encoding_patterns = [
                r'base58|base64|hex|binary',
                r'encode|decode',
                r'serialize|deserialize',
            ]

            encoding_matches = 0
            for pattern in encoding_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    encoding_matches += 1

            if encoding_matches >= 2:
                state.add_insight("Code performs multiple encoding/decoding operations", "code_agent")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing crypto code patterns: {e}")

        return findings_count

    def _extract_python_expressions(self, state, text):
        """Extract and safely evaluate simple Python expressions."""
        findings_count = 0

        try:
            # Look for simple print statements with string literals
            print_pattern = r'print\s*\(\s*["\']([^"\']+)["\']\s*\)'
            print_matches = re.findall(print_pattern, text)

            for match in print_matches:
                state.add_insight(f"Python print output: {match}", "code_agent")
                findings_count += 1

            # Look for simple variable assignments with string/number values
            assignment_pattern = r'(\w+)\s*=\s*["\']([^"\']+)["\']'
            assignments = re.findall(assignment_pattern, text)

            for var_name, value in assignments:
                if len(value) > 10 and any(char.isalnum() for char in value):
                    state.add_insight(f"Python variable {var_name} = {value[:30]}...", "code_agent")
                    findings_count += 1

            # Look for hex/int conversions
            hex_pattern = r'int\s*\(\s*["\']([a-fA-F0-9]+)["\']\s*,\s*16\s*\)'
            hex_matches = re.findall(hex_pattern, text)

            for hex_val in hex_matches:
                try:
                    decimal_val = int(hex_val, 16)
                    state.add_insight(f"Hex conversion: {hex_val} = {decimal_val}", "code_agent")
                    findings_count += 1
                except:
                    pass

        except Exception as e:
            logger.error(f"Error extracting Python expressions: {e}")

        return findings_count

    def _analyze_findings_code(self, state):
        """Analyze existing findings for code patterns."""
        findings_count = 0

        try:
            for finding in state.findings:
                text = finding.description

                # Check if finding mentions code-related terms
                code_keywords = ['code', 'script', 'function', 'program', 'execute', 'compile']
                if any(keyword in text.lower() for keyword in code_keywords):
                    # Re-analyze this finding as potential code
                    if self._looks_like_code(text):
                        state.add_insight(f"Finding contains code-like content: {finding.title}", "code_agent")
                        findings_count += 1

                        # Create a temporary material to analyze the code
                        temp_material = type('obj', (object,), {
                            'name': f"finding_{finding.id}",
                            'content': text
                        })()

                        findings_count += self._analyze_material_code(state, temp_material)

        except Exception as e:
            logger.error(f"Error analyzing findings for code: {e}")

        return findings_count

    def _looks_like_code(self, text):
        """Determine if text looks like code."""
        try:
            code_indicators = [
                r'[{}()\[\];]',           # Common code punctuation
                r'=\s*["\']',             # String assignments
                r'if\s*\(',               # Conditional statements
                r'for\s*\(',              # Loops
                r'function\s*\(',         # Function definitions
                r'def\s+\w+\s*\(',        # Python functions
                r'import\s+\w+',          # Imports
                r'#include\s*<',          # C includes
                r'//.*$',                 # C-style comments
                r'#.*$',                  # Script comments
            ]

            score = 0
            for pattern in code_indicators:
                if re.search(pattern, text, re.MULTILINE):
                    score += 1

            # Also check for high concentration of special characters
            special_chars = sum(1 for c in text if c in '{}()[];=<>+-*/&|^%!')
            if len(text) > 0:
                special_ratio = special_chars / len(text)
                if special_ratio > 0.05:  # More than 5% special characters
                    score += 1

            return score >= 2

        except Exception as e:
            logger.error(f"Error checking if text looks like code: {e}")
            return False

    def analyze_code_snippet(self, code_snippet, language=None):
        """
        Analyze a specific code snippet.

        Args:
            code_snippet: String containing code to analyze
            language: Optional language hint (python, javascript, etc.)

        Returns:
            Dictionary with analysis results
        """
        try:
            result = {
                'language': language or 'unknown',
                'lines': len(code_snippet.split('\n')),
                'contains_crypto': self._check_crypto_patterns(code_snippet),
                'insights': []
            }

            # Detect language if not provided
            if language is None:
                if self._looks_like_python(code_snippet):
                    result['language'] = 'python'
                elif self._looks_like_javascript(code_snippet):
                    result['language'] = 'javascript'
                elif self._looks_like_shell(code_snippet):
                    result['language'] = 'shell'

            # Add specific insights based on language
            if result['language'] == 'python':
                result['insights'].extend(self._get_python_insights(code_snippet))
            elif result['language'] == 'javascript':
                result['insights'].extend(self._get_javascript_insights(code_snippet))

            return result

        except Exception as e:
            logger.error(f"Error analyzing code snippet: {e}")
            return {'error': str(e)}

    def _check_crypto_patterns(self, code):
        """
        Check if code contains cryptographic patterns.

        Args:
            code: Code string to analyze

        Returns:
            Boolean indicating if crypto patterns were found
        """
        crypto_keywords = [
            'encrypt', 'decrypt', 'hash', 'sha256', 'md5',
            'aes', 'rsa', 'base64', 'cipher', 'crypto',
            'bitcoin', 'wallet', 'private_key', 'public_key',
            'ecdsa', 'secp256k1', 'mnemonic', 'seed'
        ]

        code_lower = code.lower()
        return any(keyword in code_lower for keyword in crypto_keywords)

    def _looks_like_python(self, text):
        """Check if text looks like Python code."""
        python_keywords = ['import', 'def ', 'class ', 'if __name__', 'print(']
        return any(keyword in text for keyword in python_keywords)

    def _looks_like_javascript(self, text):
        """Check if text looks like JavaScript code."""
        js_keywords = ['function', 'var ', 'let ', 'const ', 'console.log']
        return any(keyword in text for keyword in js_keywords)

    def _looks_like_shell(self, text):
        """Check if text looks like shell script."""
        shell_keywords = ['#!/bin/', 'echo ', 'grep ', 'curl ']
        return any(keyword in text for keyword in shell_keywords)

    def _get_python_insights(self, code):
        """Get Python-specific insights."""
        insights = []

        if 'hashlib' in code:
            insights.append("Uses Python hashlib for cryptographic hashing")
        if 'base64' in code:
            insights.append("Performs base64 encoding/decoding")
        if 'bitcoin' in code.lower():
            insights.append("Contains Bitcoin-related operations")

        return insights

    def _get_javascript_insights(self, code):
        """Get JavaScript-specific insights."""
        insights = []

        if 'crypto' in code.lower():
            insights.append("Uses JavaScript crypto operations")
        if 'btoa(' in code or 'atob(' in code:
            insights.append("Performs base64 encoding/decoding")

        return insights