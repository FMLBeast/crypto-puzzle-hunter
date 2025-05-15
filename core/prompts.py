"""
Prompts used for the Crypto Hunter agent.
"""

# State assessment prompt (used to analyze the current state of the puzzle)
STATE_ASSESSMENT_PROMPT = """
You are an expert cryptographer analyzing a cryptographic puzzle. 
Given the information below, provide a concise assessment of the puzzle.

Current state summary:
{state_summary}

Transformations applied:
{transformations}

Insights gathered:
{insights}

Patterns from similar puzzles:
{patterns}

Sample of puzzle content:
{puzzle_content}

Your task is to:
1. Identify the likely type of cryptographic challenge
2. Assess how close we are to a solution
3. Note any patterns or clues you can observe
4. Consider how patterns from similar puzzles might apply to this one
5. Suggest what might be the next step to solve this

Provide a detailed but concise assessment:
"""

# Strategy selection prompt (used to determine the next analysis strategy)
STRATEGY_SELECTION_PROMPT = """
You are an expert cryptographer solving a cryptographic puzzle.
Based on the current state and assessment, determine the best strategy to proceed.

Current state summary:
{state_summary}

Assessment:
{assessment}

Transformations applied:
{transformations}

Insights gathered:
{insights}

Patterns from similar puzzles:
{patterns}

Previous chat history:
{chat_history}

Your task is to select the next analysis strategy. 
Consider how patterns from similar puzzles might inform your strategy selection.
Look for techniques that worked in similar puzzles and apply them to this one.

Return your answer in this format:

```json
{{
  "strategy": "Brief description of the strategy",
  "analyzer": "name_of_analyzer_to_use",
  "params": {{
    "param1": "value1",
    "param2": "value2"
  }}
}}
```

Available analyzers:
- text_analyzer: For analyzing text patterns and encodings
- binary_analyzer: For analyzing binary data
- image_analyzer: For analyzing images (steganography)
- cipher_analyzer: For detecting and solving classical ciphers
- encoding_analyzer: For detecting and decoding various encodings
- blockchain_analyzer: For analyzing crypto addresses and data
- hash_analyzer: For analyzing and potentially cracking hashes

Think step by step and choose the most promising approach:
"""

# Direct solution prompt (used for final solution attempts)
DIRECT_SOLUTION_PROMPT = """
You are an expert cryptographer. After several analysis steps, you're now trying 
to directly solve this cryptographic puzzle. Review all information and provide 
your best solution attempt.

Current state summary:
{state_summary}

Patterns from similar puzzles:
{patterns}

Puzzle content:
{puzzle_content}

Analyze all the information carefully and try to solve the puzzle directly.
Pay special attention to patterns from similar puzzles - they may contain valuable 
techniques or approaches that worked in similar situations.

If you can determine a solution, clearly mark it with "SOLUTION:" at the beginning of that line.

If you need more analysis or can't solve it yet, explain what additional steps might help.

Your solution attempt:
"""

# Fallback texts (used when no LLM is available)
FALLBACK_STATE_ASSESSMENT_TEXT = """
This appears to be a {file_type} file of {file_size} bytes. Without LLM assistance, 
I'll try to apply basic cryptographic analysis techniques. This might include checking 
for common encodings, ciphers, or steganography techniques depending on the file type.
"""

FALLBACK_STRATEGY_SELECTION_TEXT = """
Since I'm operating in fallback mode without LLM assistance, I'll apply a sequence of 
standard analyzers to attempt to decode or extract information from this puzzle. This 
includes checking for common encodings (Base64, Hex), simple substitution ciphers, 
and file-specific analysis based on the file type.
"""

FALLBACK_DIRECT_SOLUTION_TEXT = """
Without LLM assistance, I've applied basic analysis techniques. For text puzzles, 
consider common techniques like: Caesar cipher, ROT13, Base64, Hex encoding, Binary 
encoding, or ASCII representation. For images, check for steganography using tools 
like steghide or examine metadata. For binary files, analyze file signatures and 
structures using hexdump. Also consider patterns from similar puzzles that might 
provide insights into techniques that worked in similar situations.
"""
