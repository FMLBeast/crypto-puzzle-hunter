"""
Enhanced State module for the Crypto Hunter.
Tracks the state of puzzle analysis including insights and transformations.
Improved handling of extracted text and steganography results.
"""

import os
import time
import mimetypes
import re
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field

from core.logger import solution_logger

@dataclass
class State:
    puzzle_file: Optional[str] = None
    puzzle_text: Optional[str] = None
    binary_data: Optional[bytes] = None
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    hash: Optional[str] = None
    status: str = "analyzing"

    related_files: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    clues: List[Dict[str, Any]] = field(default_factory=list)
    patterns: List[Dict[str, Any]] = field(default_factory=list)

    insights: List[Dict[str, Any]] = field(default_factory=list)
    transformations: List[Dict[str, Any]] = field(default_factory=list)

    solution: Optional[str] = None
    puzzle_type: Optional[str] = None

    # Track which analyzers we've already tried (to avoid immediate repeats)
    analyzers_used: Set[str] = field(default_factory=set)

    def __post_init__(self):
        if self.puzzle_file:
            self._load_file()

    def _load_file(self):
        """Load puzzle_file into binary_data or puzzle_text based on type."""
        try:
            path = Path(self.puzzle_file)

            if not path.exists():
                return

            self.file_size = path.stat().st_size
            self.file_type, _ = mimetypes.guess_type(path.name)

            # Calculate hash
            with open(path, 'rb') as f:
                data = f.read()
                self.hash = hashlib.sha256(data).hexdigest()[:16]

            # Determine if it's text or binary
            if self.file_type and self.file_type.startswith("text"):
                try:
                    txt = path.read_text(errors="ignore")
                    self.set_puzzle_text(txt)
                except:
                    # Fallback to binary if text reading fails
                    self.set_binary_data(data)
            else:
                self.set_binary_data(data)

        except Exception as e:
            self.add_insight("system", f"Error loading file: {e}")

    def add_insight(self, text: str, analyzer: str) -> None:
        """Add an insight with proper formatting"""
        ts = time.strftime("%H:%M:%S")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        insight = {
            "time": ts,
            "timestamp": timestamp,
            "analyzer": analyzer,
            "message": text,
            "text": text  # Backward compatibility
        }

        self.insights.append(insight)
        self.analyzers_used.add(analyzer)

        # Log to solution logger
        solution_logger.log_insight(text, analyzer, ts)

    def add_transformation(self, name: str, description: str,
                           input_data: Any, output_data: Any,
                           analyzer: str) -> None:
        """Add a transformation with enhanced handling of extracted text"""
        ts = time.strftime("%H:%M:%S")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        transformation = {
            "time": ts,
            "timestamp": timestamp,
            "name": name,
            "description": description,
            "input_data": str(input_data),
            "output_data": str(output_data),
            "analyzer": analyzer
        }

        self.transformations.append(transformation)

        # Log to solution logger
        solution_logger.log_transformation(name, description, input_data, output_data, analyzer, ts)

        # Enhanced text promotion logic
        if self._should_promote_to_puzzle_text(name, output_data):
            self.set_puzzle_text(str(output_data))

    def _should_promote_to_puzzle_text(self, name: str, output_data: Any) -> bool:
        """Determine if transformation output should be promoted to puzzle_text"""
        if not output_data or not isinstance(output_data, str):
            return False

        # Current puzzle text exists and is longer
        if self.puzzle_text and len(self.puzzle_text) > len(output_data):
            return False

        # High-priority extraction methods that should be promoted
        high_priority_extractions = [
            "PNG Text Chunks",
            "Image Text Extraction",
            "LSB Steganography",
            "Advanced Steganography",
            "EXIF Metadata",
            "Steganography Extraction"
        ]

        # Check if this is a high-priority extraction
        if any(priority in name for priority in high_priority_extractions):
            # Additional checks for meaningful content
            clean_text = output_data.strip()

            # Must be substantial content
            if len(clean_text) < 10:
                return False

            # Check for flag-like patterns or meaningful content
            meaningful_indicators = [
                'flag{', 'ctf{', 'key:', 'password:', 'secret:', 'message:',
                'solution:', 'answer:', 'hint:', 'clue:'
            ]

            if any(indicator in clean_text.lower() for indicator in meaningful_indicators):
                return True

            # Check if it's mostly printable and has some structure
            printable_ratio = sum(c.isprintable() for c in clean_text) / len(clean_text)
            if printable_ratio > 0.8 and any(c.isalpha() for c in clean_text):
                return True

        return False

    def set_puzzle_text(self, txt: str) -> None:
        """Set puzzle text and log the change"""
        if not txt or not txt.strip():
            return

        clean_text = txt.strip()

        # Only update if it's different and substantial
        if self.puzzle_text != clean_text and len(clean_text) > 5:
            self.puzzle_text = clean_text
            self.add_insight("system", f"Puzzle text updated ({len(clean_text)} chars)")

            # Try to determine puzzle type from content
            self._infer_puzzle_type()

    def set_binary_data(self, data: bytes) -> None:
        """Store binary data and record insight"""
        if not data:
            return

        self.binary_data = data
        self.file_size = len(data)

        # Calculate hash if not already set
        if not self.hash:
            self.hash = hashlib.sha256(data).hexdigest()[:16]

        self.add_insight("system", f"Binary data set ({self.file_size} bytes)")

    def set_solution(self, sol: str) -> None:
        """Record the solution and log it"""
        if not sol or not sol.strip():
            return

        clean_solution = sol.strip()
        self.solution = clean_solution
        self.status = "solved"

        self.add_insight("system", f"Solution found: {clean_solution}")
        solution_logger.log_solution(clean_solution)

    def add_related_file(self, filename: str, content: bytes) -> None:
        """Add a related file with metadata"""
        if not content:
            return

        sha = hashlib.sha256(content).hexdigest()

        # Try to extract text content if possible
        text_content = None
        try:
            if self._is_likely_text(content):
                text_content = content.decode('utf-8', errors='ignore')
        except:
            pass

        file_info = {
            "content": content,
            "size": len(content),
            "sha256": sha,
        }

        if text_content:
            file_info["text_content"] = text_content

        self.related_files[filename] = file_info

    def add_clue(self, text: str, source: str) -> None:
        """Add a clue with source information"""
        clue = {
            "text": text,
            "file": source,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.clues.append(clue)

    def add_pattern(self, text: str, source: str, category: str) -> None:
        """Add a pattern from similar puzzles"""
        pattern = {
            "text": text,
            "file": source,
            "category": category,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.patterns.append(pattern)

    def _is_likely_text(self, data: bytes) -> bool:
        """Check if binary data is likely to be text"""
        if not data:
            return False

        # Sample first 1000 bytes
        sample = data[:1000]

        # Check for high ratio of printable characters
        printable_count = sum(32 <= b <= 126 or b in (9, 10, 13) for b in sample)

        return printable_count / len(sample) > 0.8

    def _infer_puzzle_type(self) -> None:
        """Try to infer the puzzle type from available data"""
        if not self.puzzle_text:
            return

        text_lower = self.puzzle_text.lower()

        # Check for common puzzle indicators
        if any(pattern in text_lower for pattern in ['base64', 'encoded', 'decode']):
            self.puzzle_type = "encoding"
        elif any(pattern in text_lower for pattern in ['cipher', 'encrypt', 'decrypt']):
            self.puzzle_type = "cipher"
        elif any(pattern in text_lower for pattern in ['hash', 'checksum', 'digest']):
            self.puzzle_type = "hash"
        elif any(pattern in text_lower for pattern in ['steganography', 'hidden', 'lsb']):
            self.puzzle_type = "steganography"
        elif re.search(r'0x[a-fA-F0-9]{40}', self.puzzle_text):
            self.puzzle_type = "blockchain"
        elif self.file_type and self.file_type.startswith('image/'):
            self.puzzle_type = "image_steganography"
        else:
            self.puzzle_type = "unknown"

    def is_binary(self) -> bool:
        """Check if state contains binary data"""
        return self.binary_data is not None

    def is_text(self) -> bool:
        """Check if state contains text data"""
        return self.puzzle_text is not None and len(self.puzzle_text.strip()) > 0

    def is_binary_file(self, file_path) -> bool:
        """Check if a file is likely binary"""
        try:
            with open(file_path, 'rb') as f:
                sample = f.read(1000)
                return not self._is_likely_text(sample)
        except:
            return True

    def get_summary(self) -> str:
        """Get a comprehensive summary of the current state"""
        summary_parts = []

        # Basic info
        if self.puzzle_file:
            summary_parts.append(f"File: {self.puzzle_file}")
        if self.file_type:
            summary_parts.append(f"Type: {self.file_type}")
        if self.file_size:
            summary_parts.append(f"Size: {self.file_size} bytes")
        if self.hash:
            summary_parts.append(f"Hash: {self.hash}")
        if self.puzzle_type:
            summary_parts.append(f"Puzzle Type: {self.puzzle_type}")

        summary_parts.append(f"Status: {self.status}")

        # Content info
        if self.puzzle_text:
            text_preview = self.puzzle_text[:200] + "..." if len(self.puzzle_text) > 200 else self.puzzle_text
            summary_parts.append(f"Text Content: {text_preview}")

        if self.binary_data:
            summary_parts.append(f"Binary Data: {len(self.binary_data)} bytes")

        # Analysis progress
        summary_parts.append(f"Insights: {len(self.insights)}")
        summary_parts.append(f"Transformations: {len(self.transformations)}")
        summary_parts.append(f"Analyzers Used: {', '.join(sorted(self.analyzers_used))}")

        # Related data
        if self.related_files:
            summary_parts.append(f"Related Files: {len(self.related_files)}")
        if self.clues:
            summary_parts.append(f"Clues: {len(self.clues)}")
        if self.patterns:
            summary_parts.append(f"Patterns: {len(self.patterns)}")

        # Solution
        if self.solution:
            summary_parts.append(f"Solution: {self.solution}")

        return "\n".join(summary_parts)

    def get_content_sample(self, max_size: int = 1000, max_binary_size: int = 200) -> str:
        """Get a sample of the puzzle content for analysis"""
        if self.puzzle_text:
            if len(self.puzzle_text) <= max_size:
                return self.puzzle_text
            else:
                return self.puzzle_text[:max_size] + f"\n... (truncated from {len(self.puzzle_text)} chars)"

        elif self.binary_data:
            if len(self.binary_data) <= max_binary_size:
                return f"Binary data (hex): {self.binary_data.hex()}"
            else:
                sample = self.binary_data[:max_binary_size]
                return f"Binary data (hex): {sample.hex()}... (truncated from {len(self.binary_data)} bytes)"

        else:
            return "No content available"

    def merge_related_state(self, other_state: "State") -> None:
        """Merge insights and transformations from another state"""
        # Merge insights (avoid duplicates)
        existing_insights = {(i["analyzer"], i["message"]) for i in self.insights}
        for insight in other_state.insights:
            key = (insight["analyzer"], insight["message"])
            if key not in existing_insights:
                self.insights.append(insight)

        # Merge transformations (avoid duplicates)
        existing_transformations = {(t["name"], t["analyzer"]) for t in self.transformations}
        for transformation in other_state.transformations:
            key = (transformation["name"], transformation["analyzer"])
            if key not in existing_transformations:
                self.transformations.append(transformation)

        # Merge analyzer usage
        self.analyzers_used.update(other_state.analyzers_used)

        # Update solution if found
        if other_state.solution and not self.solution:
            self.set_solution(other_state.solution)

    def to_dict(self) -> Dict[str, Any]:
        """Convert state to dictionary for serialization"""
        return {
            "puzzle_file": self.puzzle_file,
            "puzzle_text": self.puzzle_text,
            "file_type": self.file_type,
            "file_size": self.file_size,
            "hash": self.hash,
            "status": self.status,
            "puzzle_type": self.puzzle_type,
            "solution": self.solution,
            "insights": self.insights,
            "transformations": self.transformations,
            "analyzers_used": list(self.analyzers_used),
            "related_files": {
                name: {
                    "size": info["size"],
                    "sha256": info["sha256"],
                    "has_text": "text_content" in info
                }
                for name, info in self.related_files.items()
            },
            "clues": self.clues,
            "patterns": self.patterns,
            "summary": self.get_summary()
        }

    def __str__(self) -> str:
        """String representation of the state"""
        return self.get_summary()