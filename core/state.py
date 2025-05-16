"""
State module for the Crypto Hunter.
Tracks the state of puzzle analysis including insights and transformations.
"""

import os
import time
import mimetypes
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

    related_files: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    clues: List[Dict[str, Any]] = field(default_factory=list)
    patterns: List[Dict[str, Any]] = field(default_factory=list)

    insights: List[Dict[str, Any]] = field(default_factory=list)
    transformations: List[Dict[str, Any]] = field(default_factory=list)

    solution: Optional[str] = None

    # Track which analyzers we’ve already tried (to avoid immediate repeats)
    attempted_analyzers: Set[str] = field(default_factory=set)

    def __post_init__(self):
        if self.puzzle_file:
            self._load_file()

    def _load_file(self):
        """Load puzzle_file into binary_data or puzzle_text based on type."""
        path = Path(self.puzzle_file)
        self.file_size = path.stat().st_size
        self.file_type, _ = mimetypes.guess_type(path.name)
        if self.file_type and self.file_type.startswith("text"):
            txt = path.read_text(errors="ignore")
            self.set_puzzle_text(txt)
        else:
            data = path.read_bytes()
            self.set_binary_data(data)

    def add_insight(self, analyzer: str, text: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.insights.append({"time": ts, "analyzer": analyzer, "text": text})
        solution_logger.log_insight(analyzer, text, ts)

    def add_transformation(self, name: str, description: str,
                           input_data: Any, output_data: Any,
                           analyzer: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.transformations.append({
            "time": ts,
            "name": name,
            "description": description,
            "input_data": input_data,
            "output_data": output_data,
            "analyzer": analyzer
        })
        solution_logger.log_transformation(name, description, input_data, output_data, analyzer, ts)

        # **NEW**: if this transformation provides text, promote it to puzzle_text
        if name == "Image LSB" or name == "PNG Text Chunk":
            if not self.puzzle_text or len(output_data) > len(self.puzzle_text):
                self.set_puzzle_text(output_data)

    def set_puzzle_text(self, txt: str) -> None:
        """Promote extracted text into puzzle_text and log it."""
        self.puzzle_text = txt
        self.add_insight("state", f"Puzzle text set ({len(txt)} chars)")

    def set_binary_data(self, data: bytes) -> None:
        """Store binary data and record insight."""
        self.binary_data = data
        self.file_size = len(data)
        self.add_insight("state", f"Binary data set ({self.file_size} bytes)")

    def set_solution(self, sol: str) -> None:
        """Record the solution and log it."""
        self.solution = sol
        self.add_insight("state", f"Solution found: {sol}")

    def add_related_file(self, filename: str, content: bytes) -> None:
        sha = hashlib.sha256(content).hexdigest()
        self.related_files[filename] = {"content": content, "size": len(content), "sha256": sha}

    def is_binary(self) -> bool:
        return self.binary_data is not None

    def is_text(self) -> bool:
        return self.puzzle_text is not None

    def merge(self, other: "State") -> None:
        """Merge insights/transformations from another state (if needed)."""
        self.related_files.update(other.related_files)
        self.insights.extend(other.insights)
        self.transformations.extend(other.transformations)
        self.clues.extend(other.clues)
