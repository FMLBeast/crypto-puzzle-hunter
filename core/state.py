"""
State module for the Crypto Hunter.
Tracks the state of puzzle analysis including insights and transformations.
"""

import os
import time
import mimetypes
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

from core.logger import solution_logger

class State:
    """
    Class to track the state of puzzle analysis.
    """
    def __init__(self, puzzle_file: Optional[str] = None):
        """
        Initialize the analysis state.

        Args:
            puzzle_file: Optional filename of the puzzle
        """
        self.puzzle_file = puzzle_file  # Main puzzle file name
        self.puzzle_text = None         # Text content (if text file)
        self.binary_data = None         # Binary content (if binary file)
        self.file_type = None           # File type (determined from extension or content)
        self.file_size = None           # File size in bytes
        self.insights = []              # List of insights gathered during analysis
        self.transformations = []       # List of transformations applied
        self.solution = None            # Puzzle solution (if found)
        self.related_files = {}         # Related files that are part of the puzzle
        self.clues = []                 # Clues associated with this puzzle

        if puzzle_file:
            self._detect_file_type()

    def _detect_file_type(self):
        """Detect the file type based on the filename."""
        if self.puzzle_file:
            # Get file extension
            ext = os.path.splitext(self.puzzle_file)[1].lower()
            self.file_type = ext[1:] if ext else "unknown"

    def is_binary(self) -> bool:
        """Check if the puzzle is a binary file."""
        if not self.file_type:
            return False

        # List of known binary file types
        binary_types = [
            "png", "jpg", "jpeg", "gif", "bmp", "tiff", "ico", "webp",
            "pdf", "doc", "docx", "xls", "xlsx", "zip", "rar", "tar", "gz",
            "exe", "dll", "bin", "iso", "mp3", "mp4", "wav", "avi", "mov",
            "class", "jar", "war", "html"  # Added HTML to support steganography in HTML files
        ]

        return self.file_type in binary_types or self.binary_data is not None

    def is_binary_file(self, file_path) -> bool:
        """Check if a file is binary based on its path."""
        ext = os.path.splitext(file_path)[1].lower()
        file_type = ext[1:] if ext else "unknown"

        # List of known binary file types
        binary_types = [
            "png", "jpg", "jpeg", "gif", "bmp", "tiff", "ico", "webp",
            "pdf", "doc", "docx", "xls", "xlsx", "zip", "rar", "tar", "gz",
            "exe", "dll", "bin", "iso", "mp3", "mp4", "wav", "avi", "mov",
            "class", "jar", "war", "html"  # Added HTML to support steganography in HTML files
        ]

        return file_type in binary_types

    def set_puzzle_file(self, filename: str) -> None:
        """
        Set the puzzle filename.

        Args:
            filename: Name of the puzzle file
        """
        self.puzzle_file = filename
        self._detect_file_type()

    def set_puzzle_text(self, text: str) -> None:
        """
        Set the puzzle text content.

        Args:
            text: Text content of the puzzle
        """
        self.puzzle_text = text
        self.file_size = len(text.encode("utf-8"))

    def set_binary_data(self, data: bytes) -> None:
        """
        Set the puzzle binary data.

        Args:
            data: Binary content of the puzzle
        """
        self.binary_data = data
        self.file_size = len(data)

    def add_insight(self, text: str, analyzer: str) -> None:
        """
        Add an insight to the analysis state.

        Args:
            text: Insight text
            analyzer: Name of the analyzer that generated the insight
        """
        current_time = time.strftime("%H:%M:%S")
        self.insights.append({
            "time": current_time,
            "analyzer": analyzer,
            "text": text
        })

        # Log the insight in real-time
        solution_logger.log_insight(text, analyzer, current_time)

    def add_transformation(self, name: str, description: str, 
                           input_data: str, output_data: str, 
                           analyzer: str) -> None:
        """
        Add a transformation to the analysis state.

        Args:
            name: Name of the transformation
            description: Description of what the transformation does
            input_data: Input data for the transformation
            output_data: Output data from the transformation
            analyzer: Name of the analyzer that performed the transformation
        """
        current_time = time.strftime("%H:%M:%S")
        self.transformations.append({
            "time": current_time,
            "name": name,
            "description": description,
            "input_data": input_data,
            "output_data": output_data,
            "analyzer": analyzer
        })

        # Log the transformation in real-time
        solution_logger.log_transformation(name, description, input_data, output_data, analyzer, current_time)

    def set_solution(self, solution: str) -> None:
        """
        Set the solution for the puzzle.

        Args:
            solution: Solution to the puzzle
        """
        self.solution = solution

        # Log the solution in real-time
        solution_logger.log_solution(solution)

    def add_related_file(self, filename: str, content: bytes) -> None:
        """
        Add a related file that is part of the puzzle.

        Args:
            filename: Name of the related file
            content: Content of the related file
        """
        # Determine if the file is binary or text
        text_content = None
        try:
            # Try to decode as text
            text_content = content.decode("utf-8", errors="replace")
        except:
            # Binary file, leave text_content as None
            pass

        self.related_files[filename] = {
            "filename": filename,
            "content": content,
            "text_content": text_content,
            "size": len(content),
            "mime_type": mimetypes.guess_type(filename)[0] or "application/octet-stream",
            "sha256": hashlib.sha256(content).hexdigest()
        }

    def add_clue(self, clue_text: str, clue_file: str = None) -> None:
        """
        Add a clue to the puzzle.

        Args:
            clue_text: Text of the clue
            clue_file: Optional filename of the clue file
        """
        self.clues.append({
            "text": clue_text,
            "file": clue_file,
            "time": time.strftime("%H:%M:%S")
        })

    def get_related_file(self, filename: str) -> Dict[str, Any]:
        """
        Get a related file by name.

        Args:
            filename: Name of the related file

        Returns:
            Dictionary with file information
        """
        return self.related_files.get(filename)

    def get_all_related_files(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all related files.

        Returns:
            Dictionary of all related files
        """
        return self.related_files

    def get_summary(self) -> str:
        """
        Get a summary of the current state.

        Returns:
            Summary string
        """
        summary = f"File: {self.puzzle_file or 'Not specified'}\n"
        summary += f"Type: {self.file_type or 'Unknown'}\n"
        summary += f"Size: {self.file_size or 0} bytes\n"
        summary += f"Insights: {len(self.insights)}\n"
        summary += f"Transformations: {len(self.transformations)}\n"
        summary += f"Related files: {len(self.related_files)}\n"
        summary += f"Clues: {len(self.clues)}\n"

        # Add related files list
        if self.related_files:
            summary += "Related files:\n"
            for filename, file_info in self.related_files.items():
                summary += f"  - {filename} ({file_info['size']} bytes)\n"

        # Add clues
        if self.clues:
            summary += "Clues:\n"
            for clue in self.clues:
                summary += f"  - {clue['text'][:50]}{'...' if len(clue['text']) > 50 else ''}\n"

        return summary

    def get_content_sample(self, max_size: int = 1000) -> str:
        """
        Get a sample of the puzzle content for analysis.

        Args:
            max_size: Maximum size of the sample

        Returns:
            Content sample
        """
        if self.puzzle_text:
            # Text content
            return self.puzzle_text[:max_size]
        elif self.binary_data:
            # Binary content (hex representation)
            return self.binary_data[:max_size].hex()

        return "No content available"

    def get_all_text_content(self) -> Dict[str, str]:
        """
        Get all text content from all files.

        Returns:
            Dictionary mapping filenames to their text content
        """
        result = {}

        # Add main puzzle file if it's text
        if self.puzzle_text and self.puzzle_file:
            result[self.puzzle_file] = self.puzzle_text

        # Add all related text files
        for filename, file_info in self.related_files.items():
            if file_info.get("text_content"):
                result[filename] = file_info["text_content"]

        return result

    def merge_related_state(self, other_state) -> None:
        """
        Merge another state's related files, insights, and transformations into this state.

        Args:
            other_state: Another State object to merge from
        """
        # Merge related files
        for filename, file_info in other_state.related_files.items():
            if filename not in self.related_files:
                self.related_files[filename] = file_info

        # Merge insights
        self.insights.extend(other_state.insights)

        # Merge transformations
        self.transformations.extend(other_state.transformations)

        # Merge clues
        self.clues.extend(other_state.clues)
