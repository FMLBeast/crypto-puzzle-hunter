"""
State management module for Crypto Hunter

This module provides the State class which tracks the current state
of the analysis, including the puzzle data, insights, and solution.
"""
import json
import os
import logging
import hashlib
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from pathlib import Path

import config

logger = logging.getLogger(__name__)


class State:
    """
    Represents the current state of a puzzle analysis.
    Tracks the puzzle data, insights, analysis history, and solution.
    """

    def __init__(
        self,
        puzzle_file: Optional[str] = None,
        puzzle_data: Optional[bytes] = None,
        puzzle_text: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize a new state object.

        Args:
            puzzle_file: Path to the puzzle file
            puzzle_data: Raw binary puzzle data
            puzzle_text: Text representation of the puzzle
            metadata: Additional metadata about the puzzle
        """
        self.created_at = datetime.now().isoformat()
        self.updated_at = self.created_at
        self.puzzle_file = puzzle_file
        self.puzzle_data = puzzle_data
        self.puzzle_text = puzzle_text
        self.metadata = metadata or {}
        self.insights: List[Dict[str, Any]] = []
        self.analysis_history: List[Dict[str, Any]] = []
        self.solution: Optional[str] = None
        self.transformations: List[Dict[str, Any]] = []
        self.file_type: Optional[str] = None
        self.file_size: Optional[int] = None
        self.hash: Optional[str] = None
        self.analyzers_used: List[str] = []
        self.status = "initialized"

        # Load data from file if provided
        if puzzle_file and os.path.exists(puzzle_file):
            self._load_from_file(puzzle_file)

    def _load_from_file(self, file_path: str) -> None:
        """
        Load puzzle data from a file.

        Args:
            file_path: Path to the puzzle file
        """
        try:
            file_size = os.path.getsize(file_path)
            
            # Check if file is too large
            if file_size > config.MAX_FILE_SIZE:
                logger.warning(
                    f"File size ({file_size} bytes) exceeds maximum allowed size "
                    f"({config.MAX_FILE_SIZE} bytes). Loading first part only."
                )
                file_size = config.MAX_FILE_SIZE
            
            # Read file data
            with open(file_path, "rb") as f:
                self.puzzle_data = f.read(file_size)
            
            # Set file metadata
            self.file_size = file_size
            self.file_type = os.path.splitext(file_path)[-1].lstrip(".").lower()
            self.hash = hashlib.sha256(self.puzzle_data).hexdigest()
            self.metadata["filename"] = os.path.basename(file_path)
            
            # Try to decode as text if possible
            try:
                self.puzzle_text = self.puzzle_data.decode("utf-8")
            except UnicodeDecodeError:
                logger.debug("File is not UTF-8 encoded text")
                self.puzzle_text = None
                
            logger.info(f"Loaded puzzle from file: {file_path}")
            logger.debug(f"File type: {self.file_type}, size: {self.file_size} bytes")
        
        except Exception as e:
            logger.error(f"Error loading puzzle file: {e}")
            raise

    def add_insight(self, message: str, analyzer: Optional[str] = None, 
                    confidence: float = 1.0, data: Optional[Dict[str, Any]] = None) -> None:
        """
        Add an insight to the current state.

        Args:
            message: The insight message
            analyzer: The analyzer that generated the insight
            confidence: Confidence level (0.0-1.0)
            data: Additional data related to the insight
        """
        insight = {
            "timestamp": datetime.now().isoformat(),
            "message": message,
            "analyzer": analyzer,
            "confidence": confidence,
            "data": data or {},
        }
        self.insights.append(insight)
        self.updated_at = insight["timestamp"]
        logger.debug(f"Added insight: {message}")

    def add_transformation(self, name: str, description: str,
                           input_data: Union[str, bytes],
                           output_data: Union[str, bytes],
                           analyzer: Optional[str] = None) -> None:
        """
        Add a transformation to the state history.

        Args:
            name: Name of the transformation
            description: Description of what the transformation does
            input_data: Input data for the transformation
            output_data: Output data from the transformation
            analyzer: The analyzer that performed the transformation
        """
        # Convert bytes to hex string for JSON serialization
        if isinstance(input_data, bytes):
            input_data_str = input_data.hex()
            input_type = "bytes"
        else:
            input_data_str = input_data
            input_type = "str"
            
        if isinstance(output_data, bytes):
            output_data_str = output_data.hex()
            output_type = "bytes"
        else:
            output_data_str = output_data
            output_type = "str"
        
        transformation = {
            "timestamp": datetime.now().isoformat(),
            "name": name,
            "description": description,
            "analyzer": analyzer,
            "input": {
                "type": input_type,
                "data": input_data_str,
            },
            "output": {
                "type": output_type,
                "data": output_data_str,
            },
        }
        
        self.transformations.append(transformation)
        self.updated_at = transformation["timestamp"]
        logger.debug(f"Added transformation: {name}")

    def record_analyzer_run(self, analyzer_name: str, result: str) -> None:
        """
        Record the execution of an analyzer.

        Args:
            analyzer_name: Name of the analyzer
            result: Result status of the analyzer run
        """
        if analyzer_name not in self.analyzers_used:
            self.analyzers_used.append(analyzer_name)
            
        run_record = {
            "timestamp": datetime.now().isoformat(),
            "analyzer": analyzer_name,
            "result": result,
        }
        
        self.analysis_history.append(run_record)
        self.updated_at = run_record["timestamp"]

    def set_solution(self, solution: str, confidence: float = 1.0,
                     analyzer: Optional[str] = None) -> None:
        """
        Set the solution for the puzzle.

        Args:
            solution: The puzzle solution
            confidence: Confidence level (0.0-1.0)
            analyzer: The analyzer that found the solution
        """
        self.solution = solution
        self.status = "solved"
        self.updated_at = datetime.now().isoformat()
        
        # Add an insight for the solution
        self.add_insight(
            f"Solution found: {solution}",
            analyzer=analyzer,
            confidence=confidence,
            data={"solution": solution},
        )
        
        logger.info(f"Solution set: {solution}")

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the state to a dictionary.

        Returns:
            Dictionary representation of the state
        """
        state_dict = {
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "puzzle_file": self.puzzle_file,
            "file_type": self.file_type,
            "file_size": self.file_size,
            "hash": self.hash,
            "metadata": self.metadata,
            "insights": self.insights,
            "analysis_history": self.analysis_history,
            "transformations": self.transformations,
            "solution": self.solution,
            "status": self.status,
            "analyzers_used": self.analyzers_used,
        }
        
        # Only include text data if it's available and not too large
        if self.puzzle_text and len(self.puzzle_text) < 10000:
            state_dict["puzzle_text"] = self.puzzle_text
        
        return state_dict

    def save(self, file_path: str) -> None:
        """
        Save the state to a JSON file.

        Args:
            file_path: Path to save the state
        """
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
            
            # Save to JSON
            with open(file_path, "w") as f:
                json.dump(self.to_dict(), f, indent=2)
                
            logger.info(f"State saved to {file_path}")
        
        except Exception as e:
            logger.error(f"Error saving state: {e}")
            raise

    @classmethod
    def load(cls, file_path: str) -> "State":
        """
        Load a state from a JSON file.

        Args:
            file_path: Path to the state file

        Returns:
            Loaded State object
        """
        try:
            with open(file_path, "r") as f:
                state_dict = json.load(f)
            
            # Create new state object
            state = cls()
            
            # Load basic attributes
            state.created_at = state_dict.get("created_at", datetime.now().isoformat())
            state.updated_at = state_dict.get("updated_at", state.created_at)
            state.puzzle_file = state_dict.get("puzzle_file")
            state.file_type = state_dict.get("file_type")
            state.file_size = state_dict.get("file_size")
            state.hash = state_dict.get("hash")
            state.metadata = state_dict.get("metadata", {})
            state.puzzle_text = state_dict.get("puzzle_text")
            state.insights = state_dict.get("insights", [])
            state.analysis_history = state_dict.get("analysis_history", [])
            state.transformations = state_dict.get("transformations", [])
            state.solution = state_dict.get("solution")
            state.status = state_dict.get("status", "loaded")
            state.analyzers_used = state_dict.get("analyzers_used", [])
            
            # Load puzzle data from file if possible and not already loaded
            if state.puzzle_file and not state.puzzle_data and os.path.exists(state.puzzle_file):
                with open(state.puzzle_file, "rb") as f:
                    state.puzzle_data = f.read()
            
            logger.info(f"State loaded from {file_path}")
            return state
        
        except Exception as e:
            logger.error(f"Error loading state: {e}")
            raise

    def clone(self) -> "State":
        """
        Create a clone of the current state.

        Returns:
            A new State object with the same data
        """
        new_state = State()
        new_state.created_at = self.created_at
        new_state.updated_at = datetime.now().isoformat()
        new_state.puzzle_file = self.puzzle_file
        new_state.puzzle_data = self.puzzle_data
        new_state.puzzle_text = self.puzzle_text
        new_state.metadata = self.metadata.copy()
        new_state.insights = self.insights.copy()
        new_state.analysis_history = self.analysis_history.copy()
        new_state.transformations = self.transformations.copy()
        new_state.solution = self.solution
        new_state.file_type = self.file_type
        new_state.file_size = self.file_size
        new_state.hash = self.hash
        new_state.analyzers_used = self.analyzers_used.copy()
        new_state.status = self.status
        
        return new_state

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current state.

        Returns:
            Dictionary with state summary
        """
        return {
            "puzzle_file": self.puzzle_file,
            "file_type": self.file_type,
            "file_size": self.file_size,
            "hash": self.hash,
            "num_insights": len(self.insights),
            "num_transformations": len(self.transformations),
            "analyzers_used": self.analyzers_used,
            "status": self.status,
            "solution": self.solution,
            "analysis_time": (
                datetime.fromisoformat(self.updated_at) - 
                datetime.fromisoformat(self.created_at)
            ).total_seconds(),
        }
