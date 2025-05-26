#!/usr/bin/env python3
"""
Enhanced State Management System for Crypto Hunter
Core workflow components for intelligent puzzle analysis
"""

import os
import json
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Union,Tuple
from dataclasses import dataclass, field


class MaterialType(Enum):
    """Types of materials discovered during analysis"""
    SOURCE_FILE = "source_file"
    DECODED_TEXT = "decoded_text"
    EXTRACTED_BINARY = "extracted_binary"
    CRYPTO_KEY = "crypto_key"
    CLUE = "clue"
    PATTERN = "pattern"
    METADATA = "metadata"


class AnalysisPhase(Enum):
    """Analysis workflow phases"""
    DISCOVERY = "discovery"
    CLASSIFICATION = "classification"
    EXTRACTION = "extraction"
    ANALYSIS = "analysis"
    SYNTHESIS = "synthesis"
    SOLUTION = "solution"


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Material:
    """Represents discovered material during analysis"""
    id: str
    name: str
    type: MaterialType
    content: Union[str, bytes, Any]
    source: str  # ID of task/analyzer that discovered this
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    file_path: Optional[str] = None
    size: Optional[int] = None
    
    def __post_init__(self):
        if self.size is None and self.content:
            if isinstance(self.content, (str, bytes)):
                self.size = len(self.content)


@dataclass
class Finding:
    """Represents analysis findings"""
    id: str
    analyzer: str
    material_id: str
    finding_type: str
    title: str
    description: str
    confidence: float  # 0.0 to 1.0
    data: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    
    def is_high_confidence(self) -> bool:
        return self.confidence >= 0.8


@dataclass
class Task:
    """Represents analysis task"""
    id: str
    name: str
    description: str
    analyzer: str
    phase: AnalysisPhase
    priority: int = 50
    dependencies: Set[str] = field(default_factory=set)
    target_materials: Set[str] = field(default_factory=set)
    status: TaskStatus = TaskStatus.PENDING
    result_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_time: Optional[float] = None
    
    def can_execute(self, completed_tasks: Set[str]) -> bool:
        """Check if task can be executed based on dependencies"""
        return (self.status == TaskStatus.PENDING and 
                self.dependencies.issubset(completed_tasks))
    
    def get_duration(self) -> Optional[float]:
        """Get task execution duration in seconds"""
        if self.execution_time:
            return self.execution_time
        elif self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class WorkflowState:
    """Central state management for enhanced workflow"""
    
    def __init__(self, puzzle_file: str):
        self.puzzle_file = puzzle_file
        self.puzzle_name = Path(puzzle_file).stem
        
        # Core collections
        self.materials: Dict[str, Material] = {}
        self.findings: Dict[str, Finding] = {}
        self.tasks: Dict[str, Task] = {}
        
        # State tracking
        self.current_phase = AnalysisPhase.DISCOVERY
        self.completed_tasks: Set[str] = set()
        self.failed_tasks: Set[str] = set()
        self.blocked_tasks: Set[str] = set()  # Tasks blocked due to loops/duplicates

        # Loop and duplicate detection
        self.task_signatures: Dict[str, str] = {}  # task_id -> content_hash
        self.signature_history: Dict[str, List[str]] = {}  # signature -> [task_ids]
        self.loop_detection_threshold = 3  # Max identical tasks before blocking
        self.similar_task_threshold = 5  # Max similar tasks before asking user
        
        # Solution tracking
        self.solution_candidates: List[str] = []
        self.final_solution: Optional[str] = None
        
        # Timestamps
        self.created_at = datetime.now()
        self.last_updated = datetime.now()
        
        # Initialize with source material
        self._initialize_source_material()
    
    def _initialize_source_material(self):
        """Initialize with source puzzle file"""
        source_material = Material(
            id="source_material",
            name=Path(self.puzzle_file).name,
            type=MaterialType.SOURCE_FILE,
            content=None,  # Will be loaded when needed
            source="initial",
            file_path=self.puzzle_file,
            metadata={
                "file_extension": Path(self.puzzle_file).suffix,
                "file_size": Path(self.puzzle_file).stat().st_size if Path(self.puzzle_file).exists() else 0
            }
        )
        
        self.materials["source_material"] = source_material
    
    def add_material(self, material: Material) -> str:
        """Add material and return its ID"""
        self.materials[material.id] = material
        self.last_updated = datetime.now()
        return material.id
    
    def add_finding(self, finding: Finding) -> str:
        """Add finding and return its ID"""
        self.findings[finding.id] = finding
        self.last_updated = datetime.now()
        return finding.id
    
    def add_task(self, task: Task) -> str:
        """Add task and return its ID"""
        self.tasks[task.id] = task
        self.last_updated = datetime.now()
        return task.id
    
    def mark_task_started(self, task_id: str):
        """Mark task as started"""
        if task_id in self.tasks:
            task = self.tasks[task_id]
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now()
            self.last_updated = datetime.now()
    
    def mark_task_completed(self, task_id: str, result_data: Dict[str, Any]):
        """Mark task as completed"""
        if task_id in self.tasks:
            task = self.tasks[task_id]
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now()
            task.result_data = result_data
            if task.started_at:
                task.execution_time = (task.completed_at - task.started_at).total_seconds()
            
            self.completed_tasks.add(task_id)
            self.last_updated = datetime.now()
    
    def mark_task_failed(self, task_id: str, error_message: str):
        """Mark task as failed"""
        if task_id in self.tasks:
            task = self.tasks[task_id]
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.now()
            task.error_message = error_message
            if task.started_at:
                task.execution_time = (task.completed_at - task.started_at).total_seconds()
            
            self.failed_tasks.add(task_id)
            self.last_updated = datetime.now()
    
    def get_materials_by_type(self, material_type: MaterialType) -> List[Material]:
        """Get all materials of a specific type"""
        return [m for m in self.materials.values() if m.type == material_type]
    
    def get_high_confidence_findings(self, min_confidence: float = 0.8) -> List[Finding]:
        """Get high confidence findings"""
        return [f for f in self.findings.values() if f.confidence >= min_confidence]
    
    def get_findings_by_analyzer(self, analyzer: str) -> List[Finding]:
        """Get findings from specific analyzer"""
        return [f for f in self.findings.values() if f.analyzer == analyzer]
    
    def get_pending_tasks(self) -> List[Task]:
        """Get all pending tasks"""
        return [t for t in self.tasks.values() if t.status == TaskStatus.PENDING]
    
    def get_executable_tasks(self) -> List[Task]:
        """Get tasks that can be executed now"""
        return [t for t in self.get_pending_tasks() if t.can_execute(self.completed_tasks)]
    
    def get_tasks_by_phase(self, phase: AnalysisPhase) -> List[Task]:
        """Get tasks in specific phase"""
        return [t for t in self.tasks.values() if t.phase == phase]
    
    def get_progress_summary(self) -> Dict[str, Any]:
        """Get comprehensive progress summary"""
        total_tasks = len(self.tasks)
        completed_tasks = len(self.completed_tasks)
        failed_tasks = len(self.failed_tasks)
        
        high_conf_findings = len(self.get_high_confidence_findings())
        
        return {
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "failed_tasks": failed_tasks,
            "pending_tasks": total_tasks - completed_tasks - failed_tasks,
            "completion_percentage": (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0,
            "total_materials": len(self.materials),
            "total_findings": len(self.findings),
            "high_confidence_findings": high_conf_findings,
            "solution_candidates": len(self.solution_candidates),
            "has_solution": self.final_solution is not None,
            "current_phase": self.current_phase,
            "analysis_duration": (datetime.now() - self.created_at).total_seconds()
        }
    
    def advance_phase(self):
        """Advance to next analysis phase"""
        phases = list(AnalysisPhase)
        current_index = phases.index(self.current_phase)
        
        if current_index + 1 < len(phases):
            self.current_phase = phases[current_index + 1]
            self.last_updated = datetime.now()
    
    def should_advance_phase(self) -> bool:
        """Determine if phase should advance"""
        current_phase_tasks = self.get_tasks_by_phase(self.current_phase)
        
        if not current_phase_tasks:
            return True
        
        completed_in_phase = sum(1 for t in current_phase_tasks if t.status == TaskStatus.COMPLETED)
        completion_rate = completed_in_phase / len(current_phase_tasks)
        
        # Advance if 80% of phase tasks are complete
        return completion_rate >= 0.8
    
    def get_material_by_name(self, name: str) -> Optional[Material]:
        """Get material by name"""
        for material in self.materials.values():
            if material.name == name:
                return material
        return None
    
    def get_task_by_name(self, name: str) -> Optional[Task]:
        """Get task by name"""
        for task in self.tasks.values():
            if task.name == name:
                return task
        return None
    
    def export_state_summary(self) -> Dict[str, Any]:
        """Export state summary for external use"""
        return {
            "puzzle_name": self.puzzle_name,
            "puzzle_file": self.puzzle_file,
            "current_phase": self.current_phase.value,
            "progress": self.get_progress_summary(),
            "materials": {
                mat_type.value: len(self.get_materials_by_type(mat_type))
                for mat_type in MaterialType
            },
            "high_confidence_findings": [
                {
                    "analyzer": f.analyzer,
                    "title": f.title,
                    "confidence": f.confidence,
                    "created_at": f.created_at.isoformat()
                }
                for f in self.get_high_confidence_findings()
            ],
            "solution_candidates": self.solution_candidates,
            "final_solution": self.final_solution,
            "created_at": self.created_at.isoformat(),
            "last_updated": self.last_updated.isoformat()
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entire state to dictionary for serialization"""
        return {
            "puzzle_file": self.puzzle_file,
            "puzzle_name": self.puzzle_name,
            "current_phase": self.current_phase.value,
            "materials": {
                mid: {
                    "id": m.id,
                    "name": m.name,
                    "type": m.type.value,
                    "content": str(m.content) if m.content else None,
                    "source": m.source,
                    "metadata": m.metadata,
                    "created_at": m.created_at.isoformat(),
                    "file_path": m.file_path,
                    "size": m.size
                }
                for mid, m in self.materials.items()
            },
            "findings": {
                fid: {
                    "id": f.id,
                    "analyzer": f.analyzer,
                    "material_id": f.material_id,
                    "finding_type": f.finding_type,
                    "title": f.title,
                    "description": f.description,
                    "confidence": f.confidence,
                    "data": f.data,
                    "created_at": f.created_at.isoformat()
                }
                for fid, f in self.findings.items()
            },
            "tasks": {
                tid: {
                    "id": t.id,
                    "name": t.name,
                    "description": t.description,
                    "analyzer": t.analyzer,
                    "phase": t.phase.value,
                    "priority": t.priority,
                    "dependencies": list(t.dependencies),
                    "target_materials": list(t.target_materials),
                    "status": t.status.value,
                    "result_data": t.result_data,
                    "error_message": t.error_message,
                    "created_at": t.created_at.isoformat(),
                    "started_at": t.started_at.isoformat() if t.started_at else None,
                    "completed_at": t.completed_at.isoformat() if t.completed_at else None,
                    "execution_time": t.execution_time
                }
                for tid, t in self.tasks.items()
            },
            "completed_tasks": list(self.completed_tasks),
            "failed_tasks": list(self.failed_tasks),
            "solution_candidates": self.solution_candidates,
            "final_solution": self.final_solution,
            "created_at": self.created_at.isoformat(),
            "last_updated": self.last_updated.isoformat()
        }


class WorkflowOrchestrator:
    """Base orchestrator for workflow management"""
    
    def __init__(self, puzzle_file: str):
        self.state = WorkflowState(puzzle_file)
        self.puzzle_file = puzzle_file
    
    def update_phase_if_needed(self):
        """Update analysis phase if conditions are met"""
        if self.state.should_advance_phase():
            old_phase = self.state.current_phase
            self.state.advance_phase()
            
            if old_phase != self.state.current_phase:
                print(f"📈 Advanced to phase: {self.state.current_phase.value}")
    
    def get_next_tasks(self, max_tasks: int = 5) -> List[Task]:
        """Get next tasks to execute"""
        executable_tasks = self.state.get_executable_tasks()
        
        # Sort by priority (descending)
        executable_tasks.sort(key=lambda t: t.priority, reverse=True)
        
        return executable_tasks[:max_tasks]
    
    def execute_task(self, task: Task) -> Tuple[bool, Dict[str, Any]]:
        """Execute a single task - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement execute_task")
    
    def run_workflow(self, max_iterations: int = 50) -> bool:
        """Run basic workflow - to be enhanced by subclasses"""
        iteration = 0
        
        while iteration < max_iterations:
            next_tasks = self.get_next_tasks()
            
            if not next_tasks:
                break
            
            for task in next_tasks:
                success, result_data = self.execute_task(task)
                
                if success:
                    self.state.mark_task_completed(task.id, result_data)
                else:
                    error = result_data.get('error', 'Unknown error')
                    self.state.mark_task_failed(task.id, error)
            
            self.update_phase_if_needed()
            iteration += 1
        
        return self.state.final_solution is not None