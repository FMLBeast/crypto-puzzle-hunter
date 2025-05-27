# enhanced_state_management.py
import logging
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import uuid

logger = logging.getLogger(__name__)


class AnalysisPhase(Enum):
    DISCOVERY      = auto()
    EXTRACTION     = auto()
    CLASSIFICATION = auto()
    ANALYSIS       = auto()
    SYNTHESIS      = auto()
    SOLUTION       = auto()


class TaskStatus(Enum):
    PENDING   = auto()
    RUNNING   = auto()
    COMPLETED = auto()
    FAILED    = auto()


class MaterialType(Enum):
    RAW_FILE       = auto()
    DECODED_TEXT   = auto()
    EXTRACTED_BINARY = auto()
    CRYPTO_KEY     = auto()
    CLUE           = auto()


class Material:
    def __init__(self,
                 id: str,
                 name: str,
                 content: Any,
                 type: MaterialType):
        self.id      = id
        self.name    = name
        self.content = content
        self.type    = type


class Finding:
    def __init__(self,
                 id: str,
                 title: str,
                 description: str,
                 finding_type: str):
        self.id           = id
        self.title        = title
        self.description  = description
        self.finding_type = finding_type


class Task:
    def __init__(self,
                 id: str,
                 name: str,
                 description: str,
                 analyzer: str,
                 phase: AnalysisPhase,
                 priority: int,
                 target_materials: Set[str],
                 dependencies: Optional[Set[str]] = None):
        self.id               = id
        self.name             = name
        self.description      = description
        self.analyzer         = analyzer
        self.phase            = phase
        self.priority         = priority
        self.target_materials = target_materials
        self.dependencies     = dependencies or set()
        self.status           = TaskStatus.PENDING


class WorkflowState:
    """
    Tracks materials, tasks, findings, transformations, and final solution.
    """
    def __init__(self):
        self.materials: Dict[str, Material]         = {}
        self.tasks:     Dict[str, Task]             = {}
        self.findings:  List[Finding]               = []
        self.solution:  Optional[str]               = None
        self.logs:      List[str]                   = []

        logger.info("🆕 WorkflowState initialized")

    def add_material(self, path: Union[str, Path]) -> Material:
        """
        Load file from disk and register as a Material.
        """
        path = Path(path)
        mid  = str(uuid.uuid4())
        with open(path, "rb") as f:
            data = f.read()
        mat = Material(id=mid, name=path.name, content=data, type=MaterialType.RAW_FILE)
        self.materials[mid] = mat
        logger.info(f"Registered material {path.name} (id={mid})")
        return mat

    def add_insight(self, text: str, analyzer: str):
        fid = str(len(self.findings))
        f   = Finding(id=fid, title="Insight", description=text, finding_type="insight")
        self.findings.append(f)
        logger.info(f"[{analyzer}] Insight: {text}")

    def add_finding(self, title: str, description: str, finding_type: str="finding"):
        fid = str(len(self.findings))
        f   = Finding(id=fid, title=title, description=description, finding_type=finding_type)
        self.findings.append(f)
        logger.info(f"[{finding_type}] {title}: {description}")

    def add_transformation(self, name: str, description: str):
        # you can treat transformations just like findings or track separately
        self.add_finding(f"Transformation: {name}", description, finding_type="transformation")

    def add_task(self, task: Task):
        self.tasks[task.id] = task
        logger.info(f"Task queued: {task.id} ({task.analyzer})")

    def get_next_task(self) -> Optional[Task]:
        pending = [t for t in self.tasks.values() if t.status == TaskStatus.PENDING]
        if not pending:
            return None
        # simple priority sort
        pending.sort(key=lambda t: -t.priority)
        t = pending[0]
        t.status = TaskStatus.RUNNING
        return t

    def complete_task(self, task: Task):
        task.status = TaskStatus.COMPLETED
        logger.info(f"Task completed: {task.id}")

    def fail_task(self, task: Task, error: str):
        task.status = TaskStatus.FAILED
        self.add_insight(f"Task {task.id} failed: {error}", analyzer=task.analyzer)

    def is_complete(self) -> bool:
        return self.solution is not None or all(t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED)
                                                  for t in self.tasks.values())

    def set_solution(self, sol: str):
        self.solution = sol
        logger.info(f"🎉 Solution set: {sol}")

    def get_summary(self) -> str:
        return (f"Materials={len(self.materials)}, "
                f"Tasks={len(self.tasks)}, "
                f"Findings={len(self.findings)}, "
                f"Solution={'YES' if self.solution else 'NO'}")
