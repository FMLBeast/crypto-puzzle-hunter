"""
Task Factory Module
Generates analysis tasks based on materials and current state.
"""

import logging
from state_management import Task, AnalysisPhase, MaterialType

logger = logging.getLogger(__name__)

class TaskFactory:
    """
    Factory for generating analysis tasks based on current state and materials.
    """

    def __init__(self, state):
        """
        Initialize the TaskFactory.

        Args:
            state: Current workflow state
        """
        self.state = state
        self.task_counter = 0
        logger.debug("TaskFactory initialized")

    def generate_initial_tasks(self, root_material):
        """
        Generate initial tasks for analyzing the root material.

        Args:
            root_material: The initial material loaded from the puzzle file

        Returns:
            List of Task objects
        """
        tasks = []

        try:
            # Determine material type and generate appropriate tasks
            if self._is_image_file(root_material):
                tasks.extend(self._generate_image_tasks(root_material))
            elif self._is_binary_file(root_material):
                tasks.extend(self._generate_binary_tasks(root_material))
            elif self._is_text_file(root_material):
                tasks.extend(self._generate_text_tasks(root_material))
            else:
                # Generate generic tasks for unknown file types
                tasks.extend(self._generate_generic_tasks(root_material))

            logger.info(f"Generated {len(tasks)} initial tasks")

        except Exception as e:
            logger.error(f"Error generating initial tasks: {e}")

        return tasks

    def _generate_image_tasks(self, material):
        """Generate tasks specific to image analysis"""
        tasks = []

        # Binary analysis
        tasks.append(self._create_task(
            f"file_analysis_{material.id}",
            "Analyze file structure and headers",
            "binary_analyzer",
            AnalysisPhase.DISCOVERY,
            priority=8,
            target_materials={material.id}
        ))

        # Advanced steganography
        tasks.append(self._create_task(
            f"advanced_stego_{material.id}",
            "Advanced steganographic analysis",
            "image_analyzer",
            AnalysisPhase.EXTRACTION,
            priority=9,
            target_materials={material.id}
        ))

        # Vision analysis
        tasks.append(self._create_task(
            f"vision_analysis_{material.id}",
            "Visual content analysis",
            "vision_analyzer",
            AnalysisPhase.ANALYSIS,
            priority=7,
            target_materials={material.id}
        ))

        # Metadata extraction
        tasks.append(self._create_task(
            f"metadata_extract_{material.id}",
            "Extract metadata from image",
            "binary_analyzer",
            AnalysisPhase.DISCOVERY,
            priority=6,
            target_materials={material.id}
        ))

        # Steganography scan
        tasks.append(self._create_task(
            f"steganography_scan_{material.id}",
            "Scan for hidden data",
            "image_analyzer",
            AnalysisPhase.EXTRACTION,
            priority=8,
            target_materials={material.id}
        ))

        return tasks

    def _generate_binary_tasks(self, material):
        """Generate tasks specific to binary file analysis"""
        tasks = []

        tasks.append(self._create_task(
            f"binary_analysis_{material.id}",
            "Binary file structure analysis",
            "binary_analyzer",
            AnalysisPhase.DISCOVERY,
            priority=8,
            target_materials={material.id}
        ))

        tasks.append(self._create_task(
            f"hex_analysis_{material.id}",
            "Hexadecimal pattern analysis",
            "binary_analyzer",
            AnalysisPhase.ANALYSIS,
            priority=7,
            target_materials={material.id}
        ))

        return tasks

    def _generate_text_tasks(self, material):
        """Generate tasks specific to text analysis"""
        tasks = []

        tasks.append(self._create_task(
            f"text_analysis_{material.id}",
            "Text content analysis",
            "text_analyzer",
            AnalysisPhase.DISCOVERY,
            priority=8,
            target_materials={material.id}
        ))

        tasks.append(self._create_task(
            f"cipher_analysis_{material.id}",
            "Cipher and encoding analysis",
            "crypto_analyzer",
            AnalysisPhase.ANALYSIS,
            priority=9,
            target_materials={material.id}
        ))

        return tasks

    def _generate_generic_tasks(self, material):
        """Generate generic tasks for unknown file types"""
        tasks = []

        tasks.append(self._create_task(
            f"generic_analysis_{material.id}",
            "Generic file analysis",
            "binary_analyzer",
            AnalysisPhase.DISCOVERY,
            priority=5,
            target_materials={material.id}
        ))

        return tasks

    def _create_task(self, task_id, description, analyzer, phase, priority, target_materials, dependencies=None):
        """
        Create a new task with the given parameters.

        Args:
            task_id: Unique identifier for the task
            description: Description of what the task does
            analyzer: Name of the analyzer to use
            phase: Analysis phase
            priority: Task priority (higher = more important)
            target_materials: Set of material IDs this task operates on
            dependencies: Optional set of task IDs this task depends on

        Returns:
            Task object
        """
        return Task(
            id=task_id,
            name=task_id,
            description=description,
            analyzer=analyzer,
            phase=phase,
            priority=priority,
            target_materials=target_materials,
            dependencies=dependencies
        )

    def _is_image_file(self, material):
        """Check if material is an image file"""
        if not hasattr(material, 'content') or not isinstance(material.content, bytes):
            return False

        data = material.content
        if len(data) < 4:
            return False

        # Check image file signatures
        return (data.startswith(b'\x89PNG') or  # PNG
                data.startswith(b'\xFF\xD8\xFF') or  # JPEG
                data.startswith(b'GIF8') or  # GIF
                data.startswith(b'BM') or  # BMP
                data.startswith(b'RIFF') and b'WEBP' in data[:12])  # WebP

    def _is_binary_file(self, material):
        """Check if material is a binary file"""
        if not hasattr(material, 'content'):
            return False

        # If it's bytes and not an image, consider it binary
        return isinstance(material.content, bytes) and not self._is_image_file(material)

    def _is_text_file(self, material):
        """Check if material is a text file"""
        if not hasattr(material, 'content'):
            return False

        # Check if content is string or can be decoded as text
        if isinstance(material.content, str):
            return True

        if isinstance(material.content, bytes):
            try:
                material.content.decode('utf-8')
                return True
            except UnicodeDecodeError:
                return False

        return False

    def generate_follow_up_tasks(self, completed_task, findings):
        """
        Generate follow-up tasks based on completed task results.

        Args:
            completed_task: The task that was just completed
            findings: List of findings from the completed task

        Returns:
            List of new Task objects
        """
        tasks = []

        try:
            # Generate tasks based on findings
            for finding in findings:
                if self._suggests_crypto_content(finding):
                    tasks.extend(self._generate_crypto_tasks(completed_task.target_materials))
                elif self._suggests_hidden_data(finding):
                    tasks.extend(self._generate_extraction_tasks(completed_task.target_materials))

        except Exception as e:
            logger.error(f"Error generating follow-up tasks: {e}")

        return tasks

    def _suggests_crypto_content(self, finding):
        """Check if finding suggests cryptographic content"""
        if not hasattr(finding, 'description'):
            return False

        crypto_keywords = ['key', 'cipher', 'encrypt', 'decode', 'hash', 'bitcoin', 'wallet']
        description = finding.description.lower()
        return any(keyword in description for keyword in crypto_keywords)

    def _suggests_hidden_data(self, finding):
        """Check if finding suggests hidden data"""
        if not hasattr(finding, 'description'):
            return False

        hidden_keywords = ['hidden', 'embedded', 'steganography', 'metadata', 'extra']
        description = finding.description.lower()
        return any(keyword in description for keyword in hidden_keywords)

    def _generate_crypto_tasks(self, target_materials):
        """Generate cryptographic analysis tasks"""
        tasks = []

        for material_id in target_materials:
            tasks.append(self._create_task(
                f"crypto_deep_{material_id}_{self.task_counter}",
                "Deep cryptographic analysis",
                "crypto_analyzer",
                AnalysisPhase.ANALYSIS,
                priority=9,
                target_materials={material_id}
            ))
            self.task_counter += 1

        return tasks

    def _generate_extraction_tasks(self, target_materials):
        """Generate data extraction tasks"""
        tasks = []

        for material_id in target_materials:
            tasks.append(self._create_task(
                f"extract_hidden_{material_id}_{self.task_counter}",
                "Extract hidden data",
                "extraction_analyzer",
                AnalysisPhase.EXTRACTION,
                priority=8,
                target_materials={material_id}
            ))
            self.task_counter += 1

        return tasks