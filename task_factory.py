#!/usr/bin/env python3
"""
Intelligent Task Factory for Crypto Hunter
Generates sophisticated task workflows based on discovered materials and findings
"""

import re
import uuid
from typing import Dict, List, Set, Optional, Any, Tuple
from typing import Dict, List, Set, Optional, Any, Tuple
from pathlib import Path

from enhanced_state_management import (
    Task, Material, Finding, WorkflowState, 
    AnalysisPhase, TaskStatus, MaterialType
)


class TaskFactory:
    """Intelligent factory for generating analysis tasks"""
    
    def __init__(self, state: WorkflowState):
        self.state = state
        
        # Task generation rules
        self.file_type_analyzers = {
            'image': ['image_analyzer', 'vision_analyzer'],
            'text': ['text_analyzer', 'encoding_analyzer', 'cipher_analyzer'],
            'binary': ['binary_analyzer', 'crypto_analyzer'],
            'executable': ['binary_analyzer', 'code_analyzer'],
            'archive': ['binary_analyzer', 'binwalk_analyzer'],
            'blockchain': ['blockchain_analyzer', 'crypto_analyzer']
        }
        
        # Pattern-based task generation
        self.pattern_tasks = {
            r'0x[a-fA-F0-9]{40}': ('blockchain_analyzer', 'Ethereum address detected'),
            r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}': ('blockchain_analyzer', 'Bitcoin address detected'),
            r'[A-Za-z0-9+/]{4,}={0,2}': ('encoding_analyzer', 'Base64 pattern detected'),
            r'[0-9a-fA-F]{32,}': ('crypto_analyzer', 'Hex pattern detected'),
            r'-----BEGIN.*-----': ('crypto_analyzer', 'PEM format detected'),
            r'flag\{.*\}': ('cipher_analyzer', 'CTF flag pattern detected')
        }
        
        # Arweave-specific patterns
        self.arweave_patterns = {
            r'[A-Za-z0-9_-]{43}': 'Arweave transaction ID',
            r'algebra.*equation': 'Mathematical problem',
            r'beep.*pattern': 'Audio pattern analysis',
            r'coordinate.*\d+\.\d+': 'Geographic coordinates',
            r'riddle|puzzle': 'Riddle analysis needed'
        }
    
    def generate_initial_tasks(self, source_material: Material) -> List[Task]:
        """Generate initial analysis tasks for source material"""
        tasks = []
        
        # Always start with file analysis
        file_analysis_task = Task(
            id=f"file_analysis_{source_material.id}",
            name="Initial File Analysis",
            description=f"Analyze file format and basic properties of {source_material.name}",
            analyzer="binary_analyzer",
            phase=AnalysisPhase.DISCOVERY,
            priority=100,
            target_materials={source_material.id}
        )
        tasks.append(file_analysis_task)
        
        # File extension based tasks
        file_ext = Path(source_material.name).suffix.lower()
        if file_ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
            # Image analysis pipeline
            tasks.extend(self._generate_image_tasks(source_material, file_analysis_task.id))
        elif file_ext in ['.txt', '.md', '.py', '.js', '.html']:
            # Text analysis pipeline
            tasks.extend(self._generate_text_tasks(source_material, file_analysis_task.id))
        elif file_ext in ['.zip', '.tar', '.gz', '.7z']:
            # Archive analysis pipeline
            tasks.extend(self._generate_archive_tasks(source_material, file_analysis_task.id))
        elif file_ext in ['.exe', '.bin', '.elf']:
            # Binary executable analysis
            tasks.extend(self._generate_executable_tasks(source_material, file_analysis_task.id))
        
        # Always add steganography scan for any file
        stego_task = Task(
            id=f"steganography_scan_{source_material.id}",
            name="Steganography Analysis",
            description=f"Comprehensive steganography analysis of {source_material.name}",
            analyzer="image_analyzer",
            phase=AnalysisPhase.EXTRACTION,
            priority=90,
            dependencies={file_analysis_task.id},
            target_materials={source_material.id}
        )
        tasks.append(stego_task)
        
        return tasks
    
    def _generate_image_tasks(self, material: Material, dependency: str) -> List[Task]:
        """Generate image-specific analysis tasks"""
        tasks = []
        
        # Advanced steganography
        advanced_stego = Task(
            id=f"advanced_stego_{material.id}",
            name="Advanced Steganography",
            description="Multi-bitplane LSB and frequency domain analysis",
            analyzer="image_analyzer",
            phase=AnalysisPhase.EXTRACTION,
            priority=85,
            dependencies={dependency},
            target_materials={material.id}
        )
        tasks.append(advanced_stego)
        
        # Vision analysis if available
        vision_task = Task(
            id=f"vision_analysis_{material.id}",
            name="AI Vision Analysis",
            description="Analyze image content using AI vision",
            analyzer="vision_analyzer", 
            phase=AnalysisPhase.ANALYSIS,
            priority=75,
            dependencies={dependency},
            target_materials={material.id}
        )
        tasks.append(vision_task)
        
        # Metadata extraction
        metadata_task = Task(
            id=f"metadata_extract_{material.id}",
            name="Metadata Analysis",
            description="Extract and analyze image metadata",
            analyzer="binary_analyzer",
            phase=AnalysisPhase.CLASSIFICATION,
            priority=70,
            dependencies={dependency},
            target_materials={material.id}
        )
        tasks.append(metadata_task)
        
        return tasks
    
    def _generate_text_tasks(self, material: Material, dependency: str) -> List[Task]:
        """Generate text-specific analysis tasks"""
        tasks = []
        
        # Text pattern analysis
        text_patterns = Task(
            id=f"text_patterns_{material.id}",
            name="Text Pattern Analysis", 
            description="Analyze text patterns and structures",
            analyzer="text_pattern_analyzer",
            phase=AnalysisPhase.ANALYSIS,
            priority=80,
            dependencies={dependency},
            target_materials={material.id}
        )
        tasks.append(text_patterns)
        
        # Encoding detection
        encoding_task = Task(
            id=f"encoding_analysis_{material.id}",
            name="Encoding Analysis",
            description="Detect and decode various text encodings",
            analyzer="encoding_analyzer",
            phase=AnalysisPhase.ANALYSIS,
            priority=85,
            dependencies={dependency},
            target_materials={material.id}
        )
        tasks.append(encoding_task)
        
        # Cipher analysis
        cipher_task = Task(
            id=f"cipher_analysis_{material.id}",
            name="Cipher Analysis",
            description="Analyze for classical and modern ciphers",
            analyzer="cipher_analyzer",
            phase=AnalysisPhase.ANALYSIS,
            priority=80,
            dependencies={dependency},
            target_materials={material.id}
        )
        tasks.append(cipher_task)
        
        return tasks
    
    def _generate_archive_tasks(self, material: Material, dependency: str) -> List[Task]:
        """Generate archive-specific analysis tasks"""
        tasks = []
        
        # Binwalk analysis
        binwalk_task = Task(
            id=f"binwalk_{material.id}",
            name="Archive Extraction",
            description="Extract embedded files using binwalk",
            analyzer="binwalk_analyzer",
            phase=AnalysisPhase.EXTRACTION,
            priority=95,
            dependencies={dependency},
            target_materials={material.id}
        )
        tasks.append(binwalk_task)
        
        return tasks
    
    def _generate_executable_tasks(self, material: Material, dependency: str) -> List[Task]:
        """Generate executable-specific analysis tasks"""
        tasks = []
        
        # Binary analysis
        binary_deep = Task(
            id=f"binary_deep_{material.id}",
            name="Deep Binary Analysis",
            description="Analyze binary structure and embedded data",
            analyzer="binary_analyzer",
            phase=AnalysisPhase.ANALYSIS,
            priority=80,
            dependencies={dependency},
            target_materials={material.id}
        )
        tasks.append(binary_deep)
        
        # Code analysis if it looks like a VM or script
        code_task = Task(
            id=f"code_analysis_{material.id}",
            name="Code Analysis",
            description="Analyze executable code and VM bytecode",
            analyzer="code_analyzer",
            phase=AnalysisPhase.ANALYSIS,
            priority=75,
            dependencies={dependency},
            target_materials={material.id}
        )
        tasks.append(code_task)
        
        return tasks
    
    def generate_material_tasks(self, material: Material, source_task_id: str) -> List[Task]:
        """Generate tasks for newly discovered material"""
        tasks = []
        
        # Basic format analysis for any new material
        format_task = Task(
            id=f"format_analysis_{material.id}",
            name=f"Format Analysis: {material.name}",
            description=f"Analyze format and structure of {material.name}",
            analyzer="binary_analyzer",
            phase=AnalysisPhase.CLASSIFICATION,
            priority=75,
            target_materials={material.id}
        )
        tasks.append(format_task)
        
        # Content-specific analysis based on material type
        if material.type == MaterialType.DECODED_TEXT:
            # Text analysis pipeline
            text_task = Task(
                id=f"text_deep_{material.id}",
                name=f"Text Analysis: {material.name}",
                description="Deep text pattern and encoding analysis",
                analyzer="text_analyzer",
                phase=AnalysisPhase.ANALYSIS,
                priority=70,
                dependencies={format_task.id},
                target_materials={material.id}
            )
            tasks.append(text_task)
            
            # Check for specific patterns
            if isinstance(material.content, str):
                pattern_tasks = self._generate_pattern_tasks(material, material.content)
                tasks.extend(pattern_tasks)
        
        elif material.type == MaterialType.EXTRACTED_BINARY:
            # Binary analysis
            binary_task = Task(
                id=f"binary_analysis_{material.id}",
                name=f"Binary Analysis: {material.name}",
                description="Analyze binary content and structure",
                analyzer="binary_analyzer",
                phase=AnalysisPhase.ANALYSIS,
                priority=70,
                dependencies={format_task.id},
                target_materials={material.id}
            )
            tasks.append(binary_task)
            
            # Crypto analysis for binary data
            crypto_task = Task(
                id=f"crypto_analysis_{material.id}",
                name=f"Crypto Analysis: {material.name}",
                description="Analyze for cryptographic content",
                analyzer="crypto_analyzer",
                phase=AnalysisPhase.ANALYSIS,
                priority=70,
                dependencies={format_task.id},
                target_materials={material.id}
            )
            tasks.append(crypto_task)
        
        elif material.type == MaterialType.CRYPTO_KEY:
            # Key analysis and validation
            key_task = Task(
                id=f"key_analysis_{material.id}",
                name=f"Key Analysis: {material.name}",
                description="Validate and analyze cryptographic key",
                analyzer="crypto_analyzer",
                phase=AnalysisPhase.ANALYSIS,
                priority=90,  # High priority for keys
                target_materials={material.id}
            )
            tasks.append(key_task)
        
        return tasks
    
    def _generate_pattern_tasks(self, material: Material, content: str) -> List[Task]:
        """Generate tasks based on detected patterns in content"""
        tasks = []
        
        # Check regular patterns
        for pattern, (analyzer, description) in self.pattern_tasks.items():
            if re.search(pattern, content):
                task_id = f"pattern_{analyzer}_{material.id}_{uuid.uuid4().hex[:8]}"
                pattern_task = Task(
                    id=task_id,
                    name=f"Pattern Analysis: {description}",
                    description=f"Analyze detected pattern: {description}",
                    analyzer=analyzer,
                    phase=AnalysisPhase.ANALYSIS,
                    priority=80,
                    target_materials={material.id}
                )
                tasks.append(pattern_task)
        
        # Check Arweave patterns
        for pattern, description in self.arweave_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                arweave_task = Task(
                    id=f"arweave_analysis_{material.id}_{uuid.uuid4().hex[:8]}",
                    name=f"Arweave Analysis: {description}",
                    description=f"Analyze Arweave-specific pattern: {description}",
                    analyzer="code_analyzer",  # Use code analyzer for Arweave tools
                    phase=AnalysisPhase.ANALYSIS,
                    priority=85,
                    target_materials={material.id}
                )
                tasks.append(arweave_task)
        
        return tasks
    
    def generate_synthesis_tasks(self, high_confidence_findings: List[Finding]) -> List[Task]:
        """Generate synthesis tasks when enough findings are available"""
        tasks = []
        
        if len(high_confidence_findings) < 3:
            return tasks
        
        # Group findings by type
        findings_by_type = {}
        for finding in high_confidence_findings:
            finding_type = finding.finding_type
            if finding_type not in findings_by_type:
                findings_by_type[finding_type] = []
            findings_by_type[finding_type].append(finding)
        
        # Cross-reference synthesis
        if len(findings_by_type) >= 2:
            synthesis_task = Task(
                id=f"cross_synthesis_{uuid.uuid4().hex[:8]}",
                name="Cross-Reference Synthesis",
                description="Synthesize findings from multiple analyzers",
                analyzer="crypto_analyzer",
                phase=AnalysisPhase.SYNTHESIS,
                priority=90,
                target_materials=set()  # Works with findings, not materials
            )
            tasks.append(synthesis_task)
        
        # Key material synthesis
        key_findings = [f for f in high_confidence_findings if 'key' in f.title.lower()]
        if len(key_findings) >= 2:
            key_synthesis = Task(
                id=f"key_synthesis_{uuid.uuid4().hex[:8]}",
                name="Cryptographic Key Synthesis",
                description="Combine multiple key-related findings",
                analyzer="crypto_analyzer",
                phase=AnalysisPhase.SYNTHESIS,
                priority=95,
                target_materials=set()
            )
            tasks.append(key_synthesis)
        
        # Solution attempt task
        solution_task = Task(
            id=f"solution_attempt_{uuid.uuid4().hex[:8]}",
            name="Solution Construction",
            description="Attempt to construct final solution from findings",
            analyzer="code_analyzer",  # Use code analyzer for flexible solution attempts
            phase=AnalysisPhase.SOLUTION,
            priority=100,
            target_materials=set()
        )
        tasks.append(solution_task)
        
        return tasks
    
    def generate_web_research_tasks(self, materials: List[Material]) -> List[Task]:
        """Generate web research tasks for external information"""
        tasks = []
        
        # Look for addresses, hashes, or other searchable content
        for material in materials:
            if material.type in [MaterialType.CRYPTO_KEY, MaterialType.CLUE]:
                if isinstance(material.content, str) and len(material.content) > 10:
                    web_task = Task(
                        id=f"web_research_{material.id}",
                        name=f"Web Research: {material.name}",
                        description=f"Research external information about {material.name}",
                        analyzer="web_analyzer",
                        phase=AnalysisPhase.ANALYSIS,
                        priority=60,  # Lower priority
                        target_materials={material.id}
                    )
                    tasks.append(web_task)
        
        return tasks
    
    def optimize_task_priorities(self, tasks: List[Task]) -> List[Task]:
        """Optimize task priorities based on dependencies and importance"""
        
        # Build dependency graph
        task_map = {task.id: task for task in tasks}
        
        for task in tasks:
            # Boost priority for tasks with many dependents
            dependents = [t for t in tasks if task.id in t.dependencies]
            task.priority += len(dependents) * 5
            
            # Boost priority for solution-phase tasks
            if task.phase == AnalysisPhase.SOLUTION:
                task.priority += 20
            
            # Boost priority for synthesis tasks
            if task.phase == AnalysisPhase.SYNTHESIS:
                task.priority += 15
            
            # Boost priority for high-value analyzers
            if task.analyzer in ['crypto_analyzer', 'image_analyzer']:
                task.priority += 10
        
        return tasks
    
    def generate_recovery_tasks(self, failed_tasks: List[Task]) -> List[Task]:
        """Generate recovery tasks for failed analysis"""
        recovery_tasks = []
        
        for failed_task in failed_tasks:
            # Try with a different analyzer if available
            alt_analyzers = self._get_alternative_analyzers(failed_task.analyzer)
            
            for alt_analyzer in alt_analyzers:
                recovery_task = Task(
                    id=f"recovery_{failed_task.id}_{alt_analyzer}",
                    name=f"Recovery: {failed_task.name}",
                    description=f"Retry analysis with {alt_analyzer}",
                    analyzer=alt_analyzer,
                    phase=failed_task.phase,
                    priority=failed_task.priority - 20,  # Lower priority
                    dependencies=failed_task.dependencies,
                    target_materials=failed_task.target_materials
                )
                recovery_tasks.append(recovery_task)
                break  # Only try one alternative per failed task
        
        return recovery_tasks
    
    def _get_alternative_analyzers(self, failed_analyzer: str) -> List[str]:
        """Get alternative analyzers for a failed one"""
        alternatives = {
            'image_analyzer': ['binary_analyzer', 'vision_analyzer'],
            'binary_analyzer': ['crypto_analyzer', 'encoding_analyzer'],
            'text_analyzer': ['encoding_analyzer', 'cipher_analyzer'],
            'crypto_analyzer': ['encoding_analyzer', 'blockchain_analyzer'],
            'vision_analyzer': ['image_analyzer'],
            'web_analyzer': ['code_analyzer']
        }
        
        return alternatives.get(failed_analyzer, ['code_analyzer'])  # Code analyzer as fallback
    
    def should_generate_emergency_tasks(self, state: WorkflowState) -> bool:
        """Check if we should generate emergency/fallback tasks"""
        progress = state.get_progress_summary()
        
        # Generate emergency tasks if:
        # 1. We're stuck (no progress for a while)
        # 2. Too many failures
        # 3. No high confidence findings after significant analysis
        
        return (
            progress['completion_percentage'] > 50 and 
            progress['high_confidence_findings'] == 0 and
            progress['failed_tasks'] > progress['completed_tasks'] * 0.3
        )
    
    def generate_emergency_tasks(self, state: WorkflowState) -> List[Task]:
        """Generate emergency/fallback tasks when normal analysis isn't working"""
        emergency_tasks = []
        
        # Brute force approach - try code analyzer on everything
        for material in state.materials.values():
            if material.type != MaterialType.CLUE:  # Skip low-value materials
                emergency_task = Task(
                    id=f"emergency_code_{material.id}",
                    name=f"Emergency Code Analysis: {material.name}",
                    description="Fallback code-based analysis attempt",
                    analyzer="code_analyzer",
                    phase=AnalysisPhase.ANALYSIS,
                    priority=30,  # Low priority
                    target_materials={material.id}
                )
                emergency_tasks.append(emergency_task)
        
        # Manual pattern search
        manual_task = Task(
            id=f"manual_pattern_search_{uuid.uuid4().hex[:8]}",
            name="Manual Pattern Search",
            description="Manual search for common puzzle patterns",
            analyzer="text_pattern_analyzer",
            phase=AnalysisPhase.ANALYSIS,
            priority=35,
            target_materials=set(state.materials.keys())
        )
        emergency_tasks.append(manual_task)
        
        return emergency_tasks