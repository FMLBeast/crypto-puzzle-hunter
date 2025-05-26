#!/usr/bin/env python3
"""
Analyzer Bridge System for Crypto Hunter
Seamlessly bridges new workflow system with existing analyzers
"""

import os
import json
import tempfile
import traceback
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Callable
import logging

from enhanced_state_management import (
    Material, Finding, Task, WorkflowState, 
    MaterialType, AnalysisPhase, TaskStatus
)
from core.state import State
from analyzers.base import get_analyzer, get_all_analyzers
from core.arweave_tools_main import get_tool, list_tools


class AnalyzerBridge:
    """Bridges workflow system with existing Crypto Hunter analyzers"""
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)
        
        # Get all available analyzers
        self.analyzers = get_all_analyzers()
        
        # Get Arweave tools
        self.arweave_tools = self._load_arweave_tools()
        
        # Temp file tracking for cleanup
        self.temp_files = set()
        
        # Analyzer-specific configuration
        self.analyzer_config = {
            'image_analyzer': {
                'supported_formats': ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff'],
                'max_file_size': 50 * 1024 * 1024,  # 50MB
                'requires_binary': True
            },
            'binary_analyzer': {
                'supported_formats': ['*'],
                'requires_binary': True
            },
            'text_analyzer': {
                'requires_text': True,
                'max_text_length': 1000000
            },
            'encoding_analyzer': {
                'requires_text': True,
                'max_text_length': 1000000
            },
            'cipher_analyzer': {
                'requires_text': True,
                'max_text_length': 100000
            },
            'crypto_analyzer': {
                'supports_both': True
            },
            'blockchain_analyzer': {
                'requires_text': True,
                'pattern_based': True
            },
            'vision_analyzer': {
                'supported_formats': ['.png', '.jpg', '.jpeg', '.gif', '.bmp'],
                'requires_api': True,
                'max_file_size': 20 * 1024 * 1024
            },
            'web_analyzer': {
                'requires_text': True,
                'requires_network': True
            },
            'code_analyzer': {
                'supports_both': True,
                'flexible': True
            }
        }
    
    def _load_arweave_tools(self) -> Dict[str, Callable]:
        """Load available Arweave tools"""
        try:
            tools = {}
            tool_list = list_tools()
            for tool_info in tool_list:
                tool_name = tool_info['name']
                tool_func = get_tool(tool_name)
                if tool_func:
                    tools[tool_name] = tool_func
            return tools
        except Exception as e:
            self.logger.warning(f"Failed to load Arweave tools: {e}")
            return {}
    
    def execute_task(self, task: Task, workflow_state: WorkflowState) -> Tuple[bool, Dict[str, Any]]:
        """
        Execute a task using the appropriate analyzer
        
        Returns:
            (success, result_data)
        """
        try:
            if self.verbose:
                print(f"🔧 Executing task: {task.name} [{task.analyzer}]")
            
            # Check if analyzer is available
            if task.analyzer not in self.analyzers:
                # Check if it's an Arweave tool
                if self._is_arweave_task(task):
                    return self._execute_arweave_task(task, workflow_state)
                else:
                    raise ValueError(f"Analyzer {task.analyzer} not available")
            
            # Pre-execution validation
            if not self._validate_task_execution(task, workflow_state):
                return False, {'error': 'Task validation failed'}
            
            # Execute based on analyzer type
            if task.analyzer == 'code_analyzer':
                return self._execute_code_analyzer(task, workflow_state)
            elif task.analyzer in ['image_analyzer', 'vision_analyzer']:
                return self._execute_image_analyzer(task, workflow_state)
            elif task.analyzer in ['text_analyzer', 'encoding_analyzer', 'cipher_analyzer']:
                return self._execute_text_analyzer(task, workflow_state)
            elif task.analyzer == 'binary_analyzer':
                return self._execute_binary_analyzer(task, workflow_state)
            elif task.analyzer == 'crypto_analyzer':
                return self._execute_crypto_analyzer(task, workflow_state)
            elif task.analyzer == 'blockchain_analyzer':
                return self._execute_blockchain_analyzer(task, workflow_state)
            elif task.analyzer == 'web_analyzer':
                return self._execute_web_analyzer(task, workflow_state)
            else:
                # Generic execution
                return self._execute_generic_analyzer(task, workflow_state)
                
        except Exception as e:
            error_msg = f"Task execution failed: {str(e)}"
            if self.verbose:
                print(f"❌ {error_msg}")
                traceback.print_exc()
            return False, {'error': error_msg, 'traceback': traceback.format_exc()}
    
    def _validate_task_execution(self, task: Task, workflow_state: WorkflowState) -> bool:
        """Validate that task can be executed"""
        config = self.analyzer_config.get(task.analyzer, {})
        
        # Check if target materials exist and are compatible
        for material_id in task.target_materials:
            if material_id not in workflow_state.materials:
                return False
            
            material = workflow_state.materials[material_id]
            
            # Check file size limits
            max_size = config.get('max_file_size')
            if max_size and material.size and material.size > max_size:
                return False
            
            # Check format compatibility
            supported_formats = config.get('supported_formats', ['*'])
            if supported_formats != ['*']:
                material_ext = Path(material.name).suffix.lower()
                if material_ext not in supported_formats:
                    return False
        
        return True
    
    def _create_legacy_state(self, task: Task, workflow_state: WorkflowState) -> State:
        """Create legacy State object for analyzer compatibility"""
        legacy_state = State()
        
        # Set main puzzle file
        source_materials = [m for m in workflow_state.materials.values() 
                          if m.type == MaterialType.SOURCE_FILE]
        if source_materials:
            source = source_materials[0]
            legacy_state.set_puzzle_file(source.file_path or source.content)
        
        # Process target materials
        for material_id in task.target_materials:
            if material_id in workflow_state.materials:
                material = workflow_state.materials[material_id]
                self._add_material_to_legacy_state(material, legacy_state)
        
        # Add context from previous findings
        relevant_findings = self._get_relevant_findings(task, workflow_state)
        for finding in relevant_findings:
            legacy_state.add_insight(
                f"[{finding.analyzer}] {finding.title}: {finding.description}",
                finding.analyzer
            )
        
        return legacy_state
    
    def _add_material_to_legacy_state(self, material: Material, legacy_state: State):
        """Add material to legacy state"""
        if material.type == MaterialType.SOURCE_FILE:
            if material.file_path:
                legacy_state.set_puzzle_file(material.file_path)
            else:
                # Create temp file
                temp_file = self._create_temp_file(material)
                legacy_state.set_puzzle_file(temp_file)
        
        elif material.type == MaterialType.DECODED_TEXT:
            if isinstance(material.content, str):
                legacy_state.set_puzzle_text(material.content)
            elif isinstance(material.content, bytes):
                try:
                    text = material.content.decode('utf-8', errors='ignore')
                    legacy_state.set_puzzle_text(text)
                except:
                    pass
        
        elif material.type in [MaterialType.EXTRACTED_BINARY, MaterialType.CRYPTO_KEY]:
            if isinstance(material.content, bytes):
                legacy_state.add_related_file(material.name, material.content)
            elif isinstance(material.content, str):
                legacy_state.add_related_file(material.name, material.content.encode())
        
        # Add material metadata as clues
        if material.metadata:
            for key, value in material.metadata.items():
                legacy_state.add_clue(f"{key}: {value}", f"material_{material.id}")
    
    def _create_temp_file(self, material: Material) -> str:
        """Create temporary file for material"""
        suffix = Path(material.name).suffix or '.tmp'
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix=suffix) as f:
            if isinstance(material.content, bytes):
                f.write(material.content)
            elif isinstance(material.content, str):
                f.write(material.content.encode('utf-8'))
            
            temp_path = f.name
            self.temp_files.add(temp_path)
            return temp_path
    
    def _get_relevant_findings(self, task: Task, workflow_state: WorkflowState) -> List[Finding]:
        """Get relevant findings for task context"""
        relevant = []
        
        # Get findings from target materials
        for material_id in task.target_materials:
            material_findings = [f for f in workflow_state.findings.values() 
                               if f.material_id == material_id]
            relevant.extend(material_findings)
        
        # Get high-confidence findings from same analyzer
        analyzer_findings = [f for f in workflow_state.findings.values()
                           if f.analyzer == task.analyzer and f.confidence > 0.7]
        relevant.extend(analyzer_findings[:5])  # Limit to avoid overwhelming
        
        return relevant
    
    def _execute_generic_analyzer(self, task: Task, workflow_state: WorkflowState) -> Tuple[bool, Dict[str, Any]]:
        """Generic analyzer execution"""
        analyzer_func = self.analyzers[task.analyzer]
        legacy_state = self._create_legacy_state(task, workflow_state)
        
        # Execute analyzer
        try:
            result_state = analyzer_func(legacy_state)
            return self._process_analyzer_results(task, legacy_state, result_state, workflow_state)
        except Exception as e:
            return False, {'error': str(e)}
    
    def _execute_code_analyzer(self, task: Task, workflow_state: WorkflowState) -> Tuple[bool, Dict[str, Any]]:
        """Execute code analyzer with enhanced task description"""
        analyzer_func = self.analyzers['code_analyzer']
        legacy_state = self._create_legacy_state(task, workflow_state)
        
        # Generate enhanced task description
        task_description = self._generate_code_task_description(task, workflow_state)
        
        try:
            # Code analyzer expects task_description parameter
            result_state = analyzer_func(legacy_state, task_description=task_description)
            return self._process_analyzer_results(task, legacy_state, result_state, workflow_state)
        except Exception as e:
            return False, {'error': str(e)}
    
    def _execute_image_analyzer(self, task: Task, workflow_state: WorkflowState) -> Tuple[bool, Dict[str, Any]]:
        """Execute image analyzer with enhanced parameters"""
        analyzer_func = self.analyzers[task.analyzer]
        legacy_state = self._create_legacy_state(task, workflow_state)
        
        try:
            # Image analyzer might need special parameters
            kwargs = {}
            if task.analyzer == 'vision_analyzer':
                kwargs.update({
                    'provider': 'anthropic',  # Default provider
                    'api_key': None,
                    'model': None,
                    'max_image_size': 1024
                })
            
            result_state = analyzer_func(legacy_state, **kwargs)
            return self._process_analyzer_results(task, legacy_state, result_state, workflow_state)
        except Exception as e:
            return False, {'error': str(e)}
    
    def _execute_text_analyzer(self, task: Task, workflow_state: WorkflowState) -> Tuple[bool, Dict[str, Any]]:
        """Execute text-based analyzers"""
        analyzer_func = self.analyzers[task.analyzer]
        legacy_state = self._create_legacy_state(task, workflow_state)
        
        try:
            # Cipher analyzer might need specific parameters
            kwargs = {}
            if task.analyzer == 'cipher_analyzer':
                # Try to infer cipher type from task name or findings
                cipher_type = self._infer_cipher_type(task, workflow_state)
                if cipher_type:
                    kwargs['cipher_type'] = cipher_type
                    kwargs['input_data'] = legacy_state.puzzle_text or ""
            
            result_state = analyzer_func(legacy_state, **kwargs)
            return self._process_analyzer_results(task, legacy_state, result_state, workflow_state)
        except Exception as e:
            return False, {'error': str(e)}
    
    def _execute_binary_analyzer(self, task: Task, workflow_state: WorkflowState) -> Tuple[bool, Dict[str, Any]]:
        """Execute binary analyzer"""
        analyzer_func = self.analyzers['binary_analyzer']
        legacy_state = self._create_legacy_state(task, workflow_state)
        
        try:
            result_state = analyzer_func(legacy_state)
            return self._process_analyzer_results(task, legacy_state, result_state, workflow_state)
        except Exception as e:
            return False, {'error': str(e)}
    
    def _execute_crypto_analyzer(self, task: Task, workflow_state: WorkflowState) -> Tuple[bool, Dict[str, Any]]:
        """Execute crypto analyzer"""
        analyzer_func = self.analyzers['crypto_analyzer']
        legacy_state = self._create_legacy_state(task, workflow_state)
        
        try:
            result_state = analyzer_func(legacy_state)
            return self._process_analyzer_results(task, legacy_state, result_state, workflow_state)
        except Exception as e:
            return False, {'error': str(e)}
    
    def _execute_blockchain_analyzer(self, task: Task, workflow_state: WorkflowState) -> Tuple[bool, Dict[str, Any]]:
        """Execute blockchain analyzer"""
        analyzer_func = self.analyzers['blockchain_analyzer']
        legacy_state = self._create_legacy_state(task, workflow_state)
        
        try:
            # Blockchain analyzer might need hex strings and metadata
            kwargs = {}
            hex_strings = self._extract_hex_strings(task, workflow_state)
            if hex_strings:
                kwargs['hex_strings'] = hex_strings
                kwargs['metadata'] = {'task_id': task.id}
            
            result_state = analyzer_func(legacy_state, **kwargs)
            return self._process_analyzer_results(task, legacy_state, result_state, workflow_state)
        except Exception as e:
            return False, {'error': str(e)}
    
    def _execute_web_analyzer(self, task: Task, workflow_state: WorkflowState) -> Tuple[bool, Dict[str, Any]]:
        """Execute web analyzer"""
        analyzer_func = self.analyzers['web_analyzer']
        legacy_state = self._create_legacy_state(task, workflow_state)
        
        try:
            # Generate search query from materials
            query = self._generate_web_query(task, workflow_state)
            
            result_state = analyzer_func(legacy_state, query=query)
            return self._process_analyzer_results(task, legacy_state, result_state, workflow_state)
        except Exception as e:
            return False, {'error': str(e)}
    
    def _is_arweave_task(self, task: Task) -> bool:
        """Check if task involves Arweave tools"""
        return (
            'arweave' in task.name.lower() or
            'arweave' in task.description.lower() or
            any(tool in task.description.lower() for tool in self.arweave_tools.keys())
        )
    
    def _execute_arweave_task(self, task: Task, workflow_state: WorkflowState) -> Tuple[bool, Dict[str, Any]]:
        """Execute Arweave-specific task"""
        try:
            # Determine which Arweave tool to use
            tool_name = self._determine_arweave_tool(task, workflow_state)
            
            if tool_name not in self.arweave_tools:
                return False, {'error': f'Arweave tool {tool_name} not available'}
            
            tool_func = self.arweave_tools[tool_name]
            
            # Prepare tool parameters
            params = self._prepare_arweave_params(tool_name, task, workflow_state)
            
            # Execute tool
            result = tool_func(**params)
            
            # Process Arweave tool results
            return self._process_arweave_results(task, tool_name, result, workflow_state)
            
        except Exception as e:
            return False, {'error': str(e)}
    
    def _determine_arweave_tool(self, task: Task, workflow_state: WorkflowState) -> str:
        """Determine which Arweave tool to use"""
        task_lower = task.description.lower()
        
        if 'algebra' in task_lower or 'equation' in task_lower:
            return 'algebra_solver'
        elif 'beep' in task_lower or 'pattern' in task_lower:
            return 'beep_pattern_finder'
        elif 'riddle' in task_lower:
            return 'riddle_lookup'
        elif 'coordinate' in task_lower or 'geographic' in task_lower:
            return 'coordinate_calculator'
        elif 'linear' in task_lower or 'programming' in task_lower:
            return 'linear_program_solver'
        elif 'combinatorics' in task_lower:
            return 'combinatorics_calculator'
        elif 'knowledge' in task_lower or 'graph' in task_lower:
            return 'knowledge_graph_query'
        elif 'timeline' in task_lower:
            return 'timeline_analyzer'
        else:
            return 'analyze_stego'  # Default steganography tool
    
    def _prepare_arweave_params(self, tool_name: str, task: Task, workflow_state: WorkflowState) -> Dict[str, Any]:
        """Prepare parameters for Arweave tool"""
        params = {}
        
        # Get material content for parameters
        material_content = []
        for material_id in task.target_materials:
            if material_id in workflow_state.materials:
                material = workflow_state.materials[material_id]
                material_content.append(material.content)
        
        # Tool-specific parameter preparation
        if tool_name == 'algebra_solver':
            params = {
                'equations': self._extract_equations(material_content),
                'variables': self._extract_variables(material_content)
            }
        elif tool_name == 'coordinate_calculator':
            coords = self._extract_coordinates(material_content)
            if coords:
                params = {
                    'lat': coords[0],
                    'lon': coords[1],
                    'operation': 'analyze'
                }
        elif tool_name == 'riddle_lookup':
            text_content = self._get_text_content(material_content)
            params = {'riddle_text': text_content}
        else:
            # Generic parameters
            if material_content:
                if isinstance(material_content[0], bytes):
                    params = {'data': material_content[0], 'file_type': 'binary'}
                else:
                    params = {'text': str(material_content[0])}
        
        return params
    
    def _process_analyzer_results(self, task: Task, legacy_state: State, result_state: State, 
                                workflow_state: WorkflowState) -> Tuple[bool, Dict[str, Any]]:
        """Process results from analyzer execution"""
        results = {'insights': [], 'transformations': [], 'new_materials': []}
        
        # Process insights
        if hasattr(result_state, 'insights'):
            for insight in result_state.insights:
                finding_id = self._create_finding_from_insight(insight, task, workflow_state)
                results['insights'].append(finding_id)
        
        # Process transformations
        if hasattr(result_state, 'transformations'):
            for transformation in result_state.transformations:
                finding_id, material_id = self._create_finding_from_transformation(
                    transformation, task, workflow_state)
                results['transformations'].append(finding_id)
                if material_id:
                    results['new_materials'].append(material_id)
        
        # Check for solution
        if hasattr(result_state, 'solution') and result_state.solution:
            workflow_state.solution_candidates.append(result_state.solution)
            
            # Validate solution
            if self._validate_solution(result_state.solution, workflow_state):
                workflow_state.final_solution = result_state.solution
                results['solution_found'] = True
        
        return True, results
    
    def _process_arweave_results(self, task: Task, tool_name: str, result: Dict[str, Any], 
                               workflow_state: WorkflowState) -> Tuple[bool, Dict[str, Any]]:
        """Process results from Arweave tool execution"""
        results = {'tool_used': tool_name, 'findings': []}
        
        # Extract meaningful results
        if isinstance(result, dict):
            if 'solution' in result:
                workflow_state.solution_candidates.append(str(result['solution']))
                results['solution_candidate'] = result['solution']
            
            if 'results' in result:
                finding_id = self._create_finding_from_arweave_result(result, task, workflow_state)
                results['findings'].append(finding_id)
        
        return True, results
    
    def _create_finding_from_insight(self, insight: Dict[str, Any], task: Task, 
                                   workflow_state: WorkflowState) -> str:
        """Create finding from analyzer insight"""
        finding = Finding(
            id=f"finding_{task.id}_{len(workflow_state.findings)}",
            analyzer=task.analyzer,
            material_id=list(task.target_materials)[0] if task.target_materials else "unknown",
            finding_type="insight",
            title=insight.get('text', 'Insight'),
            description=f"Insight from {task.analyzer}: {insight.get('text', '')}",
            confidence=0.6,
            data=insight
        )
        
        return workflow_state.add_finding(finding)
    
    def _create_finding_from_transformation(self, transformation: Dict[str, Any], task: Task, 
                                          workflow_state: WorkflowState) -> Tuple[str, Optional[str]]:
        """Create finding and possibly material from transformation"""
        # Create finding
        finding = Finding(
            id=f"finding_{task.id}_{len(workflow_state.findings)}",
            analyzer=task.analyzer,
            material_id=list(task.target_materials)[0] if task.target_materials else "unknown",
            finding_type="transformation",
            title=transformation.get('name', 'Transformation'),
            description=transformation.get('description', ''),
            confidence=0.7,
            data=transformation
        )
        
        finding_id = workflow_state.add_finding(finding)
        
        # Check if output should become material
        output_data = transformation.get('output_data')
        material_id = None
        
        if output_data and self._is_significant_output(output_data):
            material_type = self._determine_material_type_from_transformation(transformation)
            
            material = Material(
                id=f"material_{task.id}_{len(workflow_state.materials)}",
                name=transformation.get('name', 'Unknown'),
                type=material_type,
                content=output_data,
                source=task.id,
                metadata={
                    'from_transformation': True,
                    'analyzer': task.analyzer,
                    'confidence': 0.7
                }
            )
            
            material_id = workflow_state.add_material(material)
        
        return finding_id, material_id
    
    def _create_finding_from_arweave_result(self, result: Dict[str, Any], task: Task, 
                                          workflow_state: WorkflowState) -> str:
        """Create finding from Arweave tool result"""
        finding = Finding(
            id=f"arweave_finding_{task.id}_{len(workflow_state.findings)}",
            analyzer="arweave_tool",
            material_id=list(task.target_materials)[0] if task.target_materials else "unknown",
            finding_type="arweave_result",
            title=f"Arweave Tool Result",
            description=f"Result from Arweave analysis",
            confidence=0.8,
            data=result
        )
        
        return workflow_state.add_finding(finding)
    
    # Helper methods
    def _generate_code_task_description(self, task: Task, workflow_state: WorkflowState) -> str:
        """Generate enhanced task description for code analyzer"""
        base_desc = task.description
        
        # Add context from materials
        context = []
        for material_id in task.target_materials:
            if material_id in workflow_state.materials:
                material = workflow_state.materials[material_id]
                context.append(f"Material: {material.name} ({material.type.value})")
        
        # Add context from recent findings
        recent_findings = sorted(workflow_state.findings.values(), 
                               key=lambda f: f.created_at, reverse=True)[:5]
        for finding in recent_findings:
            if finding.confidence > 0.7:
                context.append(f"Finding: {finding.title}")
        
        enhanced_desc = base_desc
        if context:
            enhanced_desc += f"\n\nContext:\n" + "\n".join(context)
        
        return enhanced_desc
    
    def _infer_cipher_type(self, task: Task, workflow_state: WorkflowState) -> Optional[str]:
        """Infer cipher type from task and context"""
        task_lower = task.name.lower() + " " + task.description.lower()
        
        cipher_keywords = {
            'caesar': 'caesar',
            'vigenere': 'vigenere', 
            'substitution': 'substitution',
            'transposition': 'transposition',
            'xor': 'xor',
            'rot13': 'caesar',
            'atbash': 'atbash'
        }
        
        for keyword, cipher_type in cipher_keywords.items():
            if keyword in task_lower:
                return cipher_type
        
        return None
    
    def _extract_hex_strings(self, task: Task, workflow_state: WorkflowState) -> List[str]:
        """Extract hex strings from materials"""
        hex_strings = []
        
        for material_id in task.target_materials:
            if material_id in workflow_state.materials:
                material = workflow_state.materials[material_id]
                if isinstance(material.content, str):
                    # Look for hex patterns
                    import re
                    hex_matches = re.findall(r'[0-9a-fA-F]{8,}', material.content)
                    hex_strings.extend(hex_matches)
        
        return hex_strings
    
    def _generate_web_query(self, task: Task, workflow_state: WorkflowState) -> str:
        """Generate web search query from materials"""
        query_parts = []
        
        for material_id in task.target_materials:
            if material_id in workflow_state.materials:
                material = workflow_state.materials[material_id]
                if material.type == MaterialType.CLUE:
                    query_parts.append(str(material.content))
                elif material.type == MaterialType.CRYPTO_KEY:
                    # Search for key format info
                    query_parts.append(f"cryptographic key format {material.name}")
        
        return " ".join(query_parts[:3])  # Limit query length
    
    def _is_significant_output(self, output_data: Any) -> bool:
        """Check if output is significant enough to be material"""
        if isinstance(output_data, str):
            return len(output_data) > 10 and not output_data.isspace()
        elif isinstance(output_data, bytes):
            return len(output_data) > 10
        elif isinstance(output_data, (list, dict)):
            return len(output_data) > 0
        return False
    
    def _determine_material_type_from_transformation(self, transformation: Dict[str, Any]) -> MaterialType:
        """Determine material type from transformation"""
        name = transformation.get('name', '').lower()
        
        if 'key' in name or 'private' in name:
            return MaterialType.CRYPTO_KEY
        elif 'extract' in name or 'binary' in name:
            return MaterialType.EXTRACTED_BINARY
        elif 'decode' in name or 'text' in name:
            return MaterialType.DECODED_TEXT
        elif 'pattern' in name:
            return MaterialType.PATTERN
        else:
            return MaterialType.EXTRACTED_BINARY
    
    def _validate_solution(self, solution: str, workflow_state: WorkflowState) -> bool:
        """Validate if solution looks legitimate"""
        if not solution or len(solution) < 5:
            return False
        
        # Check common solution formats
        if solution.startswith(('flag{', 'FLAG{', 'CTF{')):
            return solution.endswith('}')
        
        # Check if it's a hex key
        if len(solution) in [32, 64] and all(c in '0123456789abcdefABCDEF' for c in solution):
            return True
        
        # Check if it's printable and reasonable length
        return solution.isprintable() and 5 <= len(solution) <= 200
    
    # Arweave helper methods
    def _extract_equations(self, content_list: List[Any]) -> List[str]:
        """Extract equations from content"""
        equations = []
        for content in content_list:
            if isinstance(content, str):
                # Look for equation patterns
                import re
                eq_patterns = re.findall(r'[a-zA-Z\+\-\*\/\=\s\d]+\=\s*\d+', content)
                equations.extend(eq_patterns)
        return equations[:10]  # Limit
    
    def _extract_variables(self, content_list: List[Any]) -> List[str]:
        """Extract variables from content"""
        variables = set()
        for content in content_list:
            if isinstance(content, str):
                import re
                var_matches = re.findall(r'\b[a-zA-Z]\b', content)
                variables.update(var_matches)
        return list(variables)[:10]  # Limit
    
    def _extract_coordinates(self, content_list: List[Any]) -> Optional[Tuple[float, float]]:
        """Extract coordinates from content"""
        for content in content_list:
            if isinstance(content, str):
                import re
                coord_match = re.search(r'(-?\d+\.?\d*)\s*,\s*(-?\d+\.?\d*)', content)
                if coord_match:
                    try:
                        lat = float(coord_match.group(1))
                        lon = float(coord_match.group(2))
                        return (lat, lon)
                    except:
                        pass
        return None
    
    def _get_text_content(self, content_list: List[Any]) -> str:
        """Get text content from materials"""
        text_parts = []
        for content in content_list:
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, bytes):
                try:
                    text_parts.append(content.decode('utf-8', errors='ignore'))
                except:
                    pass
        return " ".join(text_parts)[:1000]  # Limit length
    
    def cleanup(self):
        """Clean up temporary files"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except:
                pass
        self.temp_files.clear()
    
    def __del__(self):
        """Cleanup on destruction"""
        self.cleanup()