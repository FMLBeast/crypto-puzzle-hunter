#!/usr/bin/env python3
"""
Enhanced Workflow Orchestrator for Crypto Hunter
Intelligent orchestration with LLM guidance and adaptive task generation
"""

import os
import time
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, PriorityQueue
import logging

from enhanced_state_management import (
    WorkflowOrchestrator, WorkflowState, Task, Material, Finding,
    AnalysisPhase, TaskStatus, MaterialType
)
from task_factory import TaskFactory
from analyzer_bridge import AnalyzerBridge
from core.agent import CryptoAgent


class EnhancedOrchestrator(WorkflowOrchestrator):
    """Enhanced orchestrator with intelligent task generation and LLM guidance"""
    
    def __init__(self, puzzle_file: str, llm_agent: Optional[CryptoAgent] = None, 
                 max_workers: int = 3, verbose: bool = True):
        super().__init__(puzzle_file)
        
        self.llm_agent = llm_agent
        self.max_workers = max_workers
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)
        
        # Enhanced components
        self.task_factory = TaskFactory(self.state)
        self.analyzer_bridge = AnalyzerBridge(verbose=verbose)
        
        # Execution control
        self.execution_lock = threading.Lock()
        self.stop_requested = False
        self.pause_requested = False
        
        # Task scheduling
        self.task_queue = PriorityQueue()
        self.running_tasks = {}
        self.completed_tasks_history = []
        
        # Performance tracking
        self.performance_stats = {
            'tasks_completed': 0,
            'tasks_failed': 0,
            'total_execution_time': 0,
            'analyzer_performance': {},
            'phase_durations': {}
        }
        
        # LLM orchestration
        self.llm_review_interval = 5  # Review every 5 completed tasks
        self.last_llm_review = 0
        self.llm_suggestions = []
        
        # Replace initial workflow with enhanced version
        self._setup_enhanced_initial_workflow()
    
    def _setup_enhanced_initial_workflow(self):
        """Setup enhanced initial workflow using task factory"""
        # Clear existing tasks
        self.state.tasks.clear()
        
        # Get source material
        source_materials = [m for m in self.state.materials.values() 
                           if m.type == MaterialType.SOURCE_FILE]
        
        if source_materials:
            source_material = source_materials[0]
            
            # Generate initial tasks using task factory
            initial_tasks = self.task_factory.generate_initial_tasks(source_material)
            
            # Add tasks to state
            for task in initial_tasks:
                self.state.add_task(task)
                # Add to priority queue
                self._enqueue_task(task)
            
            if self.verbose:
                print(f"✅ Generated {len(initial_tasks)} initial tasks")
    
    def _enqueue_task(self, task: Task):
        """Add task to priority queue"""
        # Priority queue uses negative priority for max-heap behavior
        priority = -task.priority
        self.task_queue.put((priority, task.id, task))
    
    def run_enhanced_workflow(self, max_iterations: int = 50, timeout_minutes: int = 30) -> bool:
        """
        Run enhanced workflow with intelligent orchestration
        
        Returns:
            True if solution found, False otherwise
        """
        start_time = datetime.now()
        timeout_time = start_time + timedelta(minutes=timeout_minutes)
        iteration = 0
        
        if self.verbose:
            print("🚀 Starting enhanced cryptographic workflow...")
            print(f"📊 Max iterations: {max_iterations}")
            print(f"⏱️  Timeout: {timeout_minutes} minutes")
            print(f"👥 Max workers: {self.max_workers}")
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                while (iteration < max_iterations and 
                       datetime.now() < timeout_time and 
                       not self.stop_requested):
                    
                    # Check if we have a solution
                    if self.state.final_solution:
                        if self.verbose:
                            print(f"🎯 Solution found: {self.state.final_solution}")
                        return True
                    
                    # Get next batch of tasks
                    next_tasks = self._get_next_executable_tasks()
                    
                    if not next_tasks:
                        # No executable tasks - try generating more or wait
                        if not self._handle_no_executable_tasks():
                            break
                        time.sleep(1.0)
                        continue
                    
                    # Execute tasks in parallel
                    future_to_task = {}
                    for task in next_tasks:
                        if not self.pause_requested:
                            future = executor.submit(self._execute_task_safely, task)
                            future_to_task[future] = task
                    
                    # Process completed tasks
                    for future in as_completed(future_to_task, timeout=30):
                        task = future_to_task[future]
                        
                        try:
                            success, result_data = future.result()
                            self._handle_task_completion(task, success, result_data)
                            
                            # Check if LLM review is needed
                            if self._should_trigger_llm_review():
                                self._perform_llm_review()
                            
                        except Exception as e:
                            self.logger.error(f"Task {task.name} failed with exception: {e}")
                            with self.execution_lock:
                                self.state.mark_task_failed(task.id, str(e))
                    
                    # Update phase and generate new tasks
                    self.update_phase_if_needed()
                    self._generate_adaptive_tasks()
                    
                    iteration += 1
                    
                    # Brief pause between iterations
                    if not self.stop_requested:
                        time.sleep(0.5)
        
        except KeyboardInterrupt:
            if self.verbose:
                print("\n🛑 Workflow interrupted by user")
            self.stop_requested = True
        
        finally:
            self.analyzer_bridge.cleanup()
        
        # Final analysis attempt
        if not self.state.final_solution and self.state.solution_candidates:
            self._attempt_final_solution_validation()
        
        # Performance summary
        self._log_performance_summary()
        
        return self.state.final_solution is not None
    
    def _get_next_executable_tasks(self) -> List[Task]:
        """Get next executable tasks from priority queue"""
        executable_tasks = []
        temp_tasks = []
        
        # Get tasks from priority queue
        while not self.task_queue.empty() and len(executable_tasks) < self.max_workers:
            try:
                priority, task_id, task = self.task_queue.get_nowait()
                
                # Check if task is still valid and executable
                if (task_id in self.state.tasks and 
                    task.status == TaskStatus.PENDING and
                    task.can_execute(self.state.completed_tasks)):
                    executable_tasks.append(task)
                else:
                    # Re-queue if not ready yet
                    if task_id in self.state.tasks and task.status == TaskStatus.PENDING:
                        temp_tasks.append((priority, task_id, task))
            except:
                break
        
        # Put back non-executable tasks
        for item in temp_tasks:
            self.task_queue.put(item)
        
        return executable_tasks
    
    def _execute_task_safely(self, task: Task) -> Tuple[bool, Dict[str, Any]]:
        """Safely execute a task with proper error handling"""
        task_start_time = time.time()
        
        with self.execution_lock:
            self.state.mark_task_started(task.id)
            self.running_tasks[task.id] = task
        
        try:
            if self.verbose:
                print(f"▶️  Executing: {task.name} [{task.analyzer}]")
            
            # Execute using analyzer bridge
            success, result_data = self.analyzer_bridge.execute_task(task, self.state)
            
            # Record performance
            execution_time = time.time() - task_start_time
            self._record_task_performance(task, execution_time, success)
            
            return success, result_data
            
        except Exception as e:
            execution_time = time.time() - task_start_time
            self._record_task_performance(task, execution_time, False)
            
            error_msg = f"Task execution failed: {str(e)}"
            self.logger.error(error_msg)
            
            return False, {'error': error_msg}
        
        finally:
            with self.execution_lock:
                if task.id in self.running_tasks:
                    del self.running_tasks[task.id]
    
    def _handle_task_completion(self, task: Task, success: bool, result_data: Dict[str, Any]):
        """Handle task completion and generate follow-up tasks"""
        with self.execution_lock:
            if success:
                self.state.mark_task_completed(task.id, result_data)
                self.performance_stats['tasks_completed'] += 1
                
                if self.verbose:
                    print(f"✅ Completed: {task.name}")
                    
                    # Show significant results
                    if 'new_materials' in result_data and result_data['new_materials']:
                        print(f"   📦 New materials: {len(result_data['new_materials'])}")
                    if 'solution_found' in result_data:
                        print(f"   🎯 Solution found!")
                
            else:
                error = result_data.get('error', 'Unknown error')
                self.state.mark_task_failed(task.id, error)
                self.performance_stats['tasks_failed'] += 1
                
                if self.verbose:
                    print(f"❌ Failed: {task.name} - {error}")
                
                # Generate recovery tasks for critical failures
                if task.priority > 80:
                    recovery_tasks = self.task_factory.generate_recovery_tasks([task])
                    for recovery_task in recovery_tasks[:1]:  # Limit recovery attempts
                        self.state.add_task(recovery_task)
                        self._enqueue_task(recovery_task)
            
            # Add to history
            self.completed_tasks_history.append({
                'task': task,
                'success': success,
                'result_data': result_data,
                'completed_at': datetime.now()
            })
    
    def _generate_adaptive_tasks(self):
        """Generate new tasks based on current state"""
        # Generate tasks for new materials
        new_materials = [m for m in self.state.materials.values() 
                        if not any(t.id.startswith(f"format_analysis_{m.id}") 
                                 for t in self.state.tasks.values())]
        
        for material in new_materials:
            if material.type != MaterialType.SOURCE_FILE:  # Skip source file
                material_tasks = self.task_factory.generate_material_tasks(
                    material, f"discovery_{material.id}")
                
                for task in material_tasks:
                    if task.id not in self.state.tasks:
                        self.state.add_task(task)
                        self._enqueue_task(task)
        
        # Generate synthesis tasks if we have enough findings
        high_conf_findings = self.state.get_high_confidence_findings()
        if len(high_conf_findings) >= 3:
            synthesis_tasks = self.task_factory.generate_synthesis_tasks(high_conf_findings)
            
            for task in synthesis_tasks:
                if task.id not in self.state.tasks:
                    self.state.add_task(task)
                    self._enqueue_task(task)
        
        # Generate web research tasks if appropriate
        if len(self.state.findings) > 10:  # Only after some progress
            clue_materials = self.state.get_materials_by_type(MaterialType.CLUE)
            web_tasks = self.task_factory.generate_web_research_tasks(clue_materials)
            
            for task in web_tasks:
                if task.id not in self.state.tasks:
                    self.state.add_task(task)
                    self._enqueue_task(task)
    
    def _handle_no_executable_tasks(self) -> bool:
        """Handle case where no tasks are executable"""
        if self.verbose:
            print("⏸️  No executable tasks - analyzing situation...")
        
        # Check if we're truly stuck
        pending_tasks = [t for t in self.state.tasks.values() if t.status == TaskStatus.PENDING]
        
        if not pending_tasks:
            # No pending tasks - check if we need emergency measures
            if self.task_factory.should_generate_emergency_tasks(self.state):
                if self.verbose:
                    print("🚨 Generating emergency tasks...")
                
                emergency_tasks = self.task_factory.generate_emergency_tasks(self.state)
                for task in emergency_tasks:
                    self.state.add_task(task)
                    self._enqueue_task(task)
                
                return len(emergency_tasks) > 0
            else:
                # Analysis appears complete
                return False
        
        # Check if dependencies are blocking progress
        self._resolve_dependency_issues()
        return True
    
    def _resolve_dependency_issues(self):
        """Try to resolve dependency issues"""
        pending_tasks = [t for t in self.state.tasks.values() if t.status == TaskStatus.PENDING]
        
        for task in pending_tasks:
            # Check if dependencies are failed/stuck
            failed_deps = [dep for dep in task.dependencies 
                          if dep in self.state.tasks and 
                             self.state.tasks[dep].status == TaskStatus.FAILED]
            
            if failed_deps:
                # Remove failed dependencies or create alternatives
                task.dependencies = task.dependencies - set(failed_deps)
                
                if self.verbose:
                    print(f"🔧 Resolved dependencies for {task.name}")
                
                # Re-queue the task
                self._enqueue_task(task)
    
    def _should_trigger_llm_review(self) -> bool:
        """Check if LLM review should be triggered"""
        if not self.llm_agent:
            return False
        
        completed_count = self.performance_stats['tasks_completed']
        return (completed_count > 0 and 
                completed_count % self.llm_review_interval == 0 and
                completed_count > self.last_llm_review)
    
    def _perform_llm_review(self):
        """Perform LLM review of progress and get suggestions"""
        if not self.llm_agent:
            return
        
        try:
            if self.verbose:
                print("🤖 Requesting LLM analysis review...")
            
            # Prepare context for LLM
            context = self._prepare_llm_context()
            
            # This would integrate with your existing LLM orchestration
            # For now, simulate LLM suggestions
            suggestions = self._simulate_llm_suggestions(context)
            
            self.llm_suggestions.extend(suggestions)
            self.last_llm_review = self.performance_stats['tasks_completed']
            
            # Apply suggestions
            self._apply_llm_suggestions(suggestions)
            
            if self.verbose:
                print(f"🤖 Applied {len(suggestions)} LLM suggestions")
                
        except Exception as e:
            self.logger.warning(f"LLM review failed: {e}")
    
    def _prepare_llm_context(self) -> Dict[str, Any]:
        """Prepare context for LLM review"""
        recent_findings = sorted(
            self.state.findings.values(),
            key=lambda f: f.created_at,
            reverse=True
        )[:10]
        
        context = {
            'progress_summary': self.state.get_progress_summary(),
            'recent_findings': [
                {
                    'title': f.title,
                    'analyzer': f.analyzer,
                    'confidence': f.confidence,
                    'description': f.description
                }
                for f in recent_findings
            ],
            'materials_summary': {
                mat_type.value: len(self.state.get_materials_by_type(mat_type))
                for mat_type in MaterialType
            },
            'current_phase': self.state.current_phase.value,
            'solution_candidates': self.state.solution_candidates[-5:],  # Last 5
            'performance_stats': self.performance_stats
        }
        
        return context
    
    def _simulate_llm_suggestions(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Simulate LLM suggestions (replace with actual LLM integration)"""
        suggestions = []
        
        progress = context['progress_summary']
        
        # Suggest phase advancement if stuck
        if progress['completion_percentage'] > 70 and progress['high_confidence_findings'] == 0:
            suggestions.append({
                'type': 'phase_advance',
                'description': 'Consider advancing to synthesis phase',
                'priority': 80
            })
        
        # Suggest specific analyzers based on materials
        if context['materials_summary'].get('extracted_binary', 0) > 0:
            suggestions.append({
                'type': 'analyzer_focus',
                'analyzer': 'crypto_analyzer',
                'description': 'Focus on cryptographic analysis of extracted binaries',
                'priority': 85
            })
        
        # Suggest solution attempts if enough findings
        if progress['high_confidence_findings'] >= 3:
            suggestions.append({
                'type': 'solution_attempt',
                'description': 'Attempt solution synthesis from high-confidence findings',
                'priority': 95
            })
        
        return suggestions
    
    def _apply_llm_suggestions(self, suggestions: List[Dict[str, Any]]):
        """Apply LLM suggestions"""
        for suggestion in suggestions:
            suggestion_type = suggestion.get('type')
            
            if suggestion_type == 'phase_advance':
                # Force phase advancement
                phases = list(AnalysisPhase)
                current_index = phases.index(self.state.current_phase)
                if current_index + 1 < len(phases):
                    self.state.current_phase = phases[current_index + 1]
            
            elif suggestion_type == 'analyzer_focus':
                # Create focused tasks for specific analyzer
                analyzer = suggestion.get('analyzer')
                if analyzer:
                    self._create_focused_analyzer_tasks(analyzer, suggestion.get('priority', 70))
            
            elif suggestion_type == 'solution_attempt':
                # Create solution synthesis task
                solution_task = Task(
                    id=f"llm_solution_attempt_{int(time.time())}",
                    name="LLM-Suggested Solution Attempt",
                    description="Solution attempt based on LLM analysis",
                    analyzer="code_analyzer",
                    phase=AnalysisPhase.SOLUTION,
                    priority=suggestion.get('priority', 90),
                    target_materials=set()
                )
                
                self.state.add_task(solution_task)
                self._enqueue_task(solution_task)
    
    def _create_focused_analyzer_tasks(self, analyzer: str, priority: int):
        """Create focused tasks for specific analyzer"""
        # Find materials that haven't been analyzed by this analyzer yet
        unanalyzed_materials = []
        
        for material in self.state.materials.values():
            if material.type != MaterialType.SOURCE_FILE:
                # Check if this material has been analyzed by this analyzer
                material_tasks = [t for t in self.state.tasks.values() 
                                if material.id in t.target_materials and t.analyzer == analyzer]
                
                if not material_tasks:
                    unanalyzed_materials.append(material)
        
        # Create focused tasks
        for material in unanalyzed_materials[:3]:  # Limit to avoid overwhelming
            focused_task = Task(
                id=f"focused_{analyzer}_{material.id}_{int(time.time())}",
                name=f"Focused {analyzer.title()}: {material.name}",
                description=f"LLM-suggested focused analysis using {analyzer}",
                analyzer=analyzer,
                phase=AnalysisPhase.ANALYSIS,
                priority=priority,
                target_materials={material.id}
            )
            
            self.state.add_task(focused_task)
            self._enqueue_task(focused_task)
    
    def _attempt_final_solution_validation(self):
        """Attempt final validation of solution candidates"""
        if self.verbose:
            print("🔍 Performing final solution validation...")
        
        # Score solution candidates
        scored_candidates = []
        for candidate in self.state.solution_candidates:
            score = self._score_solution_candidate(candidate)
            scored_candidates.append((score, candidate))
        
        # Sort by score
        scored_candidates.sort(reverse=True)
        
        # Take the best candidate if it's good enough
        if scored_candidates and scored_candidates[0][0] > 0.7:
            self.state.final_solution = scored_candidates[0][1]
            
            if self.verbose:
                print(f"🎯 Final solution selected: {self.state.final_solution}")
    
    def _score_solution_candidate(self, candidate: str) -> float:
        """Score a solution candidate"""
        score = 0.0
        
        # Length score
        if 10 <= len(candidate) <= 100:
            score += 0.3
        elif 5 <= len(candidate) <= 200:
            score += 0.1
        
        # Format score
        if candidate.startswith(('flag{', 'FLAG{', 'CTF{')) and candidate.endswith('}'):
            score += 0.4
        elif len(candidate) in [32, 64] and all(c in '0123456789abcdefABCDEF' for c in candidate):
            score += 0.3
        
        # Printability score
        if candidate.isprintable():
            score += 0.2
        
        # Frequency in findings (more mentions = higher confidence)
        mentions = sum(1 for f in self.state.findings.values() 
                      if candidate.lower() in str(f.data).lower())
        score += min(mentions * 0.1, 0.3)
        
        return min(score, 1.0)
    
    def _record_task_performance(self, task: Task, execution_time: float, success: bool):
        """Record task performance statistics"""
        self.performance_stats['total_execution_time'] += execution_time
        
        analyzer = task.analyzer
        if analyzer not in self.performance_stats['analyzer_performance']:
            self.performance_stats['analyzer_performance'][analyzer] = {
                'total_tasks': 0,
                'successful_tasks': 0,
                'total_time': 0,
                'average_time': 0
            }
        
        stats = self.performance_stats['analyzer_performance'][analyzer]
        stats['total_tasks'] += 1
        stats['total_time'] += execution_time
        stats['average_time'] = stats['total_time'] / stats['total_tasks']
        
        if success:
            stats['successful_tasks'] += 1
    
    def _log_performance_summary(self):
        """Log final performance summary"""
        if not self.verbose:
            return
        
        print("\n" + "="*60)
        print("📊 WORKFLOW PERFORMANCE SUMMARY")
        print("="*60)
        
        stats = self.performance_stats
        total_tasks = stats['tasks_completed'] + stats['tasks_failed']
        
        print(f"Total Tasks: {total_tasks}")
        print(f"Completed: {stats['tasks_completed']} ({stats['tasks_completed']/total_tasks*100:.1f}%)")
        print(f"Failed: {stats['failed_tasks']} ({stats['tasks_failed']/total_tasks*100:.1f}%)")
        print(f"Total Execution Time: {stats['total_execution_time']:.2f}s")
        
        # Analyzer performance
        print(f"\n🔧 ANALYZER PERFORMANCE:")
        for analyzer, perf in stats['analyzer_performance'].items():
            success_rate = perf['successful_tasks'] / perf['total_tasks'] * 100
            print(f"  {analyzer}: {perf['successful_tasks']}/{perf['total_tasks']} "
                  f"({success_rate:.1f}%) avg {perf['average_time']:.2f}s")
        
        # Final state
        progress = self.state.get_progress_summary()
        print(f"\n📈 FINAL STATE:")
        print(f"  Materials: {progress['total_materials']}")
        print(f"  Findings: {progress['total_findings']} ({progress['high_confidence_findings']} high-conf)")
        print(f"  Solution Candidates: {progress['solution_candidates']}")
        print(f"  Final Solution: {'YES' if progress['has_solution'] else 'NO'}")
        
        print("="*60)
    
    def pause_workflow(self):
        """Pause the workflow"""
        self.pause_requested = True
        if self.verbose:
            print("⏸️  Workflow paused")
    
    def resume_workflow(self):
        """Resume the workflow"""
        self.pause_requested = False
        if self.verbose:
            print("▶️  Workflow resumed")
    
    def stop_workflow(self):
        """Stop the workflow"""
        self.stop_requested = True
        if self.verbose:
            print("🛑 Workflow stop requested")
    
    def get_real_time_status(self) -> Dict[str, Any]:
        """Get real-time workflow status"""
        with self.execution_lock:
            return {
                'running_tasks': [
                    {
                        'id': task.id,
                        'name': task.name,
                        'analyzer': task.analyzer,
                        'started_at': task.started_at.isoformat() if task.started_at else None
                    }
                    for task in self.running_tasks.values()
                ],
                'queued_tasks': self.task_queue.qsize(),
                'performance_stats': self.performance_stats.copy(),
                'llm_suggestions': len(self.llm_suggestions),
                'stop_requested': self.stop_requested,
                'pause_requested': self.pause_requested
            }