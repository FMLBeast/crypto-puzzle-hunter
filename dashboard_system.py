#!/usr/bin/env python3
"""
Real-time Analysis Dashboard for Enhanced Crypto Hunter
Provides live monitoring and visualization of workflow progress
"""

import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.layout import Layout
from rich.live import Live
from rich import box

from enhanced_state_management import WorkflowState, AnalysisPhase, TaskStatus, MaterialType


class AnalysisDashboard:
    """Real-time dashboard for workflow analysis"""
    
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.console = Console()
        self.start_time = datetime.now()
        
        # Dashboard configuration
        self.refresh_rate = 1.0  # seconds
        self.max_recent_items = 10
        
        # Performance tracking
        self.performance_history = []
        self.task_timeline = []
    
    def create_layout(self) -> Layout:
        """Create dashboard layout"""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )
        
        layout["left"].split_column(
            Layout(name="progress", size=8),
            Layout(name="tasks")
        )
        
        layout["right"].split_column(
            Layout(name="materials", size=10),
            Layout(name="findings")
        )
        
        return layout
    
    def generate_header(self) -> Panel:
        """Generate dashboard header"""
        state = self.orchestrator.state
        progress = state.get_progress_summary()
        
        elapsed = datetime.now() - self.start_time
        elapsed_str = str(elapsed).split('.')[0]  # Remove microseconds
        
        status_text = f"""
🧩 Enhanced Crypto Hunter Dashboard
📁 Puzzle: {state.puzzle_name}
⏱️  Runtime: {elapsed_str}
📊 Progress: {progress['completion_percentage']:.1f}% | Phase: {progress['current_phase'].title()}
🎯 Solution: {'FOUND' if progress['has_solution'] else 'SEARCHING...'}
        """.strip()
        
        color = "green" if progress['has_solution'] else "cyan"
        return Panel(status_text, style=color, box=box.DOUBLE)
    
    def generate_progress_panel(self) -> Panel:
        """Generate progress overview panel"""
        state = self.orchestrator.state
        progress = state.get_progress_summary()
        
        # Create progress bars for different metrics
        progress_text = []
        
        # Overall completion
        completion = progress['completion_percentage']
        bar_length = 30
        filled = int(completion / 100 * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)
        progress_text.append(f"Overall: {bar} {completion:.1f}%")
        
        # Phase progress
        current_phase_tasks = state.get_tasks_by_phase(state.current_phase)
        if current_phase_tasks:
            completed_in_phase = sum(1 for t in current_phase_tasks if t.status == TaskStatus.COMPLETED)
            phase_completion = completed_in_phase / len(current_phase_tasks) * 100
            filled = int(phase_completion / 100 * bar_length)
            bar = "█" * filled + "░" * (bar_length - filled)
            progress_text.append(f"Phase:   {bar} {phase_completion:.1f}%")
        
        # Task statistics
        progress_text.append("")
        progress_text.append(f"📋 Tasks: {progress['completed_tasks']}/{progress['total_tasks']} completed")
        progress_text.append(f"❌ Failed: {progress['failed_tasks']}")
        progress_text.append(f"📦 Materials: {progress['total_materials']}")
        progress_text.append(f"🔍 Findings: {progress['total_findings']} ({progress['high_confidence_findings']} high-conf)")
        progress_text.append(f"🎯 Candidates: {progress['solution_candidates']}")
        
        return Panel("\n".join(progress_text), title="📊 Progress", box=box.ROUNDED)
    
    def generate_tasks_panel(self) -> Panel:
        """Generate active tasks panel"""
        state = self.orchestrator.state
        
        # Get running and recent tasks
        running_tasks = [t for t in state.tasks.values() if t.status == TaskStatus.RUNNING]
        pending_tasks = [t for t in state.tasks.values() if t.status == TaskStatus.PENDING]
        
        # Sort pending by priority
        pending_tasks.sort(key=lambda t: t.priority, reverse=True)
        
        table = Table(title="🔧 Active Tasks", box=box.SIMPLE)
        table.add_column("Status", style="cyan", width=8)
        table.add_column("Task", style="white")
        table.add_column("Analyzer", style="yellow", width=12)
        table.add_column("Priority", style="magenta", width=8)
        
        # Add running tasks
        for task in running_tasks:
            runtime = ""
            if task.started_at:
                runtime = f" ({(datetime.now() - task.started_at).seconds}s)"
            table.add_row("🏃 RUN", f"{task.name}{runtime}", task.analyzer, str(task.priority))
        
        # Add top pending tasks
        for task in pending_tasks[:5]:
            deps_ready = "✅" if task.can_execute(state.completed_tasks) else "⏳"
            table.add_row(f"{deps_ready} PEND", task.name, task.analyzer, str(task.priority))
        
        if not running_tasks and not pending_tasks:
            table.add_row("", "No active tasks", "", "")
        
        return Panel(table, box=box.ROUNDED)
    
    def generate_materials_panel(self) -> Panel:
        """Generate materials overview panel"""
        state = self.orchestrator.state
        
        table = Table(title="📦 Discovered Materials", box=box.SIMPLE)
        table.add_column("Type", style="cyan")
        table.add_column("Count", style="white")
        table.add_column("Latest", style="dim")
        
        for mat_type in MaterialType:
            materials = state.get_materials_by_type(mat_type)
            count = len(materials)
            
            if count > 0:
                latest = max(materials, key=lambda m: m.created_at)
                latest_name = latest.name[:20] + "..." if len(latest.name) > 20 else latest.name
                table.add_row(mat_type.value.replace('_', ' ').title(), str(count), latest_name)
            else:
                table.add_row(mat_type.value.replace('_', ' ').title(), "0", "-")
        
        return Panel(table, box=box.ROUNDED)
    
    def generate_findings_panel(self) -> Panel:
        """Generate recent findings panel"""
        state = self.orchestrator.state
        
        # Get recent high-confidence findings
        high_conf_findings = state.get_high_confidence_findings()
        high_conf_findings.sort(key=lambda f: f.created_at, reverse=True)
        
        recent_findings = sorted(state.findings.values(), key=lambda f: f.created_at, reverse=True)
        
        table = Table(title="🔍 Recent Findings", box=box.SIMPLE)
        table.add_column("Time", style="dim", width=8)
        table.add_column("Analyzer", style="yellow", width=12)
        table.add_column("Finding", style="white")
        table.add_column("Conf", style="green", width=6)
        
        # Add high confidence findings first
        for finding in high_conf_findings[:3]:
            time_str = finding.created_at.strftime("%H:%M:%S")
            title = finding.title[:30] + "..." if len(finding.title) > 30 else finding.title
            conf_str = f"{finding.confidence:.1%}"
            table.add_row(time_str, finding.analyzer, f"⭐ {title}", conf_str)
        
        # Add other recent findings
        other_findings = [f for f in recent_findings if not f.is_high_confidence()]
        for finding in other_findings[:5]:
            time_str = finding.created_at.strftime("%H:%M:%S")
            title = finding.title[:30] + "..." if len(finding.title) > 30 else finding.title
            conf_str = f"{finding.confidence:.1%}"
            table.add_row(time_str, finding.analyzer, title, conf_str)
        
        if not state.findings:
            table.add_row("", "", "No findings yet", "")
        
        return Panel(table, box=box.ROUNDED)
    
    def generate_footer(self) -> Panel:
        """Generate dashboard footer"""
        state = self.orchestrator.state
        
        # Performance stats
        if hasattr(self.orchestrator, 'performance_stats'):
            stats = self.orchestrator.performance_stats
            tasks_per_min = stats['tasks_completed'] / max((datetime.now() - self.start_time).seconds / 60, 1)
            
            footer_text = f"""
📈 Performance: {tasks_per_min:.1f} tasks/min | Total time: {stats['total_execution_time']:.1f}s
🎯 Solution candidates: {len(state.solution_candidates)}
💾 Auto-saving results | Press Ctrl+C to stop gracefully
            """.strip()
        else:
            footer_text = f"📊 Monitoring active | Solution candidates: {len(state.solution_candidates)} | Press Ctrl+C to stop"
        
        return Panel(footer_text, style="dim", box=box.SIMPLE)
    
    def display_static_dashboard(self):
        """Display static dashboard (for non-live mode)"""
        layout = self.create_layout()
        
        layout["header"].update(self.generate_header())
        layout["progress"].update(self.generate_progress_panel())
        layout["tasks"].update(self.generate_tasks_panel())
        layout["materials"].update(self.generate_materials_panel())
        layout["findings"].update(self.generate_findings_panel())
        layout["footer"].update(self.generate_footer())
        
        self.console.print(layout)
    
    def run_live_dashboard(self):
        """Run live updating dashboard"""
        def generate_layout():
            layout = self.create_layout()
            
            layout["header"].update(self.generate_header())
            layout["progress"].update(self.generate_progress_panel())
            layout["tasks"].update(self.generate_tasks_panel())
            layout["materials"].update(self.generate_materials_panel())
            layout["findings"].update(self.generate_findings_panel())
            layout["footer"].update(self.generate_footer())
            
            return layout
        
        with Live(generate_layout(), refresh_per_second=1) as live:
            try:
                while not getattr(self.orchestrator, 'stop_requested', False):
                    time.sleep(self.refresh_rate)
                    live.update(generate_layout())
            except KeyboardInterrupt:
                pass
    
    def generate_analysis_summary(self) -> str:
        """Generate text summary of analysis"""
        state = self.orchestrator.state
        progress = state.get_progress_summary()
        
        summary_lines = [
            f"🧩 CRYPTO HUNTER ANALYSIS SUMMARY",
            f"=" * 50,
            f"",
            f"📁 Puzzle: {state.puzzle_name}",
            f"⏱️  Duration: {datetime.now() - self.start_time}",
            f"📊 Overall Progress: {progress['completion_percentage']:.1f}%",
            f"📍 Current Phase: {progress['current_phase'].value.title()}",
            f"",
            f"🔢 STATISTICS:",
            f"  • Tasks: {progress['completed_tasks']}/{progress['total_tasks']} completed ({progress['failed_tasks']} failed)",
            f"  • Materials: {progress['total_materials']} discovered",
            f"  • Findings: {progress['total_findings']} total, {progress['high_confidence_findings']} high-confidence",
            f"  • Solution Candidates: {progress['solution_candidates']}",
            f"",
        ]
        
        # Add solution information
        if state.final_solution:
            summary_lines.extend([
                f"🎯 SOLUTION FOUND:",
                f"  {state.final_solution}",
                f""
            ])
        elif state.solution_candidates:
            summary_lines.extend([
                f"🎯 SOLUTION CANDIDATES:",
                *[f"  • {candidate}" for candidate in state.solution_candidates[-5:]],
                f""
            ])
        
        # Add high confidence findings
        high_conf_findings = state.get_high_confidence_findings()
        if high_conf_findings:
            summary_lines.extend([
                f"⭐ HIGH CONFIDENCE FINDINGS:",
                *[f"  • [{f.analyzer}] {f.title} ({f.confidence:.1%})" 
                  for f in high_conf_findings[:10]],
                f""
            ])
        
        # Add material breakdown
        summary_lines.extend([
            f"📦 MATERIALS BY TYPE:",
            *[f"  • {mat_type.value.replace('_', ' ').title()}: {len(state.get_materials_by_type(mat_type))}"
              for mat_type in MaterialType if state.get_materials_by_type(mat_type)],
            f""
        ])
        
        # Add performance data if available
        if hasattr(self.orchestrator, 'performance_stats'):
            stats = self.orchestrator.performance_stats
            summary_lines.extend([
                f"📈 PERFORMANCE:",
                f"  • Total execution time: {stats['total_execution_time']:.2f}s",
                f"  • Tasks completed: {stats['tasks_completed']}",
                f"  • Tasks failed: {stats['tasks_failed']}",
                f""
            ])
            
            if stats['analyzer_performance']:
                summary_lines.append("🔧 ANALYZER PERFORMANCE:")
                for analyzer, perf in stats['analyzer_performance'].items():
                    success_rate = perf['successful_tasks'] / perf['total_tasks'] * 100 if perf['total_tasks'] > 0 else 0
                    summary_lines.append(f"  • {analyzer}: {perf['successful_tasks']}/{perf['total_tasks']} ({success_rate:.1f}%) avg {perf['average_time']:.2f}s")
        
        return "\n".join(summary_lines)
    
    def export_dashboard_data(self, output_file: str):
        """Export dashboard data to JSON"""
        state = self.orchestrator.state
        
        dashboard_data = {
            "timestamp": datetime.now().isoformat(),
            "puzzle_name": state.puzzle_name,
            "analysis_duration": (datetime.now() - self.start_time).total_seconds(),
            "progress_summary": state.get_progress_summary(),
            "state_export": state.export_state_summary(),
            "performance_stats": getattr(self.orchestrator, 'performance_stats', {}),
            "dashboard_config": {
                "refresh_rate": self.refresh_rate,
                "max_recent_items": self.max_recent_items
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(dashboard_data, f, indent=2, default=str)
    
    def save_analysis_summary(self, output_file: str):
        """Save text analysis summary"""
        summary = self.generate_analysis_summary()
        
        with open(output_file, 'w') as f:
            f.write(summary)
    
    def display_completion_summary(self):
        """Display final completion summary"""
        state = self.orchestrator.state
        progress = state.get_progress_summary()
        
        # Create completion panel
        if state.final_solution:
            completion_text = f"""
🎯 PUZZLE SOLVED!

Solution: {state.final_solution}

📊 Final Statistics:
• Analysis Duration: {datetime.now() - self.start_time}
• Tasks Completed: {progress['completed_tasks']}/{progress['total_tasks']}
• Materials Discovered: {progress['total_materials']}
• High-Confidence Findings: {progress['high_confidence_findings']}
            """.strip()
            
            panel = Panel(completion_text, 
                         title="[bold green]🏆 SUCCESS[/bold green]",
                         style="green", 
                         box=box.DOUBLE)
        else:
            completion_text = f"""
🔍 ANALYSIS COMPLETED

No definitive solution found, but discovered:
• {progress['solution_candidates']} solution candidates
• {progress['high_confidence_findings']} high-confidence findings
• {progress['total_materials']} materials

📊 Statistics:
• Analysis Duration: {datetime.now() - self.start_time}
• Tasks Completed: {progress['completed_tasks']}/{progress['total_tasks']}
            """.strip()
            
            panel = Panel(completion_text,
                         title="[bold yellow]📊 ANALYSIS COMPLETE[/bold yellow]",
                         style="yellow",
                         box=box.DOUBLE)
        
        self.console.print(panel)