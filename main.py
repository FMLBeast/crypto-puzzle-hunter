#!/usr/bin/env python3
"""
Enhanced Main Interface for Crypto Hunter
Complete integration of new workflow system with existing codebase
"""

import os
import sys
import argparse
import threading
import time
from pathlib import Path
from typing import Optional, Dict, Any
import signal
import json

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from orchestrator import EnhancedOrchestrator
from dashboard_system import AnalysisDashboard
from core.agent import CryptoAgent
from core.enhanced_state_saver import EnhancedStateSaver
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box


class EnhancedCryptoHunter:
    """Enhanced Crypto Hunter with new workflow system"""
    
    def __init__(self):
        self.console = Console()
        self.orchestrator = None
        self.dashboard = None
        self.llm_agent = None
        self.state_saver = None
        
        # Execution control
        self.stop_requested = False
        self.dashboard_thread = None
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.console.print("\n[yellow]Shutdown signal received - cleaning up...[/yellow]")
        self.stop_requested = True
        
        if self.orchestrator:
            self.orchestrator.stop_workflow()
        
        # Give time for cleanup
        time.sleep(2)
        sys.exit(0)
    
    def display_banner(self):
        """Display enhanced banner"""
        banner_text = """
🧩 CRYPTO HUNTER - ENHANCED WORKFLOW SYSTEM

Advanced Cryptographic Puzzle Solver with:
• Intelligent Task Orchestration
• Real-time Analysis Dashboard  
• LLM-Guided Strategy Selection
• Adaptive Material Discovery
• Parallel Analyzer Execution
        """
        
        self.console.print(Panel(banner_text.strip(), 
                                title="[bold cyan]Enhanced Crypto Hunter[/bold cyan]",
                                box=box.DOUBLE))
    
    def run_analysis(self, puzzle_file: str, args: argparse.Namespace) -> bool:
        """Run complete analysis workflow"""
        
        # Validate puzzle file
        if not Path(puzzle_file).exists():
            self.console.print(f"[red]❌ Puzzle file not found: {puzzle_file}[/red]")
            return False
        
        self.console.print(f"[cyan]📁 Analyzing puzzle: {Path(puzzle_file).name}[/cyan]")
        
        # Initialize LLM agent if requested
        if args.llm_provider:
            self.console.print(f"[yellow]🤖 Initializing {args.llm_provider} LLM agent...[/yellow]")
            try:
                self.llm_agent = CryptoAgent(
                    provider=args.llm_provider,
                    api_key=None,  # Use environment variables
                    model=args.llm_model,
                    verbose=args.verbose
                )
                self.console.print("[green]✅ LLM agent initialized[/green]")
            except Exception as e:
                self.console.print(f"[red]❌ LLM agent initialization failed: {e}[/red]")
                if args.require_llm:
                    return False
                self.llm_agent = None
        
        # Initialize enhanced orchestrator
        self.console.print("[yellow]⚙️  Initializing enhanced orchestrator...[/yellow]")
        self.orchestrator = EnhancedOrchestrator(
            puzzle_file=puzzle_file,
            llm_agent=self.llm_agent,
            max_workers=args.max_workers,
            verbose=args.verbose
        )
        
        # Initialize dashboard.css
        self.dashboard = AnalysisDashboard(self.orchestrator)
        
        # Initialize state saver
        self.state_saver = EnhancedStateSaver(
            output_dir=args.output_dir,
            results_dir=args.results_dir
        )
        
        # Display initial status
        self._display_analysis_setup(args)
        
        # Start dashboard.css if requested
        if args.live_dashboard:
            self._start_dashboard_thread(args.dashboard_refresh)
        
        # Run the workflow
        self.console.print("\n[bold green]🚀 Starting enhanced analysis workflow...[/bold green]")
        
        try:
            solution_found = self.orchestrator.run_enhanced_workflow(
                max_iterations=args.max_iterations,
                timeout_minutes=args.timeout_minutes
            )
            
            # Save comprehensive results
            self._save_results(puzzle_file, args)
            
            # Display final results
            self._display_final_results(solution_found)
            
            return solution_found
            
        except Exception as e:
            self.console.print(f"[red]❌ Analysis failed: {e}[/red]")
            if args.verbose:
                import traceback
                self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return False
        
        finally:
            # Cleanup
            self._cleanup()
    
    def _display_analysis_setup(self, args: argparse.Namespace):
        """Display analysis setup information"""
        setup_table = Table(title="Analysis Configuration", box=box.ROUNDED)
        setup_table.add_column("Setting", style="cyan")
        setup_table.add_column("Value", style="white")
        
        setup_table.add_row("Max Workers", str(args.max_workers))
        setup_table.add_row("Max Iterations", str(args.max_iterations))
        setup_table.add_row("Timeout", f"{args.timeout_minutes} minutes")
        setup_table.add_row("LLM Provider", args.llm_provider or "None")
        setup_table.add_row("Live Dashboard", "Yes" if args.live_dashboard else "No")
        setup_table.add_row("Verbose Output", "Yes" if args.verbose else "No")
        setup_table.add_row("Output Directory", args.output_dir)
        
        self.console.print(setup_table)
        print()
    
    def _start_dashboard_thread(self, refresh_interval: float):
        """Start dashboard.css in separate thread"""
        def dashboard_loop():
            try:
                while not self.stop_requested:
                    if self.orchestrator and self.dashboard:
                        # Clear screen and show dashboard.css
                        os.system('clear' if os.name == 'posix' else 'cls')
                        self.dashboard.display_static_dashboard()
                        
                        # Show real-time status
                        status = self.orchestrator.get_real_time_status()
                        if status['running_tasks']:
                            self.console.print(f"\n[dim]Running: {len(status['running_tasks'])} tasks[/dim]")
                    
                    time.sleep(refresh_interval)
            except:
                pass
        
        self.dashboard_thread = threading.Thread(target=dashboard_loop, daemon=True)
        self.dashboard_thread.start()
    
    def _save_results(self, puzzle_file: str, args: argparse.Namespace):
        """Save comprehensive analysis results"""
        if not self.state_saver or not self.orchestrator:
            return
        
        try:
            self.console.print("[yellow]💾 Saving comprehensive results...[/yellow]")
            
            # Save using enhanced state saver
            saved_files = self.state_saver.save_comprehensive_results(
                state=self.orchestrator.state,
                puzzle_path=puzzle_file,
                create_compressed=args.create_archive
            )
            
            # Export dashboard.css data
            dashboard_file = Path(args.output_dir) / "dashboard_export.json"
            self.dashboard.export_dashboard_data(str(dashboard_file))
            
            # Export workflow state
            workflow_file = Path(args.output_dir) / "workflow_state.json"
            with open(workflow_file, 'w') as f:
                json.dump(self.orchestrator.state.to_dict(), f, indent=2, default=str)
            
            self.console.print(f"[green]✅ Results saved to {args.output_dir}[/green]")
            
            # Display saved files
            if args.verbose and saved_files:
                file_table = Table(title="Saved Files", box=box.SIMPLE)
                file_table.add_column("Type", style="cyan")
                file_table.add_column("Path", style="white")
                
                for file_type, file_path in saved_files.items():
                    file_table.add_row(file_type.replace('_', ' ').title(), file_path)
                
                self.console.print(file_table)
            
        except Exception as e:
            self.console.print(f"[red]❌ Failed to save results: {e}[/red]")
    
    def _display_final_results(self, solution_found: bool):
        """Display final analysis results"""
        if not self.orchestrator:
            return
        
        progress = self.orchestrator.state.get_progress_summary()
        
        # Results summary
        results_panel = Panel(
            self._format_results_summary(progress, solution_found),
            title="[bold]🎯 Analysis Results[/bold]",
            box=box.DOUBLE
        )
        
        self.console.print(results_panel)
        
        # Solution display
        if solution_found and self.orchestrator.state.final_solution:
            solution_panel = Panel(
                f"[bold green]{self.orchestrator.state.final_solution}[/bold green]",
                title="[bold]🏆 SOLUTION FOUND[/bold]",
                box=box.DOUBLE,
                style="green"
            )
            self.console.print(solution_panel)
        
        elif self.orchestrator.state.solution_candidates:
            candidates_text = "\n".join([
                f"• {candidate}" 
                for candidate in self.orchestrator.state.solution_candidates[-5:]
            ])
            
            candidates_panel = Panel(
                candidates_text,
                title="[bold]🎯 Solution Candidates[/bold]",
                box=box.ROUNDED,
                style="yellow"
            )
            self.console.print(candidates_panel)
        
        # High confidence findings
        high_conf_findings = self.orchestrator.state.get_high_confidence_findings()
        if high_conf_findings:
            findings_text = "\n".join([
                f"• [{f.analyzer}] {f.title} ({f.confidence:.1%})"
                for f in high_conf_findings[:10]
            ])
            
            findings_panel = Panel(
                findings_text,
                title="[bold]⭐ High Confidence Findings[/bold]",
                box=box.ROUNDED
            )
            self.console.print(findings_panel)
    
    def _format_results_summary(self, progress: Dict[str, Any], solution_found: bool) -> str:
        """Format results summary"""
        status_icon = "🎯" if solution_found else "🔍"
        status_text = "SOLVED" if solution_found else "ANALYZED"
        
        summary = f"""
{status_icon} Status: {status_text}
📊 Progress: {progress['completion_percentage']:.1f}%
⚙️  Tasks: {progress['completed_tasks']}/{progress['total_tasks']} completed
📦 Materials: {progress['total_materials']} discovered
🔍 Findings: {progress['total_findings']} ({progress['high_confidence_findings']} high-confidence)
🎯 Candidates: {progress['solution_candidates']}
📍 Phase: {progress['current_phase'].title()}
        """.strip()
        
        return summary
    
    def _cleanup(self):
        """Cleanup resources"""
        if self.dashboard_thread and self.dashboard_thread.is_alive():
            self.stop_requested = True
            self.dashboard_thread.join(timeout=2)
        
        if self.orchestrator:
            # Cleanup any temporary files
            self.orchestrator.analyzer_bridge.cleanup()
    
    def run_interactive_mode(self, args: argparse.Namespace):
        """Run interactive mode for puzzle selection"""
        self.console.print("[bold cyan]🎮 Interactive Mode[/bold cyan]")
        
        if args.puzzles_dir and Path(args.puzzles_dir).exists():
            puzzle_files = list(Path(args.puzzles_dir).glob("*"))
            puzzle_files = [f for f in puzzle_files if f.is_file()]
            
            if not puzzle_files:
                self.console.print(f"[red]No puzzle files found in {args.puzzles_dir}[/red]")
                return False
            
            # Display available puzzles
            puzzle_table = Table(title="Available Puzzles", box=box.ROUNDED)
            puzzle_table.add_column("Index", style="cyan")
            puzzle_table.add_column("File", style="white")
            puzzle_table.add_column("Size", style="dim")
            
            for i, puzzle_file in enumerate(puzzle_files):
                size = puzzle_file.stat().st_size
                size_str = f"{size:,} bytes" if size < 1024*1024 else f"{size/(1024*1024):.1f} MB"
                puzzle_table.add_row(str(i), puzzle_file.name, size_str)
            
            self.console.print(puzzle_table)
            
            # Get user selection
            try:
                choice = self.console.input("\n[cyan]Enter puzzle index (or 'q' to quit): [/cyan]")
                
                if choice.lower() == 'q':
                    return False
                
                index = int(choice)
                if 0 <= index < len(puzzle_files):
                    selected_puzzle = str(puzzle_files[index])
                    return self.run_analysis(selected_puzzle, args)
                else:
                    self.console.print("[red]Invalid selection[/red]")
                    return False
                    
            except (ValueError, KeyboardInterrupt):
                self.console.print("\n[yellow]Selection cancelled[/yellow]")
                return False
        
        else:
            self.console.print("[red]Puzzles directory not specified or doesn't exist[/red]")
            return False


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Enhanced Crypto Hunter - Advanced Cryptographic Puzzle Solver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py puzzle.png
  python main.py puzzle.txt --llm-provider anthropic --live-dashboard.css
  python main.py --interactive --puzzles-dir ./puzzles
  python main.py puzzle.zip --max-workers 5 --timeout 60
        """
    )
    
    # Main arguments
    parser.add_argument("puzzle_file", nargs='?', help="Puzzle file to analyze")
    
    # LLM configuration
    llm_group = parser.add_argument_group("LLM Configuration")
    llm_group.add_argument("--llm-provider", choices=["anthropic", "openai"],
                          help="LLM provider for orchestration")
    llm_group.add_argument("--llm-model", help="Specific LLM model to use")
    llm_group.add_argument("--require-llm", action="store_true",
                          help="Require LLM agent (fail if not available)")
    
    # Execution configuration
    exec_group = parser.add_argument_group("Execution Configuration")
    exec_group.add_argument("--max-workers", type=int, default=3,
                           help="Maximum parallel workers (default: 3)")
    exec_group.add_argument("--max-iterations", type=int, default=50,
                           help="Maximum analysis iterations (default: 50)")
    exec_group.add_argument("--timeout-minutes", type=int, default=30,
                           help="Analysis timeout in minutes (default: 30)")
    
    # Interface options
    interface_group = parser.add_argument_group("Interface Options")
    interface_group.add_argument("--live-dashboard.css", action="store_true",
                                help="Show live analysis dashboard.css")
    interface_group.add_argument("--dashboard.css-refresh", type=float, default=2.0,
                                help="Dashboard refresh interval (default: 2.0)")
    interface_group.add_argument("--interactive", action="store_true",
                                help="Run in interactive mode")
    interface_group.add_argument("--puzzles-dir", help="Directory containing puzzles")
    
    # Output configuration
    output_group = parser.add_argument_group("Output Configuration")
    output_group.add_argument("--output-dir", default="enhanced_results",
                             help="Output directory (default: enhanced_results)")
    output_group.add_argument("--results-dir", default="results",
                             help="Results directory (default: results)")
    output_group.add_argument("--create-archive", action="store_true",
                             help="Create compressed archive of results")
    
    # Logging and debugging
    debug_group = parser.add_argument_group("Debugging Options")
    debug_group.add_argument("--verbose", "-v", action="store_true",
                            help="Enable verbose output")
    debug_group.add_argument("--debug", action="store_true",
                            help="Enable debug logging")
    
    return parser.parse_args()


def setup_logging(args: argparse.Namespace):
    """Setup logging configuration"""
    import logging
    
    level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('enhanced_crypto_hunter.log'),
            logging.StreamHandler() if args.verbose else logging.NullHandler()
        ]
    )


def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Setup logging
    setup_logging(args)
    
    # Create main application
    app = EnhancedCryptoHunter()
    
    # Display banner
    app.display_banner()
    
    try:
        if args.interactive:
            # Interactive mode
            success = app.run_interactive_mode(args)
        
        elif args.puzzle_file:
            # Direct analysis
            success = app.run_analysis(args.puzzle_file, args)
        
        else:
            # No puzzle specified
            app.console.print("[red]❌ No puzzle file specified. Use --help for usage.[/red]")
            success = False
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        app.console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        sys.exit(1)
    
    except Exception as e:
        app.console.print(f"[red]❌ Unexpected error: {e}[/red]")
        if args.debug:
            import traceback
            app.console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)


if __name__ == "__main__":
    main()