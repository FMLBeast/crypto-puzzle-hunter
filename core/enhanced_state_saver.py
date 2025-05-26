"""
Enhanced State Saver and Output Manager for Crypto Hunter
Provides comprehensive state persistence and organized output generation with robust error handling
"""

import os
import json
import time
import hashlib
import zipfile
import base64
import binascii
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import logging
import re

from core.logger import solution_logger
from core.state import State

class EnhancedStateSaver:
    """Enhanced state saving with comprehensive output organization and error recovery"""

    def __init__(self, output_dir: str, results_dir: str):
        self.output_dir = Path(output_dir)
        self.results_dir = Path(results_dir)
        self.logger = logging.getLogger(__name__)
        self._setup_directories()

    def load_state(self, puzzle_path: str) -> Optional['State']:
        """
        Load a previously saved state for a puzzle

        Args:
            puzzle_path: Path to the puzzle file

        Returns:
            State object if found, None otherwise
        """
        try:
            puzzle_name = self._get_puzzle_name(puzzle_path)
            state_file = self.results_dir / f"{puzzle_name}_state.json"

            if not state_file.exists():
                return None

            with open(state_file, 'r', encoding='utf-8') as f:
                state_data = json.load(f)

            # Reconstruct state object
            state = State()

            # Basic properties
            if 'puzzle_file' in state_data:
                state.puzzle_file = state_data['puzzle_file']
            if 'puzzle_text' in state_data:
                state.puzzle_text = state_data['puzzle_text']
            if 'solution' in state_data:
                state.solution = state_data['solution']
            if 'puzzle_type' in state_data:
                state.puzzle_type = state_data['puzzle_type']

            # Binary data (base64 encoded)
            if 'binary_data_b64' in state_data:
                try:
                    state.binary_data = base64.b64decode(state_data['binary_data_b64'])
                except Exception as e:
                    self.logger.warning(f"Failed to decode binary data: {e}")

            # Collections
            state.insights = state_data.get('insights', [])
            state.transformations = state_data.get('transformations', [])
            state.clues = state_data.get('clues', [])
            state.patterns = state_data.get('patterns', [])
            state.related_files = state_data.get('related_files', {})

            return state

        except Exception as e:
            self.logger.error(f"Failed to load state: {e}")
            return None

    def _setup_directories(self):
        """Set up all necessary directories"""
        try:
            directories = [
                self.output_dir,
                self.results_dir,
                self.output_dir / "analysis",
                self.output_dir / "extractions",
                self.output_dir / "transformations",
                self.output_dir / "reports",
                self.output_dir / "keys",
                self.output_dir / "logs"
            ]

            for directory in directories:
                directory.mkdir(parents=True, exist_ok=True)

        except Exception as e:
            self.logger.error(f"Failed to setup directories: {e}")
            # Continue anyway - we'll handle individual failures later

    def save_comprehensive_results(self, state, puzzle_path: str, create_compressed: bool = True) -> Dict[str, str]:
        """
        Save comprehensive analysis results with organized output files

        Args:
            state: Final puzzle state
            puzzle_path: Path to the puzzle
            create_compressed: Whether to create a compressed archive

        Returns:
            Dictionary of saved file paths
        """
        saved_files = {}
        puzzle_name = self._get_puzzle_name(puzzle_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{puzzle_name}_{timestamp}"

        try:
            # 1. Save main results JSON
            try:
                main_results = self._create_main_results(state, puzzle_path)
                results_path = self.results_dir / f"{base_name}_results.json"
                self._safe_write_json(results_path, main_results)
                saved_files['main_results'] = str(results_path)
                self.logger.info(f"Saved main results to {results_path}")
            except Exception as e:
                self.logger.error(f"Failed to save main results: {e}")
                # Create minimal results as fallback
                try:
                    minimal_results = {
                        'puzzle_path': puzzle_path,
                        'timestamp': datetime.now().isoformat(),
                        'insights_count': len(state.insights) if hasattr(state, 'insights') else 0,
                        'transformations_count': len(state.transformations) if hasattr(state, 'transformations') else 0,
                        'solution': getattr(state, 'solution', None),
                        'status': 'partial_failure'
                    }
                    minimal_path = self.results_dir / f"{base_name}_minimal.json"
                    self._safe_write_json(minimal_path, minimal_results)
                    saved_files['minimal_results'] = str(minimal_path)
                except Exception as e2:
                    self.logger.error(f"Even minimal results save failed: {e2}")

            # 2. Save detailed analysis report
            try:
                analysis_path = self.output_dir / "reports" / f"{base_name}_analysis.md"
                self._save_analysis_report(state, puzzle_path, analysis_path)
                saved_files['analysis_report'] = str(analysis_path)
            except Exception as e:
                self.logger.error(f"Failed to save analysis report: {e}")

            # 3. Save HTML report
            try:
                html_path = self.output_dir / "reports" / f"{base_name}_report.html"
                self._save_html_report(state, puzzle_path, html_path)
                saved_files['html_report'] = str(html_path)
            except Exception as e:
                self.logger.error(f"Failed to save HTML report: {e}")

            # 4. Save transformations
            try:
                transformation_files = self._save_transformations(state, base_name)
                saved_files.update(transformation_files)
            except Exception as e:
                self.logger.error(f"Failed to save transformations: {e}")

            # 5. Save steganography data
            try:
                stego_files = self._save_steganography_data(state, base_name)
                saved_files.update(stego_files)
            except Exception as e:
                self.logger.error(f"Failed to save steganography data: {e}")

            # 6. Save binary data extractions
            try:
                binary_files = self._save_binary_data(state, base_name)
                saved_files.update(binary_files)
            except Exception as e:
                self.logger.error(f"Failed to save binary data: {e}")

            # 7. Save potential cryptographic keys
            try:
                key_files = self._save_potential_keys(state, base_name)
                saved_files.update(key_files)
            except Exception as e:
                self.logger.error(f"Failed to save keys: {e}")

            # 8. Save execution log
            try:
                log_path = self.output_dir / "logs" / f"{base_name}_execution.log"
                self._save_execution_log(state, log_path)
                saved_files['execution_log'] = str(log_path)
            except Exception as e:
                self.logger.error(f"Failed to save execution log: {e}")

            # 9. Create summary file
            try:
                summary_path = self.output_dir / f"{base_name}_SUMMARY.txt"
                self._create_summary_file(state, puzzle_path, saved_files, summary_path)
                saved_files['summary'] = str(summary_path)
            except Exception as e:
                self.logger.error(f"Failed to create summary: {e}")

            # 10. Create compressed archive if requested
            if create_compressed and saved_files:
                try:
                    archive_path = self._create_compressed_archive(saved_files, base_name)
                    if archive_path:
                        saved_files['compressed_archive'] = archive_path
                except Exception as e:
                    self.logger.error(f"Failed to create compressed archive: {e}")

            # 11. Save current state for potential resumption
            try:
                state_path = self.results_dir / f"{puzzle_name}_state.json"
                state_data = state.to_dict() if hasattr(state, 'to_dict') else {
                    'puzzle_file': getattr(state, 'puzzle_file', None),
                    'puzzle_text': getattr(state, 'puzzle_text', None),
                    'solution': getattr(state, 'solution', None),
                    'insights': getattr(state, 'insights', []),
                    'transformations': getattr(state, 'transformations', []),
                    'timestamp': datetime.now().isoformat()
                }

                # Handle binary data
                if hasattr(state, 'binary_data') and state.binary_data:
                    try:
                        state_data['binary_data_b64'] = base64.b64encode(state.binary_data).decode('utf-8')
                    except Exception:
                        pass  # Skip binary data if it can't be encoded

                self._safe_write_json(state_path, state_data)
                saved_files['state_save'] = str(state_path)
            except Exception as e:
                self.logger.error(f"Failed to save state: {e}")

            # Log success summary
            successful_saves = len([f for f in saved_files.values() if f and os.path.exists(f)])
            self.logger.info(f"Successfully saved {successful_saves} files out of {len(saved_files)} attempted")

            return saved_files

        except Exception as e:
            self.logger.error(f"Critical error in save_comprehensive_results: {e}")
            # Return whatever we managed to save
            return saved_files

    def _get_puzzle_name(self, puzzle_path: str) -> str:
        """Extract a clean puzzle name from the path"""
        try:
            path = Path(puzzle_path)
            name = path.stem
            # Clean the name for use in filenames
            name = re.sub(r'[^\w\-_.]', '_', name)
            return name[:50]  # Limit length
        except Exception:
            return "unknown_puzzle"

    def _safe_write_json(self, filepath: Path, data: Dict[str, Any]):
        """Safely write JSON data with error handling"""
        try:
            # Ensure directory exists
            filepath.parent.mkdir(parents=True, exist_ok=True)

            # Sanitize data for JSON serialization
            sanitized_data = self._sanitize_for_json(data)

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(sanitized_data, f, indent=2, ensure_ascii=False, default=str)

        except Exception as e:
            self.logger.error(f"Failed to write JSON to {filepath}: {e}")
            # Try to write a minimal version
            try:
                minimal_data = {
                    'error': f"Failed to serialize full data: {str(e)}",
                    'timestamp': datetime.now().isoformat(),
                    'partial_data': str(data)[:1000]  # First 1000 chars as string
                }
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(minimal_data, f, indent=2)
            except Exception:
                pass  # Give up on this file

    def _sanitize_for_json(self, obj):
        """Recursively sanitize data for JSON serialization"""
        if isinstance(obj, dict):
            return {k: self._sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._sanitize_for_json(item) for item in obj]
        elif isinstance(obj, bytes):
            try:
                return base64.b64encode(obj).decode('utf-8')
            except Exception:
                return f"<binary data {len(obj)} bytes>"
        elif isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        else:
            return str(obj)

    def _create_main_results(self, state, puzzle_path: str) -> Dict[str, Any]:
        """Create the main results dictionary with comprehensive data"""
        try:
            results = {
                'analysis_metadata': {
                    'puzzle_path': puzzle_path,
                    'puzzle_name': self._get_puzzle_name(puzzle_path),
                    'analysis_date': datetime.now().isoformat(),
                    'crypto_hunter_version': '1.0.0',
                    'analysis_duration': self._calculate_analysis_duration(state),
                },
                'puzzle_info': {
                    'file_size': len(state.binary_data) if hasattr(state, 'binary_data') and state.binary_data else len(state.puzzle_text or ''),
                    'file_type': 'binary' if (hasattr(state, 'binary_data') and state.binary_data) else 'text',
                    'puzzle_type': getattr(state, 'puzzle_type', 'unknown'),
                    'has_solution': bool(getattr(state, 'solution', None)),
                },
                'analysis_results': {
                    'solution': getattr(state, 'solution', None),
                    'insights_count': len(getattr(state, 'insights', [])),
                    'transformations_count': len(getattr(state, 'transformations', [])),
                    'clues_count': len(getattr(state, 'clues', [])),
                    'patterns_count': len(getattr(state, 'patterns', [])),
                    'related_files_count': len(getattr(state, 'related_files', {})),
                },
                'key_insights': self._extract_key_insights(state),
                'transformations_summary': [
                    {
                        'name': t.get('name', 'Unknown'),
                        'description': t.get('description', ''),
                        'analyzer': t.get('analyzer', 'Unknown'),
                        'timestamp': t.get('timestamp', '')
                    }
                    for t in (getattr(state, 'transformations', []) or [])[-10:]  # Last 10
                ],
                'insights_summary': [
                    {
                        'text': i.get('text', ''),
                        'analyzer': i.get('analyzer', 'Unknown'),
                        'timestamp': i.get('timestamp', '')
                    }
                    for i in (getattr(state, 'insights', []) or [])[-10:]  # Last 10
                ],
                'steganography_analysis': {
                    'high_confidence_extractions': self._count_high_confidence_extractions(state),
                },
                'potential_keys': self._extract_potential_keys_summary(state),
            }

            return results

        except Exception as e:
            self.logger.error(f"Failed to create main results: {e}")
            # Return minimal results
            return {
                'error': f"Failed to create full results: {str(e)}",
                'puzzle_path': puzzle_path,
                'timestamp': datetime.now().isoformat(),
                'solution': getattr(state, 'solution', None),
                'partial_data': True
            }

    def _extract_potential_keys_summary(self, state) -> Dict[str, List[Dict[str, str]]]:
        """Extract summary of potential cryptographic keys"""
        summary = {
            'hex_keys': [],
            'base64_keys': [],
            'bitcoin_addresses': [],
            'ethereum_addresses': [],
            'mnemonic_phrases': []
        }

        try:
            # Check transformations for key-like data
            for transform in getattr(state, 'transformations', []):
                output_data = transform.get('output_data', '')
                if isinstance(output_data, str):
                    summary['hex_keys'].extend(self._find_hex_keys(output_data, transform))
                    summary['bitcoin_addresses'].extend(self._find_bitcoin_addresses(output_data, transform))
                    summary['ethereum_addresses'].extend(self._find_ethereum_addresses(output_data, transform))
                    summary['mnemonic_phrases'].extend(self._find_mnemonic_phrases(output_data, transform))

            # Remove duplicates
            for key_type in summary:
                seen = set()
                unique_keys = []
                for key_info in summary[key_type]:
                    key_str = key_info.get('key', '')
                    if key_str and key_str not in seen:
                        seen.add(key_str)
                        unique_keys.append(key_info)
                summary[key_type] = unique_keys[:10]  # Limit to top 10

        except Exception as e:
            self.logger.error(f"Failed to extract potential keys: {e}")

        return summary

    def _calculate_analysis_duration(self, state) -> Optional[str]:
        """Calculate analysis duration from timestamps"""
        try:
            insights = getattr(state, 'insights', [])
            if not insights:
                return None

            timestamps = []
            for insight in insights:
                if 'timestamp' in insight:
                    try:
                        ts = datetime.fromisoformat(insight['timestamp'].replace('Z', '+00:00'))
                        timestamps.append(ts)
                    except Exception:
                        continue

            if len(timestamps) >= 2:
                duration = timestamps[-1] - timestamps[0]
                return str(duration)

        except Exception as e:
            self.logger.error(f"Failed to calculate duration: {e}")

        return None

    def _count_high_confidence_extractions(self, state) -> int:
        """Count high-confidence steganographic extractions"""
        try:
            count = 0
            for transform in getattr(state, 'transformations', []):
                name = transform.get('name', '').lower()
                if any(keyword in name for keyword in ['lsb', 'steganography', 'hidden', 'extracted']):
                    output = transform.get('output_data', '')
                    if output and len(str(output)) > 10:  # Some meaningful content
                        count += 1
            return count
        except Exception:
            return 0

    def _save_analysis_report(self, state, puzzle_path: str, report_path: Path):
        """Save a detailed analysis report in Markdown format"""
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)

            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(f"# Crypto Hunter Analysis Report\n\n")
                f.write(f"**Puzzle:** {puzzle_path}\n")
                f.write(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**File Type:** {'Binary' if (hasattr(state, 'binary_data') and state.binary_data) else 'Text'}\n\n")

                if getattr(state, 'solution', None):
                    f.write(f"## 🎯 Solution\n\n**{state.solution}**\n\n")

                f.write(f"## 📊 Analysis Summary\n\n")
                f.write(f"- **Insights Generated:** {len(getattr(state, 'insights', []))}\n")
                f.write(f"- **Transformations Applied:** {len(getattr(state, 'transformations', []))}\n")
                f.write(f"- **Clues Used:** {len(getattr(state, 'clues', []))}\n")
                f.write(f"- **Patterns Matched:** {len(getattr(state, 'patterns', []))}\n\n")

                # Recent insights
                insights = getattr(state, 'insights', [])
                if insights:
                    f.write(f"## 💡 Key Insights\n\n")
                    for i, insight in enumerate(insights[-10:], 1):
                        f.write(f"{i}. **[{insight.get('analyzer', 'Unknown')}]** {insight.get('text', '')}\n")
                    f.write("\n")

                # Transformations
                transformations = getattr(state, 'transformations', [])
                if transformations:
                    f.write(f"## 🔄 Recent Transformations\n\n")
                    for i, transform in enumerate(transformations[-10:], 1):
                        f.write(f"### {i}. {transform.get('name', 'Unknown Transformation')}\n")
                        f.write(f"**Analyzer:** {transform.get('analyzer', 'Unknown')}\n\n")
                        f.write(f"**Description:** {transform.get('description', 'No description')}\n\n")

                        input_data = transform.get('input_data', '')
                        if input_data:
                            f.write(f"**Input:** `{str(input_data)[:100]}{'...' if len(str(input_data)) > 100 else ''}`\n\n")

                        output_data = transform.get('output_data', '')
                        if output_data:
                            f.write(f"**Output:** `{str(output_data)[:200]}{'...' if len(str(output_data)) > 200 else ''}`\n\n")

        except Exception as e:
            self.logger.error(f"Failed to save analysis report: {e}")

    def _save_html_report(self, state, puzzle_path: str, report_path: Path):
        """Save a comprehensive HTML report"""
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            html_content = self._generate_html_report(state, puzzle_path)

            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

        except Exception as e:
            self.logger.error(f"Failed to save HTML report: {e}")

    def _generate_html_report(self, state, puzzle_path: str) -> str:
        """Generate HTML report content"""
        try:
            solution = getattr(state, 'solution', None)
            insights = getattr(state, 'insights', [])
            transformations = getattr(state, 'transformations', [])

            html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Crypto Hunter Analysis Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; 
               line-height: 1.6; margin: 0; padding: 20px; background: #f5f7fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; 
                     border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                   color: white; padding: 2rem; text-align: center; }}
        .content {{ padding: 2rem; }}
        .section {{ margin-bottom: 2rem; }}
        .section h2 {{ color: #2d3748; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.5rem; }}
        .solution {{ background: #f0fff4; border: 2px solid #68d391; border-radius: 8px; 
                     padding: 1rem; margin: 1rem 0; }}
        .insight, .transformation {{ background: #f7fafc; border-left: 4px solid #4299e1; 
                                    padding: 1rem; margin: 0.5rem 0; border-radius: 0 8px 8px 0; }}
        .transformation {{ border-left-color: #ed8936; }}
        .meta {{ color: #718096; font-size: 0.9em; }}
        .code {{ background: #1a202c; color: #e2e8f0; padding: 1rem; border-radius: 6px; 
                 font-family: 'Monaco', 'Menlo', monospace; overflow-x: auto; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                  gap: 1rem; margin: 1rem 0; }}
        .stat {{ background: #edf2f7; padding: 1rem; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #2d3748; }}
        .stat-label {{ color: #718096; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Crypto Hunter Analysis Report</h1>
            <p>{puzzle_path}</p>
            <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="content">
            {'<div class="solution"><h2>🎯 Solution Found</h2><p><strong>' + solution + '</strong></p></div>' if solution else ''}
            
            <div class="section">
                <h2>📊 Analysis Statistics</h2>
                <div class="stats">
                    <div class="stat">
                        <div class="stat-value">{len(insights)}</div>
                        <div class="stat-label">Insights Generated</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{len(transformations)}</div>
                        <div class="stat-label">Transformations Applied</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{'Binary' if (hasattr(state, 'binary_data') and state.binary_data) else 'Text'}</div>
                        <div class="stat-label">File Type</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{len(getattr(state, 'clues', []))}</div>
                        <div class="stat-label">Clues Used</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>💡 Key Insights</h2>
                {''.join([f'<div class="insight"><strong>[{insight.get("analyzer", "Unknown")}]</strong> {insight.get("text", "")}<div class="meta">{insight.get("timestamp", "")}</div></div>' for insight in insights[-10:]])}
            </div>
            
            <div class="section">
                <h2>🔄 Recent Transformations</h2>
                {''.join([f'''<div class="transformation">
                    <h3>{transform.get("name", "Unknown")}</h3>
                    <p><strong>Analyzer:</strong> {transform.get("analyzer", "Unknown")}</p>
                    <p><strong>Description:</strong> {transform.get("description", "No description")}</p>
                    {f'<div class="code">{str(transform.get("output_data", ""))[:500]}{"..." if len(str(transform.get("output_data", ""))) > 500 else ""}</div>' if transform.get("output_data") else ""}
                    <div class="meta">{transform.get("timestamp", "")}</div>
                </div>''' for transform in transformations[-5:]])}
            </div>
        </div>
    </div>
</body>
</html>
"""
            return html

        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {e}")
            return f"<html><body><h1>Error generating report: {e}</h1></body></html>"

    def _save_transformations(self, state, base_name: str) -> Dict[str, str]:
        """Save all transformations as individual files"""
        saved_files = {}

        try:
            transformations = getattr(state, 'transformations', [])
            if not transformations:
                return saved_files

            transform_dir = self.output_dir / "transformations" / base_name
            transform_dir.mkdir(parents=True, exist_ok=True)

            for i, transform in enumerate(transformations):
                try:
                    # Create safe filename
                    name = transform.get('name', f'transform_{i}')
                    safe_name = self._make_safe_filename(name)

                    # Save transformation data
                    transform_file = transform_dir / f"{i:03d}_{safe_name}.json"

                    # Sanitize transformation for JSON
                    sanitized_transform = self._sanitize_transformation(transform)

                    self._safe_write_json(transform_file, sanitized_transform)

                    saved_files[f'transformation_{i}'] = str(transform_file)

                    # Save output data separately if it's substantial
                    output_data = transform.get('output_data')
                    if output_data and len(str(output_data)) > 100:
                        output_file = transform_dir / f"{i:03d}_{safe_name}_output.txt"
                        try:
                            with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
                                f.write(str(output_data))
                            saved_files[f'transformation_{i}_output'] = str(output_file)
                        except Exception as e:
                            self.logger.warning(f"Failed to save transformation output {i}: {e}")

                except Exception as e:
                    self.logger.warning(f"Failed to save transformation {i}: {e}")
                    continue

        except Exception as e:
            self.logger.error(f"Failed to save transformations: {e}")

        return saved_files

    def _sanitize_transformation(self, transformation: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize transformation data for JSON serialization"""
        try:
            sanitized = {}
            for key, value in transformation.items():
                if isinstance(value, bytes):
                    try:
                        # Try to decode as text first
                        sanitized[key] = value.decode('utf-8', errors='ignore')
                    except Exception:
                        # Fall back to base64
                        sanitized[key] = base64.b64encode(value).decode('utf-8')
                elif isinstance(value, (str, int, float, bool, type(None))):
                    sanitized[key] = value
                elif isinstance(value, (list, dict)):
                    sanitized[key] = self._sanitize_for_json(value)
                else:
                    sanitized[key] = str(value)
            return sanitized
        except Exception as e:
            self.logger.error(f"Failed to sanitize transformation: {e}")
            return {'error': f'Failed to sanitize: {str(e)}'}

    def _save_steganography_data(self, state, base_name: str) -> Dict[str, str]:
        """Save extracted steganographic data to separate files"""
        saved_files = {}

        try:
            stego_dir = self.output_dir / "extractions" / base_name
            stego_dir.mkdir(parents=True, exist_ok=True)

            # Look for steganography-related transformations
            stego_count = 0
            for transform in getattr(state, 'transformations', []):
                name = transform.get('name', '').lower()
                if any(keyword in name for keyword in ['lsb', 'steganography', 'hidden', 'extracted', 'embedded']):
                    try:
                        output_data = transform.get('output_data')
                        if output_data:
                            stego_file = stego_dir / f"stego_extract_{stego_count:03d}_{self._make_safe_filename(transform.get('name', 'unknown'))}.bin"

                            # Handle different data types
                            if isinstance(output_data, bytes):
                                with open(stego_file, 'wb') as f:
                                    f.write(output_data)
                            elif isinstance(output_data, str):
                                with open(stego_file, 'w', encoding='utf-8', errors='ignore') as f:
                                    f.write(output_data)
                            else:
                                with open(stego_file, 'w', encoding='utf-8') as f:
                                    f.write(str(output_data))

                            saved_files[f'steganography_{stego_count}'] = str(stego_file)
                            stego_count += 1

                    except Exception as e:
                        self.logger.warning(f"Failed to save steganography data {stego_count}: {e}")
                        continue

        except Exception as e:
            self.logger.error(f"Failed to save steganography data: {e}")

        return saved_files

    def _save_binary_data(self, state, base_name: str) -> Dict[str, str]:
        """Save binary data extractions"""
        saved_files = {}

        try:
            if hasattr(state, 'binary_data') and state.binary_data:
                binary_dir = self.output_dir / "extractions" / base_name
                binary_dir.mkdir(parents=True, exist_ok=True)

                # Save original binary data
                original_file = binary_dir / "original_binary_data.bin"
                with open(original_file, 'wb') as f:
                    f.write(state.binary_data)
                saved_files['original_binary'] = str(original_file)

                # Save hex dump
                hex_file = binary_dir / "binary_hexdump.txt"
                with open(hex_file, 'w', encoding='utf-8') as f:
                    hex_data = state.binary_data.hex()
                    # Format as readable hex dump
                    for i in range(0, len(hex_data), 32):
                        line = hex_data[i:i+32]
                        formatted = ' '.join([line[j:j+2] for j in range(0, len(line), 2)])
                        f.write(f"{i//2:08x}: {formatted}\n")
                saved_files['hex_dump'] = str(hex_file)

        except Exception as e:
            self.logger.error(f"Failed to save binary data: {e}")

        return saved_files

    def _save_potential_keys(self, state, base_name: str) -> Dict[str, str]:
        """Save potential cryptographic keys found in the analysis"""
        saved_files = {}

        try:
            keys_dir = self.output_dir / "keys" / base_name
            keys_dir.mkdir(parents=True, exist_ok=True)

            # Extract potential keys from transformations
            all_keys = {
                'hex_keys': [],
                'wif_keys': [],
                'mnemonic_phrases': [],
                'ethereum_addresses': [],
                'bitcoin_addresses': []
            }

            for transform in getattr(state, 'transformations', []):
                output_data = transform.get('output_data', '')
                if isinstance(output_data, str):
                    all_keys['hex_keys'].extend(self._find_hex_keys(output_data, transform))
                    all_keys['wif_keys'].extend(self._find_wif_keys(output_data, transform))
                    all_keys['mnemonic_phrases'].extend(self._find_mnemonic_phrases(output_data, transform))
                    all_keys['ethereum_addresses'].extend(self._find_ethereum_addresses(output_data, transform))
                    all_keys['bitcoin_addresses'].extend(self._find_bitcoin_addresses(output_data, transform))

            # Save each type of key
            for key_type, keys in all_keys.items():
                if keys:
                    key_file = keys_dir / f"{key_type}.json"
                    self._safe_write_json(key_file, keys)
                    saved_files[key_type] = str(key_file)

        except Exception as e:
            self.logger.error(f"Failed to save potential keys: {e}")

        return saved_files

    def _find_hex_keys(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]:
        """Find hex strings that could be cryptographic keys"""
        keys = []
        try:
            # Look for hex strings of common key lengths
            hex_patterns = [
                (r'\b[0-9a-fA-F]{64}\b', 'SHA256/Private Key (32 bytes)'),
                (r'\b[0-9a-fA-F]{128}\b', 'SHA512 (64 bytes)'),
                (r'\b[0-9a-fA-F]{40}\b', 'SHA1 (20 bytes)'),
                (r'\b[0-9a-fA-F]{32}\b', 'MD5 (16 bytes)'),
            ]

            for pattern, description in hex_patterns:
                matches = re.findall(pattern, text)
                for match in matches[:5]:  # Limit to 5 per type
                    keys.append({
                        'key': match,
                        'type': description,
                        'source': transform.get('name', 'Unknown'),
                        'analyzer': transform.get('analyzer', 'Unknown')
                    })
        except Exception:
            pass

        return keys

    def _find_wif_keys(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]:
        """Find WIF format private keys"""
        keys = []
        try:
            # WIF keys start with 5, K, or L and are 51-52 characters
            wif_pattern = r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b'
            matches = re.findall(wif_pattern, text)

            for match in matches[:5]:  # Limit to 5
                keys.append({
                    'key': match,
                    'type': 'WIF Private Key',
                    'source': transform.get('name', 'Unknown'),
                    'analyzer': transform.get('analyzer', 'Unknown')
                })
        except Exception:
            pass

        return keys

    def _find_mnemonic_phrases(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]:
        """Find potential BIP39 mnemonic phrases"""
        phrases = []
        try:
            # Look for sequences of common English words
            words = text.lower().split()
            if len(words) >= 12:
                # Check for potential mnemonic sequences
                for i in range(len(words) - 11):
                    phrase_words = words[i:i+12]
                    if self._is_potential_mnemonic(' '.join(phrase_words)):
                        phrases.append({
                            'key': ' '.join(phrase_words),
                            'type': 'BIP39 Mnemonic (12 words)',
                            'source': transform.get('name', 'Unknown'),
                            'analyzer': transform.get('analyzer', 'Unknown')
                        })
                        if len(phrases) >= 3:  # Limit to 3
                            break
        except Exception:
            pass

        return phrases

    def _find_ethereum_addresses(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]:
        """Find Ethereum addresses"""
        addresses = []
        try:
            eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
            matches = re.findall(eth_pattern, text)

            for match in matches[:5]:  # Limit to 5
                addresses.append({
                    'key': match,
                    'type': 'Ethereum Address',
                    'source': transform.get('name', 'Unknown'),
                    'analyzer': transform.get('analyzer', 'Unknown')
                })
        except Exception:
            pass

        return addresses

    def _find_bitcoin_addresses(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]:
        """Find Bitcoin addresses"""
        addresses = []
        try:
            # Legacy addresses (1...) and SegWit addresses (3...)
            btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
            matches = re.findall(btc_pattern, text)

            for match in matches[:5]:  # Limit to 5
                addresses.append({
                    'key': match,
                    'type': 'Bitcoin Address',
                    'source': transform.get('name', 'Unknown'),
                    'analyzer': transform.get('analyzer', 'Unknown')
                })
        except Exception:
            pass

        return addresses

    def _is_potential_mnemonic(self, phrase: str) -> bool:
        """Basic check if a phrase could be a BIP39 mnemonic"""
        try:
            words = phrase.split()
            if len(words) not in [12, 15, 18, 21, 24]:
                return False

            # Very basic check - all words should be alphabetic and reasonable length
            for word in words:
                if not word.isalpha() or len(word) < 3 or len(word) > 8:
                    return False

            return True
        except Exception:
            return False

    def _save_execution_log(self, state, log_path: Path):
        """Save execution log with all insights in chronological order"""
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)

            with open(log_path, 'w', encoding='utf-8') as f:
                f.write(f"Crypto Hunter Execution Log\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write(f"{'='*80}\n\n")

                # Combine insights and transformations with timestamps
                events = []

                for insight in getattr(state, 'insights', []):
                    events.append({
                        'type': 'insight',
                        'timestamp': insight.get('timestamp', ''),
                        'analyzer': insight.get('analyzer', 'Unknown'),
                        'content': insight.get('text', '')
                    })

                for transform in getattr(state, 'transformations', []):
                    events.append({
                        'type': 'transformation',
                        'timestamp': transform.get('timestamp', ''),
                        'analyzer': transform.get('analyzer', 'Unknown'),
                        'content': f"{transform.get('name', 'Unknown')}: {transform.get('description', '')}"
                    })

                # Sort by timestamp
                events.sort(key=lambda x: x['timestamp'])

                for event in events:
                    f.write(f"[{event['timestamp']}] {event['type'].upper()} ({event['analyzer']})\n")
                    f.write(f"  {event['content']}\n\n")

        except Exception as e:
            self.logger.error(f"Failed to save execution log: {e}")

    def _create_summary_file(self, state, puzzle_path: str, saved_files: Dict[str, str], summary_path: Path):
        """Create a summary file with key information and file locations"""
        try:
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("CRYPTO HUNTER ANALYSIS SUMMARY\n")
                f.write("="*80 + "\n\n")

                f.write(f"Puzzle: {puzzle_path}\n")
                f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"File Type: {'Binary' if (hasattr(state, 'binary_data') and state.binary_data) else 'Text'}\n\n")

                if getattr(state, 'solution', None):
                    f.write("SOLUTION FOUND!\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"{state.solution}\n\n")

                f.write("ANALYSIS STATISTICS\n")
                f.write("-" * 40 + "\n")
                f.write(f"Insights Generated: {len(getattr(state, 'insights', []))}\n")
                f.write(f"Transformations Applied: {len(getattr(state, 'transformations', []))}\n")
                f.write(f"Clues Used: {len(getattr(state, 'clues', []))}\n")
                f.write(f"Patterns Matched: {len(getattr(state, 'patterns', []))}\n\n")

                f.write("GENERATED FILES\n")
                f.write("-" * 40 + "\n")
                for file_type, file_path in saved_files.items():
                    if file_path and os.path.exists(file_path):
                        file_size = os.path.getsize(file_path)
                        f.write(f"{file_type}: {file_path} ({file_size} bytes)\n")
                f.write("\n")

                # Recent insights
                insights = getattr(state, 'insights', [])
                if insights:
                    f.write("KEY INSIGHTS\n")
                    f.write("-" * 40 + "\n")
                    for i, insight in enumerate(insights[-10:], 1):
                        f.write(f"{i}. [{insight.get('analyzer', 'Unknown')}] {insight.get('text', '')}\n")
                    f.write("\n")

        except Exception as e:
            self.logger.error(f"Failed to create summary file: {e}")

    def _create_compressed_archive(self, saved_files: Dict[str, str], base_name: str) -> Optional[str]:
        """Create a compressed archive of all generated files"""
        try:
            archive_path = self.results_dir / f"{base_name}_complete.zip"

            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_type, file_path in saved_files.items():
                    if file_path and os.path.exists(file_path):
                        # Use relative path in archive
                        arcname = f"{base_name}/{file_type}_{os.path.basename(file_path)}"
                        zipf.write(file_path, arcname)

            return str(archive_path)

        except Exception as e:
            self.logger.error(f"Failed to create compressed archive: {e}")
            return None

    def _extract_key_insights(self, state) -> Dict[str, List[str]]:
        """Extract and categorize key insights"""
        categories = {
            'cryptographic': [],
            'steganographic': [],
            'encoding': [],
            'blockchain': [],
            'file_analysis': [],
            'patterns': [],
            'other': []
        }

        try:
            for insight in getattr(state, 'insights', []):
                text = insight.get('text', '').lower()
                analyzer = insight.get('analyzer', '').lower()

                if any(word in text for word in ['hash', 'cipher', 'decrypt', 'encrypt', 'key', 'crypto']):
                    categories['cryptographic'].append(insight.get('text', ''))
                elif any(word in text for word in ['lsb', 'steganography', 'hidden', 'embedded']):
                    categories['steganographic'].append(insight.get('text', ''))
                elif any(word in text for word in ['base64', 'hex', 'encoding', 'decode']):
                    categories['encoding'].append(insight.get('text', ''))
                elif any(word in text for word in ['bitcoin', 'ethereum', 'blockchain', 'address']):
                    categories['blockchain'].append(insight.get('text', ''))
                elif any(word in text for word in ['file', 'binary', 'entropy', 'signature']):
                    categories['file_analysis'].append(insight.get('text', ''))
                elif any(word in text for word in ['pattern', 'repeating', 'sequence']):
                    categories['patterns'].append(insight.get('text', ''))
                else:
                    categories['other'].append(insight.get('text', ''))

            # Limit each category to top 5 insights
            for category in categories:
                categories[category] = categories[category][:5]

        except Exception as e:
            self.logger.error(f"Failed to extract key insights: {e}")

        return categories

    def _find_hex_patterns(self, text: str, length: int) -> List[str]:
        """Find hex patterns of specific length"""
        try:
            pattern = rf'\b[0-9a-fA-F]{{{length}}}\b'
            return re.findall(pattern, text)[:10]  # Limit to 10
        except Exception:
            return []

    def _make_safe_filename(self, name: str) -> str:
        """Make a string safe for use as a filename"""
        try:
            # Replace unsafe characters
            safe_name = re.sub(r'[^\w\-_.]', '_', name)
            # Limit length
            safe_name = safe_name[:50]
            # Ensure it's not empty
            if not safe_name:
                safe_name = "unnamed"
            return safe_name
        except Exception:
            return "unnamed"

# Create a global instance
enhanced_saver = EnhancedStateSaver("output", "results")