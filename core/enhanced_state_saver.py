"""
Enhanced State Saver and Output Manager for Crypto Hunter
Provides comprehensive state persistence and organized output generation
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

from core.logger import solution_logger


class EnhancedStateSaver:
    """Enhanced state saving with comprehensive output organization"""

    def __init__(self, output_dir: str = "./output", results_dir: str = "./results"):
        self.output_dir = Path(output_dir)
        self.results_dir = Path(results_dir)
        self.logger = logging.getLogger(__name__)

        # Create directories
        self._setup_directories()

    def load_state(self, puzzle_path: str) -> Optional['State']:
        """
        Load a previously saved state for a puzzle

        Args:
            puzzle_path: Path to the puzzle file

        Returns:
            State object if found, None otherwise
        """
        from core.state import State

        try:
            puzzle_name = self._get_puzzle_name(puzzle_path)

            # Find the most recent results file for this puzzle
            result_files = list(self.results_dir.glob(f"{puzzle_name}_*_results.json"))

            if not result_files:
                self.logger.info(f"No previous results found for {puzzle_name}")
                return None

            # Sort by modification time (most recent first)
            result_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            latest_result = result_files[0]

            self.logger.info(f"Found previous results: {latest_result}")

            # Load the JSON data
            with open(latest_result, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Create a new State object
            state = State()

            # Set basic attributes
            state.puzzle_file = data.get("puzzle_info", {}).get("puzzle_file")
            state.file_type = data.get("puzzle_info", {}).get("file_type")
            state.file_size = data.get("puzzle_info", {}).get("file_size")
            state.hash = data.get("puzzle_info", {}).get("hash")
            state.status = data.get("analysis_summary", {}).get("status", "analyzing")
            state.puzzle_type = data.get("puzzle_info", {}).get("puzzle_type")
            state.solution = data.get("analysis_summary", {}).get("solution")

            # Set insights and transformations
            state.insights = data.get("insights", [])
            state.transformations = data.get("transformations", [])

            # Set analyzers used
            state.analyzers_used = set(data.get("analysis_summary", {}).get("analyzers_used", []))

            # Set related files, clues, and patterns
            state.related_files = data.get("related_files", {})
            state.clues = data.get("clues", [])
            state.patterns = data.get("patterns", [])

            # Set puzzle text if available
            puzzle_text = data.get("content_samples", {}).get("puzzle_text_preview")
            if puzzle_text:
                state.puzzle_text = puzzle_text

            # Try to load the original file to get binary data if needed
            if not state.puzzle_text:
                try:
                    with open(puzzle_path, "rb") as f:
                        content = f.read()
                    if state.is_binary():
                        state.set_binary_data(content)
                    else:
                        state.set_puzzle_text(content.decode("utf-8", errors="replace"))
                except Exception as e:
                    self.logger.error(f"Failed to load original file: {e}")

            self.logger.info(f"Successfully loaded previous state with {len(state.insights)} insights and {len(state.transformations)} transformations")
            return state

        except Exception as e:
            self.logger.error(f"Failed to load previous state: {e}")
            return None

    def _setup_directories(self):
        """Set up all necessary directories"""
        directories = [
            self.output_dir,
            self.results_dir,
            self.output_dir / "extracted_data",
            self.output_dir / "steganography",
            self.output_dir / "analysis_reports",
            self.output_dir / "potential_keys",
            self.output_dir / "binary_data",
            self.output_dir / "logs",
            self.output_dir / "html_reports",
            self.output_dir / "compressed"
        ]

        for directory in directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self.logger.error(f"Failed to create directory {directory}: {e}")

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
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            puzzle_name = self._get_puzzle_name(puzzle_path)
            base_name = f"{puzzle_name}_{timestamp}"

            saved_files = {}

            # Progress tracking
            total_steps = 8 + (1 if create_compressed else 0)
            current_step = 0

            def update_progress(step_name: str):
                nonlocal current_step
                current_step += 1
                progress = (current_step / total_steps) * 100
                self.logger.info(f"[{progress:.1f}%] {step_name}")

            # 1. Save main results JSON
            update_progress("Saving main results")
            main_results = self._create_main_results(state, puzzle_path)
            main_results_path = self.results_dir / f"{base_name}_results.json"
            self._safe_write_json(main_results_path, main_results)
            saved_files["main_results"] = str(main_results_path)

            # 2. Save detailed analysis report (Markdown)
            update_progress("Creating analysis report")
            report_path = self.output_dir / "analysis_reports" / f"{base_name}_analysis_report.md"
            self._save_analysis_report(state, puzzle_path, report_path)
            saved_files["analysis_report"] = str(report_path)

            # 3. Save HTML report
            update_progress("Creating HTML report")
            html_report_path = self.output_dir / "html_reports" / f"{base_name}_report.html"
            self._save_html_report(state, puzzle_path, html_report_path)
            saved_files["html_report"] = str(html_report_path)

            # 4. Save extracted steganographic data
            update_progress("Saving steganographic data")
            stego_files = self._save_steganography_data(state, base_name)
            saved_files.update(stego_files)

            # Log steganographic data in real-time
            if stego_files:
                solution_logger.log_insight(
                    f"Generated {len(stego_files)} steganography files on-the-go",
                    "state_saver"
                )

            # 5. Save potential cryptographic keys
            update_progress("Analyzing potential keys")
            key_files = self._save_potential_keys(state, base_name)
            saved_files.update(key_files)

            # Log potential keys in real-time
            if key_files:
                solution_logger.log_insight(
                    f"Generated {len(key_files)} potential key files on-the-go",
                    "state_saver"
                )

            # 6. Save binary data extractions
            update_progress("Saving binary data")
            binary_files = self._save_binary_data(state, base_name)
            saved_files.update(binary_files)

            # Log binary data in real-time
            if binary_files:
                solution_logger.log_insight(
                    f"Generated {len(binary_files)} binary data files on-the-go",
                    "state_saver"
                )

            # 7. Save all transformations as separate files
            update_progress("Saving transformations")
            transform_files = self._save_transformations(state, base_name)
            saved_files.update(transform_files)

            # Log transformations in real-time
            if transform_files:
                solution_logger.log_insight(
                    f"Generated {len(transform_files)} transformation files on-the-go",
                    "state_saver"
                )

            # 8. Save execution log
            update_progress("Creating execution log")
            log_path = self.output_dir / "logs" / f"{base_name}_execution.log"
            self._save_execution_log(state, log_path)
            saved_files["execution_log"] = str(log_path)

            # 9. Create summary file
            update_progress("Creating summary")
            summary_path = self.output_dir / f"{base_name}_SUMMARY.txt"
            self._create_summary_file(state, puzzle_path, saved_files, summary_path)
            saved_files["summary"] = str(summary_path)

            # 10. Create compressed archive if requested
            if create_compressed:
                update_progress("Creating compressed archive")
                archive_path = self._create_compressed_archive(saved_files, base_name)
                if archive_path:
                    saved_files["compressed_archive"] = archive_path

            # Log to solution logger
            solution_logger.log_insight(
                f"Saved comprehensive results: {len(saved_files)} files generated",
                "state_saver"
            )

            return saved_files

        except Exception as e:
            self.logger.error(f"Failed to save comprehensive results: {e}")
            return {"error": str(e)}

    def _get_puzzle_name(self, puzzle_path: str) -> str:
        """Extract a clean puzzle name from the path"""
        path = Path(puzzle_path)
        if path.is_file():
            return path.stem
        else:
            return path.name

    def _safe_write_json(self, filepath: Path, data: Dict[str, Any]):
        """Safely write JSON data with error handling"""
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            self.logger.error(f"Failed to write JSON to {filepath}: {e}")
            raise

    def _create_main_results(self, state, puzzle_path: str) -> Dict[str, Any]:
        """Create the main results dictionary with comprehensive data"""
        return {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "crypto_hunter_version": "1.0.0",
                "analysis_duration": self._calculate_analysis_duration(state)
            },
            "puzzle_info": {
                "path": str(puzzle_path),
                "puzzle_file": state.puzzle_file,
                "file_type": state.file_type,
                "file_size": state.file_size,
                "hash": state.hash,
                "puzzle_type": state.puzzle_type
            },
            "analysis_summary": {
                "status": state.status,
                "solution": state.solution,
                "insights_count": len(state.insights),
                "transformations_count": len(state.transformations),
                "analyzers_used": list(state.analyzers_used),
                "related_files_count": len(state.related_files),
                "clues_count": len(state.clues),
                "patterns_count": len(state.patterns),
                "high_confidence_extractions": self._count_high_confidence_extractions(state)
            },
            "insights": state.insights,
            "transformations": [self._sanitize_transformation(t) for t in state.transformations],
            "related_files": {
                name: {
                    "size": info["size"],
                    "sha256": info["sha256"],
                    "has_text": "text_content" in info
                }
                for name, info in state.related_files.items()
            },
            "clues": state.clues,
            "patterns": state.patterns,
            "content_samples": {
                "puzzle_text_preview": state.puzzle_text[:1000] + "..." if state.puzzle_text and len(
                    state.puzzle_text) > 1000 else state.puzzle_text,
                "binary_data_preview": base64.b64encode(state.binary_data[:100]).decode(
                    'ascii') if state.binary_data else None
            }
        }

    def _sanitize_transformation(self, transformation: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize transformation data for JSON serialization"""
        sanitized = transformation.copy()

        # Truncate very long output data
        if "output_data" in sanitized and len(str(sanitized["output_data"])) > 10000:
            sanitized["output_data"] = str(sanitized["output_data"])[:10000] + "... [TRUNCATED]"

        return sanitized

    def _calculate_analysis_duration(self, state) -> Optional[str]:
        """Calculate analysis duration from timestamps"""
        if not state.insights:
            return None

        try:
            first_time = datetime.fromisoformat(state.insights[0].get("timestamp", ""))
            last_time = datetime.fromisoformat(state.insights[-1].get("timestamp", ""))
            duration = last_time - first_time
            return str(duration)
        except:
            return None

    def _count_high_confidence_extractions(self, state) -> int:
        """Count high-confidence steganographic extractions"""
        count = 0
        for transform in state.transformations:
            name = transform.get("name", "").lower()
            if any(keyword in name for keyword in ["high-confidence", "steganography", "extracted", "lsb"]):
                count += 1
        return count

    def _save_html_report(self, state, puzzle_path: str, report_path: Path):
        """Save a comprehensive HTML report"""
        try:
            html_content = self._generate_html_report(state, puzzle_path)
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html_content)
        except Exception as e:
            self.logger.error(f"Failed to save HTML report: {e}")

    def _generate_html_report(self, state, puzzle_path: str) -> str:
        """Generate HTML report content"""
        # Basic HTML template with embedded CSS
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Crypto Hunter Analysis Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #667eea; background: #f8f9fa; }}
        .solution {{ background: #d4edda; border-color: #28a745; color: #155724; }}
        .warning {{ background: #fff3cd; border-color: #ffc107; color: #856404; }}
        .error {{ background: #f8d7da; border-color: #dc3545; color: #721c24; }}
        .code {{ background: #f4f4f4; padding: 10px; border-radius: 4px; font-family: monospace; overflow-x: auto; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
        .card {{ background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Crypto Hunter Analysis Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Puzzle:</strong> {puzzle_path}</p>
    </div>
"""

        # Solution section
        if state.solution:
            html += f"""
    <div class="section solution">
        <h2>🎉 Solution Found!</h2>
        <div class="code">{state.solution}</div>
    </div>
"""

        # Puzzle information
        html += f"""
    <div class="section">
        <h2>📁 Puzzle Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>File</td><td>{state.puzzle_file or 'N/A'}</td></tr>
            <tr><td>Type</td><td>{state.file_type or 'N/A'}</td></tr>
            <tr><td>Size</td><td>{state.file_size or 'N/A'} bytes</td></tr>
            <tr><td>Hash</td><td>{state.hash or 'N/A'}</td></tr>
            <tr><td>Puzzle Type</td><td>{state.puzzle_type or 'N/A'}</td></tr>
            <tr><td>Status</td><td>{state.status}</td></tr>
        </table>
    </div>
"""

        # Analysis summary
        html += f"""
    <div class="section">
        <h2>📊 Analysis Summary</h2>
        <div class="grid">
            <div class="card">
                <h3>Statistics</h3>
                <ul>
                    <li><strong>Insights:</strong> {len(state.insights)}</li>
                    <li><strong>Transformations:</strong> {len(state.transformations)}</li>
                    <li><strong>Analyzers Used:</strong> {len(state.analyzers_used)}</li>
                </ul>
            </div>
            <div class="card">
                <h3>Data Sources</h3>
                <ul>
                    <li><strong>Related Files:</strong> {len(state.related_files)}</li>
                    <li><strong>Clues:</strong> {len(state.clues)}</li>
                    <li><strong>Patterns:</strong> {len(state.patterns)}</li>
                </ul>
            </div>
        </div>
    </div>
"""

        # Key findings
        key_insights = self._extract_key_insights(state)
        html += """
    <div class="section">
        <h2>🔍 Key Findings</h2>
"""

        for category, insights in key_insights.items():
            if insights:
                html += f"<h3>{category}</h3><ul>"
                for insight in insights[:5]:  # Top 5 per category
                    html += f"<li>{insight}</li>"
                html += "</ul>"

        html += "</div>"

        # Steganographic extractions
        stego_transformations = [t for t in state.transformations
                                 if "steganography" in t.get("name", "").lower() or
                                 "lsb" in t.get("name", "").lower()]

        if stego_transformations:
            html += """
    <div class="section">
        <h2>🔐 Steganographic Extractions</h2>
"""
            for i, transform in enumerate(stego_transformations[:5], 1):  # Top 5
                html += f"""
        <div class="card">
            <h4>{i}. {transform['name']}</h4>
            <p><strong>Description:</strong> {transform['description']}</p>
            <div class="code">{str(transform['output_data'])[:500]}{'...' if len(str(transform['output_data'])) > 500 else ''}</div>
        </div>
"""
            html += "</div>"

        # Recent insights
        html += """
    <div class="section">
        <h2>📝 Recent Analysis Log</h2>
        <div style="max-height: 400px; overflow-y: auto;">
"""

        for insight in state.insights[-20:]:  # Last 20 insights
            analyzer = insight.get('analyzer', 'unknown')
            message = insight.get('message', insight.get('text', ''))
            time_str = insight.get('time', '')
            html += f"<p><strong>[{time_str}] {analyzer}:</strong> {message}</p>"

        html += """
        </div>
    </div>
</body>
</html>"""

        return html

    def _save_analysis_report(self, state, puzzle_path: str, report_path: Path):
        """Save a detailed analysis report in Markdown format"""
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(f"# Crypto Hunter Analysis Report\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Puzzle:** {puzzle_path}\n\n")

                # Puzzle Information
                f.write("## Puzzle Information\n\n")
                f.write(f"- **File:** {state.puzzle_file}\n")
                f.write(f"- **Type:** {state.file_type}\n")
                f.write(f"- **Size:** {state.file_size} bytes\n")
                f.write(f"- **Hash:** {state.hash}\n")
                f.write(f"- **Puzzle Type:** {state.puzzle_type}\n")
                f.write(f"- **Status:** {state.status}\n")
                if state.solution:
                    f.write(f"- **Solution:** `{state.solution}`\n")
                f.write("\n")

                # Analysis Summary
                f.write("## Analysis Summary\n\n")
                f.write(f"- **Insights Generated:** {len(state.insights)}\n")
                f.write(f"- **Transformations Applied:** {len(state.transformations)}\n")
                f.write(f"- **Analyzers Used:** {', '.join(sorted(state.analyzers_used))}\n")
                if state.related_files:
                    f.write(f"- **Related Files:** {len(state.related_files)}\n")
                if state.clues:
                    f.write(f"- **Clues:** {len(state.clues)}\n")
                if state.patterns:
                    f.write(f"- **Patterns:** {len(state.patterns)}\n")
                f.write("\n")

                # Key Findings
                f.write("## Key Findings\n\n")
                key_insights = self._extract_key_insights(state)
                for category, insights in key_insights.items():
                    if insights:
                        f.write(f"### {category}\n\n")
                        for insight in insights:
                            f.write(f"- {insight}\n")
                        f.write("\n")

                # Steganographic Extractions
                stego_transformations = [t for t in state.transformations
                                         if "steganography" in t.get("name", "").lower() or
                                         "lsb" in t.get("name", "").lower()]
                if stego_transformations:
                    f.write("## Steganographic Extractions\n\n")
                    for i, transform in enumerate(stego_transformations, 1):
                        f.write(f"### {i}. {transform['name']}\n\n")
                        f.write(f"**Description:** {transform['description']}\n\n")
                        f.write(f"**Output Preview:**\n```\n{str(transform['output_data'])[:500]}...\n```\n\n")

                # All Insights (chronological)
                f.write("## Detailed Analysis Log\n\n")
                for i, insight in enumerate(state.insights, 1):
                    f.write(
                        f"{i}. **[{insight.get('time', '')}] {insight.get('analyzer', '')}:** {insight.get('message', insight.get('text', ''))}\n")
                f.write("\n")
        except Exception as e:
            self.logger.error(f"Failed to save analysis report: {e}")

    def _save_steganography_data(self, state, base_name: str) -> Dict[str, str]:
        """Save extracted steganographic data to separate files"""
        saved_files = {}
        try:
            stego_dir = self.output_dir / "steganography" / base_name
            stego_dir.mkdir(parents=True, exist_ok=True)

            # Find steganographic transformations
            stego_transformations = [t for t in state.transformations
                                     if any(keyword in t.get("name", "").lower()
                                            for keyword in
                                            ["steganography", "lsb", "dct", "dft", "extraction", "hidden", "chunk"])]

            for i, transform in enumerate(stego_transformations):
                safe_name = self._make_safe_filename(transform['name'])
                filename = f"{i + 1:02d}_{safe_name}.txt"
                filepath = stego_dir / filename

                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(f"Extraction Method: {transform['name']}\n")
                    f.write(f"Description: {transform['description']}\n")
                    f.write(f"Analyzer: {transform['analyzer']}\n")
                    f.write(f"Timestamp: {transform.get('timestamp', '')}\n")
                    f.write(f"Input: {transform.get('input_data', '')}\n")
                    f.write(f"\n{'=' * 50}\n")
                    f.write(f"EXTRACTED DATA:\n")
                    f.write(f"{'=' * 50}\n\n")
                    f.write(str(transform['output_data']))

                saved_files[f"stego_{i + 1}"] = str(filepath)

                # Also save binary data if it looks like a file
                output_data = transform['output_data']
                if isinstance(output_data, (bytes, bytearray)) or (
                        isinstance(output_data, str) and len(output_data) > 100):
                    binary_path = stego_dir / f"{i + 1:02d}_{safe_name}.bin"
                    try:
                        if isinstance(output_data, str):
                            # Try to decode as hex or base64
                            binary_data = self._try_decode_string(output_data)
                        else:
                            binary_data = output_data

                        if binary_data:
                            with open(binary_path, "wb") as bf:
                                bf.write(binary_data)
                            saved_files[f"stego_{i + 1}_binary"] = str(binary_path)
                    except Exception as e:
                        self.logger.debug(f"Could not save binary data for {safe_name}: {e}")

        except Exception as e:
            self.logger.error(f"Failed to save steganography data: {e}")

        return saved_files

    def _save_binary_data(self, state, base_name: str) -> Dict[str, str]:
        """Save binary data extractions"""
        saved_files = {}
        try:
            binary_dir = self.output_dir / "binary_data" / base_name
            binary_dir.mkdir(parents=True, exist_ok=True)

            # Save original binary data if available
            if state.binary_data:
                original_path = binary_dir / "original_binary.bin"
                with open(original_path, "wb") as f:
                    f.write(state.binary_data)
                saved_files["original_binary"] = str(original_path)

                # Also save as hex dump
                hex_path = binary_dir / "original_binary.hex"
                with open(hex_path, "w") as f:
                    hex_data = binascii.hexlify(state.binary_data).decode('ascii')
                    # Format as hex dump
                    for i in range(0, len(hex_data), 32):
                        f.write(f"{i // 2:08x}: {hex_data[i:i + 32]}\n")
                saved_files["original_hex"] = str(hex_path)

            # Save any binary transformations
            binary_transforms = [t for t in state.transformations
                                 if "binary" in t.get("name", "").lower() or
                                 "hex" in t.get("name", "").lower()]

            for i, transform in enumerate(binary_transforms):
                safe_name = self._make_safe_filename(transform['name'])

                # Try to extract binary data
                output_data = transform['output_data']
                binary_data = self._try_decode_string(str(output_data))

                if binary_data and len(binary_data) > 10:
                    binary_path = binary_dir / f"{i + 1:02d}_{safe_name}.bin"
                    with open(binary_path, "wb") as f:
                        f.write(binary_data)
                    saved_files[f"binary_{i + 1}"] = str(binary_path)

        except Exception as e:
            self.logger.error(f"Failed to save binary data: {e}")

        return saved_files

    def _try_decode_string(self, data_str: str) -> Optional[bytes]:
        """Try to decode a string as hex, base64, or other formats"""
        if not isinstance(data_str, str):
            return None

        data_str = data_str.strip()

        # Try hex decoding
        try:
            if all(c in '0123456789abcdefABCDEF' for c in data_str.replace(' ', '').replace('\n', '')):
                clean_hex = ''.join(data_str.split())
                if len(clean_hex) % 2 == 0:
                    return bytes.fromhex(clean_hex)
        except:
            pass

        # Try base64 decoding
        try:
            import base64
            return base64.b64decode(data_str)
        except:
            pass

        # Try as UTF-8 bytes
        try:
            return data_str.encode('utf-8')
        except:
            pass

        return None

    def _save_potential_keys(self, state, base_name: str) -> Dict[str, str]:
        """Save potential cryptographic keys found in the analysis"""
        saved_files = {}
        try:
            keys_dir = self.output_dir / "potential_keys" / base_name
            keys_dir.mkdir(parents=True, exist_ok=True)

            # Look for various types of potential keys
            potential_keys = []

            for transform in state.transformations:
                output = str(transform.get('output_data', ''))

                # Look for hex strings that could be keys
                potential_keys.extend(self._find_hex_keys(output, transform))

                # Look for WIF format private keys
                potential_keys.extend(self._find_wif_keys(output, transform))

                # Look for mnemonic phrases
                potential_keys.extend(self._find_mnemonic_phrases(output, transform))

                # Look for Ethereum addresses
                potential_keys.extend(self._find_ethereum_addresses(output, transform))

                # Look for Bitcoin addresses
                potential_keys.extend(self._find_bitcoin_addresses(output, transform))

            # Save potential keys
            if potential_keys:
                keys_file = keys_dir / "potential_keys.json"
                self._safe_write_json(keys_file, potential_keys)
                saved_files["potential_keys_json"] = str(keys_file)

                # Also save as text for easy reading
                keys_txt = keys_dir / "potential_keys.txt"
                with open(keys_txt, "w", encoding="utf-8") as f:
                    f.write("POTENTIAL CRYPTOGRAPHIC KEYS FOUND\n")
                    f.write("=" * 50 + "\n\n")

                    for i, key in enumerate(potential_keys, 1):
                        f.write(f"{i}. {key['type']}\n")
                        f.write(f"   Value: {key['value']}\n")
                        f.write(f"   Source: {key['source']}\n")
                        f.write(f"   Description: {key['description']}\n")
                        f.write(f"   Confidence: {key.get('confidence', 'unknown')}\n\n")

                saved_files["potential_keys_txt"] = str(keys_txt)

                # Create individual key files for high-confidence keys
                high_conf_keys = [k for k in potential_keys if k.get('confidence') == 'high']
                for i, key in enumerate(high_conf_keys, 1):
                    key_file = keys_dir / f"key_{i:02d}_{key['type'].replace(' ', '_')}.txt"
                    with open(key_file, "w", encoding="utf-8") as f:
                        f.write(f"Type: {key['type']}\n")
                        f.write(f"Value: {key['value']}\n")
                        f.write(f"Source: {key['source']}\n")
                        f.write(f"Description: {key['description']}\n")
                        f.write(f"Confidence: {key.get('confidence', 'unknown')}\n")
                    saved_files[f"key_{i}"] = str(key_file)

        except Exception as e:
            self.logger.error(f"Failed to save potential keys: {e}")

        return saved_files

    def _find_hex_keys(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]:
        """Find hex strings that could be cryptographic keys"""
        keys = []

        # Different key lengths to look for
        key_patterns = {
            64: "32-byte hex (potential private key/hash)",
            40: "20-byte hex (potential address/hash)",
            32: "16-byte hex (potential AES key)",
            16: "8-byte hex (potential key fragment)"
        }

        for length, description in key_patterns.items():
            hex_matches = self._find_hex_patterns(text, length)
            for match in hex_matches:
                confidence = "high" if length == 64 else "medium" if length == 40 else "low"
                keys.append({
                    "type": description,
                    "value": match,
                    "source": transform['name'],
                    "description": transform['description'],
                    "confidence": confidence
                })

        return keys

    def _find_wif_keys(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]:
        """Find WIF format private keys"""
        import re
        keys = []
        pattern = r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b'
        matches = re.findall(pattern, text)

        for match in matches:
            keys.append({
                "type": "WIF private key",
                "value": match,
                "source": transform['name'],
                "description": transform['description'],
                "confidence": "high"
            })

        return keys

    def _find_mnemonic_phrases(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]:
        """Find potential BIP39 mnemonic phrases"""
        import re
        keys = []

        # Look for sequences of words that might be seed phrases
        words = re.findall(r'\b[a-z]{3,8}\b', text.lower())

        # Check for common mnemonic lengths
        for phrase_length in [12, 15, 18, 21, 24]:
            if len(words) >= phrase_length:
                for i in range(len(words) - phrase_length + 1):
                    phrase = " ".join(words[i:i + phrase_length])
                    # Basic check for mnemonic-like content
                    if self._is_potential_mnemonic(phrase):
                        keys.append({
                            "type": f"Potential BIP39 mnemonic ({phrase_length} words)",
                            "value": phrase,
                            "source": transform['name'],
                            "description": transform['description'],
                            "confidence": "medium"
                        })
                        break  # Only take the first potential match per length

        return keys

    def _find_ethereum_addresses(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]:
        """Find Ethereum addresses"""
        import re
        keys = []
        pattern = r'\b0x[a-fA-F0-9]{40}\b'
        matches = re.findall(pattern, text)

        for match in matches:
            keys.append({
                "type": "Ethereum address",
                "value": match,
                "source": transform['name'],
                "description": transform['description'],
                "confidence": "high"
            })

        return keys

    def _find_bitcoin_addresses(self, text: str, transform: Dict[str, Any]) -> List[Dict[str, str]]:
        """Find Bitcoin addresses"""
        import re
        keys = []
        pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        matches = re.findall(pattern, text)

        for match in matches:
            keys.append({
                "type": "Bitcoin address",
                "value": match,
                "source": transform['name'],
                "description": transform['description'],
                "confidence": "high"
            })

        return keys

    def _is_potential_mnemonic(self, phrase: str) -> bool:
        """Basic check if a phrase could be a BIP39 mnemonic"""
        words = phrase.split()

        # Check if words look like common English words (very basic check)
        common_patterns = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one',
                           'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'its', 'may', 'new', 'now', 'old',
                           'see', 'two', 'way', 'who', 'boy', 'did', 'man', 'car', 'eye', 'sun', 'run', 'big', 'end',
                           'far', 'fun', 'got', 'gun', 'hot', 'let', 'lot', 'men', 'mom', 'red', 'sat', 'six', 'ten',
                           'top', 'win', 'yes', 'yet', 'zoo']

        # Check if at least some words match common patterns
        matches = sum(1 for word in words if any(pattern in word for pattern in common_patterns))
        return matches >= len(words) * 0.3  # At least 30% should have common patterns

    def _save_transformations(self, state, base_name: str) -> Dict[str, str]:
        """Save all transformations as individual files"""
        saved_files = {}
        try:
            transform_dir = self.output_dir / "extracted_data" / base_name
            transform_dir.mkdir(parents=True, exist_ok=True)

            for i, transform in enumerate(state.transformations):
                safe_name = self._make_safe_filename(transform['name'])
                filename = f"{i + 1:02d}_{safe_name}.txt"
                filepath = transform_dir / filename

                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(f"Name: {transform['name']}\n")
                    f.write(f"Description: {transform['description']}\n")
                    f.write(f"Analyzer: {transform['analyzer']}\n")
                    f.write(f"Timestamp: {transform.get('timestamp', '')}\n")
                    f.write(f"Input: {transform.get('input_data', '')}\n")
                    f.write(f"\n{'=' * 50}\n")
                    f.write(f"OUTPUT DATA:\n")
                    f.write(f"{'=' * 50}\n\n")
                    f.write(str(transform['output_data']))

                saved_files[f"transform_{i + 1}"] = str(filepath)

        except Exception as e:
            self.logger.error(f"Failed to save transformations: {e}")

        return saved_files

    def _save_execution_log(self, state, log_path: Path):
        """Save execution log with all insights in chronological order"""
        try:
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(f"Crypto Hunter Execution Log\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'=' * 50}\n\n")

                for insight in state.insights:
                    timestamp = insight.get('timestamp', insight.get('time', ''))
                    analyzer = insight.get('analyzer', 'unknown')
                    message = insight.get('message', insight.get('text', ''))

                    f.write(f"[{timestamp}] {analyzer}: {message}\n")
        except Exception as e:
            self.logger.error(f"Failed to save execution log: {e}")

    def _create_summary_file(self, state, puzzle_path: str, saved_files: Dict[str, str], summary_path: Path):
        """Create a summary file with key information and file locations"""
        try:
            with open(summary_path, "w", encoding="utf-8") as f:
                f.write("CRYPTO HUNTER ANALYSIS SUMMARY\n")
                f.write("=" * 50 + "\n\n")

                f.write(f"Puzzle: {puzzle_path}\n")
                f.write(f"Analyzed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Status: {state.status}\n")
                if state.solution:
                    f.write(f"SOLUTION: {state.solution}\n")
                f.write("\n")

                # Key Statistics
                f.write("ANALYSIS STATISTICS:\n")
                f.write("-" * 20 + "\n")
                f.write(f"Insights Generated: {len(state.insights)}\n")
                f.write(f"Transformations: {len(state.transformations)}\n")
                f.write(f"Analyzers Used: {len(state.analyzers_used)}\n")
                f.write(f"File Size: {state.file_size} bytes\n")
                f.write("\n")

                # Key Findings
                key_insights = self._extract_key_insights(state)
                if any(key_insights.values()):
                    f.write("KEY FINDINGS:\n")
                    f.write("-" * 20 + "\n")
                    for category, insights in key_insights.items():
                        if insights:
                            f.write(f"{category}:\n")
                            for insight in insights[:3]:  # Top 3 per category
                                f.write(f"  - {insight}\n")
                    f.write("\n")

                # Generated Files
                f.write("GENERATED FILES:\n")
                f.write("-" * 20 + "\n")
                for file_type, file_path in saved_files.items():
                    f.write(f"{file_type}: {file_path}\n")
                f.write("\n")

                # Quick Access to Important Files
                if "potential_keys_txt" in saved_files:
                    f.write("⚠️  POTENTIAL CRYPTOGRAPHIC KEYS FOUND!\n")
                    f.write(f"    See: {saved_files['potential_keys_txt']}\n\n")

                if "html_report" in saved_files:
                    f.write("🌐 HTML REPORT AVAILABLE:\n")
                    f.write(f"    Open: {saved_files['html_report']}\n\n")

                if state.solution:
                    f.write("🎉 PUZZLE SOLVED!\n")
                    f.write(f"    Solution: {state.solution}\n\n")
        except Exception as e:
            self.logger.error(f"Failed to create summary file: {e}")

    def _create_compressed_archive(self, saved_files: Dict[str, str], base_name: str) -> Optional[str]:
        """Create a compressed archive of all generated files"""
        try:
            archive_path = self.output_dir / "compressed" / f"{base_name}_complete.zip"

            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_type, file_path in saved_files.items():
                    if file_path and Path(file_path).exists():
                        # Add file with a clean name in the archive
                        archive_name = f"{file_type}_{Path(file_path).name}"
                        zipf.write(file_path, archive_name)

            return str(archive_path)
        except Exception as e:
            self.logger.error(f"Failed to create compressed archive: {e}")
            return None

    def _extract_key_insights(self, state) -> Dict[str, List[str]]:
        """Extract and categorize key insights"""
        categories = {
            "Steganography": [],
            "Cryptographic Keys": [],
            "File Analysis": [],
            "Potential Solutions": [],
            "Errors/Issues": []
        }

        for insight in state.insights:
            message = insight.get('message', insight.get('text', '')).lower()
            original_message = insight.get('message', insight.get('text', ''))

            if any(keyword in message for keyword in
                   ['lsb', 'steganography', 'hidden', 'extracted', 'chunk', 'metadata']):
                categories["Steganography"].append(original_message)
            elif any(keyword in message for keyword in ['key', 'private', 'wif', 'hex', 'address', 'mnemonic']):
                categories["Cryptographic Keys"].append(original_message)
            elif any(keyword in message for keyword in ['solution', 'flag', 'answer', 'solved']):
                categories["Potential Solutions"].append(original_message)
            elif any(keyword in message for keyword in ['error', 'failed', 'issue', 'problem']):
                categories["Errors/Issues"].append(original_message)
            elif any(keyword in message for keyword in ['file', 'format', 'size', 'entropy', 'binary', 'analysis']):
                categories["File Analysis"].append(original_message)

        return categories

    def _find_hex_patterns(self, text: str, length: int) -> List[str]:
        """Find hex patterns of specific length"""
        import re
        pattern = f'\\b[0-9a-fA-F]{{{length}}}\\b'
        return re.findall(pattern, text)

    def _make_safe_filename(self, name: str) -> str:
        """Make a string safe for use as a filename"""
        import re
        # Replace unsafe characters with underscores
        safe = re.sub(r'[<>:"/\\|?*]', '_', name)
        # Remove multiple underscores
        safe = re.sub(r'_+', '_', safe)
        # Trim and limit length
        return safe.strip('_')[:50]


# Global instance
enhanced_saver = EnhancedStateSaver()
