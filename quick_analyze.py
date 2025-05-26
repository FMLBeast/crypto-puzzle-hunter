#!/usr/bin/env python3
"""
Quick analysis script for Crypto Hunter project.
Run this to get all the files needed for collaboration.
"""

import os
import sys
from pathlib import Path

# Add the project walker to the path
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))

from project_walker import ProjectWalker

def quick_analyze():
    """Run a quick analysis and generate all useful output files."""
    print("🚀 Quick Crypto Hunter Project Analysis")
    print("=" * 50)
    
    # Detect project root
    current_dir = Path.cwd()
    project_root = current_dir
    
    # Look for indicators of the project root
    indicators = ['core', 'analyzers', 'main.py', 'requirements.txt', '.git']
    for indicator in indicators:
        if (current_dir / indicator).exists():
            project_root = current_dir
            break
    
    print(f"📁 Analyzing project at: {project_root}")
    
    # Initialize walker with sensible defaults for this project
    walker = ProjectWalker(
        str(project_root),
        exclude_dirs=[
            '__pycache__', '.git', '.pytest_cache', 'node_modules', 
            '.venv', 'venv', 'env', '.env', 'build', 'dist',
            'output', 'results', 'logs', 'temp', 'cache'
        ],
        exclude_files=[
            '__init__.py'  # Usually just imports
        ]
    )
    
    print("🔍 Walking project structure...")
    project_info = walker.walk_project()
    
    # Generate all outputs
    print("📝 Generating overview...")
    summary = walker.generate_summary(project_info)
    
    print("📋 Creating function index...")
    function_index = walker.create_function_index(project_info)
    
    # Save files
    output_dir = project_root / "project_analysis"
    output_dir.mkdir(exist_ok=True)
    
    # Main overview file
    overview_file = output_dir / "project_overview.md"
    with open(overview_file, 'w', encoding='utf-8') as f:
        f.write("# Crypto Hunter Project Overview\n\n")
        f.write("*Generated automatically for collaboration*\n\n")
        f.write(summary)
    
    # Function index
    index_file = output_dir / "function_index.md"
    with open(index_file, 'w', encoding='utf-8') as f:
        f.write("# Function Index\n\n")
        f.write("*Searchable reference of all functions and methods*\n\n")
        f.write(function_index)
    
    # Detailed JSON
    json_file = output_dir / "detailed_structure.json"
    walker.save_detailed_json(project_info, str(json_file))
    
    # Create a collaboration-ready summary
    collab_file = output_dir / "collaboration_summary.md"
    collab_content = create_collaboration_summary(project_info, summary)
    with open(collab_file, 'w', encoding='utf-8') as f:
        f.write(collab_content)
    
    print(f"✅ Analysis complete! Generated files:")
    print(f"   📄 {overview_file} - Full project overview")
    print(f"   📋 {index_file} - Function index")
    print(f"   🤝 {collab_file} - Collaboration-ready summary")
    print(f"   📊 {json_file} - Detailed JSON data")
    print()
    print("🤝 COLLABORATION READY!")
    print("Share the collaboration_summary.md file to get started.")
    
    return str(collab_file)

def create_collaboration_summary(project_info, full_summary):
    """Create a concise summary perfect for collaboration."""
    
    # Calculate totals
    total_files = sum(len(modules) for modules in project_info.values())
    total_functions = sum(len(mod.functions) for modules in project_info.values() for mod in modules)
    total_classes = sum(len(mod.classes) for modules in project_info.values() for mod in modules)
    
    collab = []
    collab.append("# Crypto Hunter - Collaboration Summary")
    collab.append("")
    collab.append("## 🎯 Project Purpose")
    collab.append("Advanced cryptographic puzzle solving framework with multiple specialized analyzers and AI orchestration.")
    collab.append("")
    collab.append("## 📊 Quick Stats")
    collab.append(f"- **{total_files}** Python modules")
    collab.append(f"- **{total_functions}** functions")
    collab.append(f"- **{total_classes}** classes")
    collab.append("")
    
    collab.append("## 🏗️ Architecture Overview")
    collab.append("")
    
    # Highlight key modules
    key_modules = {
        "core_modules": "Core Framework",
        "analyzers": "Puzzle Analyzers", 
        "tools": "Specialized Tools"
    }
    
    for category, title in key_modules.items():
        modules = project_info.get(category, [])
        if modules:
            collab.append(f"### {title} ({len(modules)} modules)")
            
            for module in modules:
                collab.append(f"**{module.name}**")
                if module.docstring:
                    doc = module.docstring.split('\n')[0][:100]
                    collab.append(f"  - {doc}")
                
                # Key functions
                if module.functions:
                    key_funcs = [f.name for f in module.functions[:3]]
                    collab.append(f"  - Functions: {', '.join(key_funcs)}")
                
                # Key classes
                if module.classes:
                    key_classes = [c.name for c in module.classes[:2]]
                    collab.append(f"  - Classes: {', '.join(key_classes)}")
                
                collab.append("")
    
    collab.append("## 🔧 Key Integration Points")
    collab.append("")
    
    # Find key classes and functions for collaboration
    integration_points = []
    
    for modules in project_info.values():
        for module in modules:
            # Look for key orchestration classes
            for cls in module.classes:
                if any(keyword in cls.name.lower() for keyword in 
                       ['agent', 'orchestrator', 'manager', 'coordinator', 'analyzer']):
                    integration_points.append(f"**{module.name}.{cls.name}** - {cls.docstring.split(chr(10))[0] if cls.docstring else 'Core component'}")
            
            # Look for key functions
            for func in module.functions:
                if any(keyword in func.name.lower() for keyword in 
                       ['analyze', 'solve', 'process', 'orchestrate', 'coordinate']):
                    if func.docstring:
                        integration_points.append(f"**{module.name}.{func.name}()** - {func.docstring.split(chr(10))[0]}")
    
    # Show top integration points
    for point in integration_points[:8]:
        collab.append(f"- {point}")
    
    collab.append("")
    collab.append("## 🤝 Ready for Collaboration")
    collab.append("")
    collab.append("This project is well-structured and ready for collaborative development. Key areas for enhancement:")
    collab.append("")
    collab.append("1. **Analyzer Enhancement** - Improve existing puzzle-solving algorithms")
    collab.append("2. **New Tool Integration** - Add support for new cryptographic techniques")
    collab.append("3. **Agent Orchestration** - Enhance AI coordination between components")
    collab.append("4. **Performance Optimization** - Optimize analysis pipelines")
    collab.append("5. **Feature Expansion** - Add new puzzle types and solving methods")
    collab.append("")
    collab.append("---")
    collab.append("*Use this summary to understand the project structure before diving into specific modules.*")
    
    return "\n".join(collab)

if __name__ == "__main__":
    quick_analyze()
