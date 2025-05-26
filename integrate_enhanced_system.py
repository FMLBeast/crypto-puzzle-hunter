#!/usr/bin/env python3
"""
Integration Script for Enhanced Crypto Hunter System
Replaces the old workflow with the new enhanced system
"""

import os
import sys
import shutil
from pathlib import Path
import argparse


def backup_existing_files():
    """Backup existing main.py and other files that will be replaced"""
    backup_dir = Path("backup_old_system")
    backup_dir.mkdir(exist_ok=True)
    
    files_to_backup = [
        "main.py",
        "core/state.py"  # We'll need the old State class for compatibility
    ]
    
    for file_path in files_to_backup:
        if Path(file_path).exists():
            backup_path = backup_dir / file_path
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file_path, backup_path)
            print(f"✅ Backed up {file_path} to {backup_path}")


def create_new_main_py():
    """Create the new main.py that uses enhanced system by default"""
    new_main_content = '''#!/usr/bin/env python3
"""
Crypto Hunter - Enhanced Workflow System
Complete replacement with intelligent orchestration
"""

import os
import sys
import argparse
from pathlib import Path

# Enhanced system imports
from enhanced_main import EnhancedCryptoHunter, parse_arguments as parse_enhanced_args

# Legacy fallback imports
try:
    from core.agent import CryptoAgent
    from core.state import State
    from core.utils import setup_logging
    LEGACY_AVAILABLE = True
except ImportError:
    LEGACY_AVAILABLE = False


def main():
    """Main entry point - uses enhanced system by default"""
    
    # Check if user wants legacy mode
    if "--legacy" in sys.argv:
        if not LEGACY_AVAILABLE:
            print("❌ Legacy system not available")
            sys.exit(1)
        
        # Remove --legacy flag and run old system
        sys.argv.remove("--legacy")
        import main_legacy
        main_legacy.main()
        return
    
    # Run enhanced system
    try:
        app = EnhancedCryptoHunter()
        app.display_banner()
        
        # Parse arguments
        args = parse_enhanced_args()
        
        # Run analysis
        if args.interactive:
            success = app.run_interactive_mode(args)
        elif args.puzzle_file:
            success = app.run_analysis(args.puzzle_file, args)
        else:
            app.console.print("[red]❌ No puzzle file specified. Use --help for usage.[/red]")
            success = False
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\\n🛑 Analysis interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
'''
    
    # Backup existing main.py
    if Path("main.py").exists():
        shutil.copy2("main.py", "main_legacy.py")
        print("✅ Backed up main.py to main_legacy.py")
    
    # Write new main.py
    with open("main.py", "w") as f:
        f.write(new_main_content)
    
    print("✅ Created new main.py with enhanced system")


def update_existing_files():
    """Update existing files for compatibility"""
    
    # Add import compatibility to core/__init__.py
    core_init = Path("core/__init__.py")
    if not core_init.exists():
        core_init.write_text("# Core module initialization\\n")
    
    # Create enhanced system directory if needed
    enhanced_dir = Path("enhanced")
    enhanced_dir.mkdir(exist_ok=True)
    
    print("✅ Updated core module structure")


def create_requirements_update():
    """Create updated requirements.txt"""
    enhanced_requirements = """
# Enhanced Crypto Hunter Requirements

# Core dependencies (existing)
anthropic>=0.7.0
openai>=1.0.0
langchain>=0.1.0
langchain-anthropic>=0.1.0
langchain-openai>=0.1.0
langchain-community>=0.0.20
python-dotenv>=1.0.0

# Image processing (existing)
Pillow>=10.0.0
opencv-python>=4.8.0
numpy>=1.24.0

# Crypto and blockchain (existing)
cryptography>=41.0.0
eth-utils>=2.3.0
web3>=6.11.0
eth-keys>=0.4.0
requests>=2.31.0

# Text processing (existing)
beautifulsoup4>=4.12.0
html5lib>=1.1

# Enhanced system dependencies
rich>=13.0.0
click>=8.1.0
pydantic>=2.0.0
fastapi>=0.104.0
uvicorn>=0.24.0

# Data analysis and visualization
pandas>=2.0.0
matplotlib>=3.7.0
seaborn>=0.12.0
plotly>=5.17.0

# Scientific computing
scipy>=1.11.0
scikit-learn>=1.3.0
networkx>=3.2.0

# Development tools
pytest>=7.4.0
black>=23.9.0
isort>=5.12.0
mypy>=1.6.0
"""
    
    with open("requirements_enhanced.txt", "w") as f:
        f.write(enhanced_requirements.strip())
    
    print("✅ Created requirements_enhanced.txt")


def create_startup_script():
    """Create convenient startup script"""
    startup_script = '''#!/bin/bash
# Enhanced Crypto Hunter Startup Script

echo "🧩 Enhanced Crypto Hunter"
echo "========================"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/upgrade requirements
echo "Installing requirements..."
pip install -r requirements_enhanced.txt

# Run the application
echo "Starting Enhanced Crypto Hunter..."
python main.py "$@"
'''
    
    with open("start_enhanced.sh", "w") as f:
        f.write(startup_script)
    
    os.chmod("start_enhanced.sh", 0o755)
    print("✅ Created start_enhanced.sh script")


def create_test_puzzle():
    """Create a simple test puzzle to verify the system works"""
    test_dir = Path("test_puzzles")
    test_dir.mkdir(exist_ok=True)
    
    # Simple base64 encoded text
    test_content = "VGhpcyBpcyBhIHRlc3QgcHV6emxlIGZvciBFbmhhbmNlZCBDcnlwdG8gSHVudGVyIQ=="
    
    with open(test_dir / "simple_test.txt", "w") as f:
        f.write(test_content)
    
    # Create a more complex test puzzle
    complex_content = """
    ZmxhZ3tUaGlzX2lzX2FfY29tcGxleF90ZXN0X3B1enpsZX0K
    
    Additional clues:
    - Look for base64 patterns
    - The flag format is flag{...}
    - This is a steganography test
    """
    
    with open(test_dir / "complex_test.txt", "w") as f:
        f.write(complex_content.strip())
    
    print("✅ Created test puzzles in test_puzzles/")


def verify_installation():
    """Verify that the enhanced system is properly installed"""
    print("\\n🔍 Verifying installation...")
    
    required_files = [
        "enhanced_state_management.py",
        "task_factory.py", 
        "analyzer_bridge.py",
        "enhanced_orchestrator.py",
        "enhanced_main.py",
        "dashboard_system.py"
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
    
    if missing_files:
        print("❌ Missing required files:")
        for file_path in missing_files:
            print(f"  - {file_path}")
        return False
    
    # Test import
    try:
        import enhanced_state_management
        import task_factory
        import analyzer_bridge
        import enhanced_orchestrator
        import enhanced_main
        import dashboard_system
        print("✅ All enhanced system modules can be imported")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False


def show_usage_instructions():
    """Show usage instructions for the new system"""
    instructions = """
🎉 ENHANCED CRYPTO HUNTER INTEGRATION COMPLETE!

📋 USAGE INSTRUCTIONS:
======================

1. Basic Usage (replaces old main.py):
   python main.py puzzle.txt

2. Enhanced Features:
   python main.py puzzle.png --llm-provider anthropic --live-dashboard
   python main.py --interactive --puzzles-dir ./test_puzzles
   
3. Advanced Options:
   python main.py puzzle.zip --max-workers 5 --timeout 60 --verbose
   
4. Legacy Mode (if needed):
   python main.py --legacy puzzle.txt

📁 NEW FILES CREATED:
====================
• enhanced_state_management.py - Core workflow system
• task_factory.py - Intelligent task generation
• analyzer_bridge.py - Bridge to existing analyzers
• enhanced_orchestrator.py - Advanced orchestration
• enhanced_main.py - New main interface
• dashboard_system.py - Real-time dashboard
• main.py - Updated entry point
• main_legacy.py - Backup of old system
• requirements_enhanced.txt - Updated dependencies
• start_enhanced.sh - Startup script
• test_puzzles/ - Test puzzle files

🚀 QUICK START:
===============
1. Install dependencies: pip install -r requirements_enhanced.txt
2. Test with simple puzzle: python main.py test_puzzles/simple_test.txt
3. Try interactive mode: python main.py --interactive --puzzles-dir test_puzzles
4. Enable live dashboard: python main.py test_puzzles/complex_test.txt --live-dashboard

🔧 FEATURES:
============
✅ Intelligent task orchestration
✅ Real-time analysis dashboard
✅ LLM-guided strategy selection
✅ Parallel analyzer execution
✅ Adaptive material discovery
✅ Comprehensive result saving
✅ Interactive puzzle selection
✅ Performance monitoring

🆘 TROUBLESHOOTING:
===================
• If imports fail: pip install -r requirements_enhanced.txt
• For legacy mode: python main.py --legacy puzzle.txt
• View logs: enhanced_crypto_hunter.log
• Check dashboard: Use --live-dashboard flag

Happy puzzle solving! 🧩
"""
    
    print(instructions)


def main():
    """Main integration function"""
    parser = argparse.ArgumentParser(description="Integrate Enhanced Crypto Hunter System")
    parser.add_argument("--skip-backup", action="store_true", help="Skip backing up existing files")
    parser.add_argument("--verify-only", action="store_true", help="Only verify installation")
    args = parser.parse_args()
    
    print("🚀 Enhanced Crypto Hunter Integration")
    print("=" * 40)
    
    if args.verify_only:
        success = verify_installation()
        if success:
            print("✅ Enhanced system is properly installed")
            show_usage_instructions()
        else:
            print("❌ Enhanced system installation has issues")
        return
    
    # Step 1: Backup existing files
    if not args.skip_backup:
        print("\\n📁 Step 1: Backing up existing files...")
        backup_existing_files()
    
    # Step 2: Create new main.py
    print("\\n🔧 Step 2: Creating new main.py...")
    create_new_main_py()
    
    # Step 3: Update existing files
    print("\\n⚙️  Step 3: Updating file structure...")
    update_existing_files()
    
    # Step 4: Create requirements
    print("\\n📦 Step 4: Creating enhanced requirements...")
    create_requirements_update()
    
    # Step 5: Create startup script
    print("\\n🚀 Step 5: Creating startup script...")
    create_startup_script()
    
    # Step 6: Create test puzzles
    print("\\n🧩 Step 6: Creating test puzzles...")
    create_test_puzzle()
    
    # Step 7: Verify installation
    print("\\n🔍 Step 7: Verifying installation...")
    success = verify_installation()
    
    if success:
        print("\\n🎉 INTEGRATION SUCCESSFUL!")
        show_usage_instructions()
    else:
        print("\\n❌ INTEGRATION INCOMPLETE")
        print("Please check the error messages above and ensure all enhanced system files are present.")


if __name__ == "__main__":
    main()
