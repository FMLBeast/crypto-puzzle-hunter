# Enhanced Crypto Hunter Integration Guide

This guide will help you integrate the new enhanced workflow system into your existing Crypto Hunter project.

## 🎯 Overview

The enhanced system replaces the old linear analysis approach with:

- **Intelligent Task Orchestration**: AI-driven task generation and scheduling
- **Real-time Dashboard**: Live monitoring of analysis progress
- **Parallel Execution**: Multiple analyzers running simultaneously
- **Adaptive Discovery**: Dynamic material and finding discovery
- **LLM Integration**: Optional LLM guidance for strategy selection

## 📁 Required Files

You need to create these files in your project root:

1. **`enhanced_state_management.py`** - Core workflow components
2. **`task_factory.py`** - Intelligent task generation
3. **`analyzer_bridge.py`** - Bridge to existing analyzers
4. **`enhanced_orchestrator.py`** - Advanced orchestration engine
5. **`enhanced_main.py`** - New main interface
6. **`dashboard_system.py`** - Real-time analysis dashboard
7. **`integrate_enhanced_system.py`** - Integration script

## 🚀 Quick Integration Steps

### Step 1: Copy Files
Copy all the enhanced system files to your project root directory.

### Step 2: Run Integration Script
```bash
python integrate_enhanced_system.py
```

This will:
- Backup your existing `main.py` as `main_legacy.py`
- Create a new `main.py` that uses the enhanced system
- Set up the required directory structure
- Create test puzzles for verification

### Step 3: Install Dependencies
```bash
pip install -r requirements_enhanced.txt
```

### Step 4: Test the System
```bash
# Test with a simple puzzle
python main.py test_puzzles/simple_test.txt

# Try interactive mode
python main.py --interactive --puzzles-dir test_puzzles

# Enable live dashboard
python main.py test_puzzles/complex_test.txt --live-dashboard
```

## 🔧 Usage Examples

### Basic Analysis
```bash
python main.py puzzle.png
```

### With LLM Orchestration
```bash
python main.py puzzle.txt --llm-provider anthropic --verbose
```

### Interactive Mode
```bash
python main.py --interactive --puzzles-dir ./puzzles
```

### Advanced Configuration
```bash
python main.py puzzle.zip \
  --llm-provider openai \
  --max-workers 5 \
  --timeout 60 \
  --live-dashboard \
  --verbose
```

### Legacy Mode (Fallback)
```bash
python main.py --legacy puzzle.txt
```

## 🎛️ Command Line Options

### Analysis Configuration
- `--llm-provider {anthropic,openai}` - LLM provider for orchestration
- `--llm-model MODEL` - Specific LLM model to use
- `--require-llm` - Fail if LLM agent not available
- `--max-workers N` - Maximum parallel workers (default: 3)
- `--max-iterations N` - Maximum analysis iterations (default: 50)
- `--timeout-minutes N` - Analysis timeout (default: 30)

### Interface Options
- `--live-dashboard` - Show live analysis dashboard
- `--dashboard-refresh N` - Dashboard refresh interval (default: 2.0)
- `--interactive` - Run in interactive mode
- `--puzzles-dir DIR` - Directory containing puzzles

### Output Options
- `--output-dir DIR` - Output directory (default: enhanced_results)
- `--results-dir DIR` - Results directory (default: results)
- `--create-archive` - Create compressed archive of results
- `--verbose` - Enable verbose output
- `--debug` - Enable debug logging

## 🏗️ Architecture Overview

### Core Components

1. **WorkflowState** - Central state management
   - Tracks materials, findings, tasks
   - Manages analysis phases
   - Handles solution candidates

2. **TaskFactory** - Intelligent task generation
   - Creates tasks based on discovered materials
   - Handles pattern-based task generation
   - Manages task dependencies and priorities

3. **AnalyzerBridge** - Existing analyzer integration
   - Bridges new workflow with existing analyzers
   - Handles parameter mapping and result processing
   - Manages temporary files and cleanup

4. **EnhancedOrchestrator** - Advanced workflow orchestration
   - Parallel task execution
   - LLM-guided strategy selection
   - Performance monitoring and optimization

5. **AnalysisDashboard** - Real-time monitoring
   - Live progress visualization
   - Performance metrics
   - Finding and material tracking

### Data Flow

```
Puzzle File → WorkflowState → TaskFactory → Task Queue
                    ↓
            AnalyzerBridge → Existing Analyzers → Results
                    ↓
            Findings & Materials → Enhanced Orchestrator
                    ↓
            Dashboard Display → Solution Discovery
```

## 🔌 Integration with Existing Analyzers

The system automatically integrates with your existing analyzers:

- **text_analyzer** - Text pattern analysis
- **binary_analyzer** - Binary data analysis
- **image_analyzer** - Image and steganography analysis
- **crypto_analyzer** - Cryptographic analysis
- **cipher_analyzer** - Classical cipher analysis
- **encoding_analyzer** - Encoding detection and decoding
- **blockchain_analyzer** - Blockchain address analysis
- **vision_analyzer** - AI vision analysis
- **web_analyzer** - Web research capabilities
- **code_analyzer** - Dynamic code generation

## 📊 Dashboard Features

The real-time dashboard provides:

- **Progress Tracking**: Overall and phase-specific progress
- **Active Tasks**: Currently running and queued tasks
- **Material Discovery**: Types and counts of discovered materials
- **Recent Findings**: Latest analysis results with confidence scores
- **Performance Metrics**: Task completion rates and timing

## 🎯 LLM Integration

When enabled, the LLM agent provides:

- **Strategy Selection**: Intelligent analyzer selection
- **Task Prioritization**: Dynamic priority adjustment
- **Cross-Reference Analysis**: Finding correlation
- **Solution Validation**: Candidate verification

## 💾 Output and Results

The enhanced system generates:

- **Comprehensive Results**: JSON and markdown reports
- **Dashboard Export**: Real-time data snapshots
- **Workflow State**: Complete analysis state
- **Performance Stats**: Detailed timing and success metrics
- **Solution Candidates**: Ranked potential solutions

## 🔧 Configuration Files

### Environment Variables
```bash
# LLM API Keys
ANTHROPIC_API_KEY=your_anthropic_key
OPENAI_API_KEY=your_openai_key

# Other services
ETHERSCAN_API_KEY=your_etherscan_key
```

### Custom Configuration
You can customize the system by modifying:

- **TaskFactory.file_type_analyzers** - Analyzer mappings
- **TaskFactory.pattern_tasks** - Pattern-based task generation
- **AnalyzerBridge.analyzer_config** - Analyzer-specific settings
- **EnhancedOrchestrator.llm_review_interval** - LLM review frequency

## 🐛 Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   pip install -r requirements_enhanced.txt
   ```

2. **LLM Agent Failures**
   - Check API keys in environment variables
   - Use `--require-llm` flag for debugging
   - Try without LLM first: remove `--llm-provider`

3. **Dashboard Not Updating**
   - Ensure `--live-dashboard` flag is used
   - Check terminal size (dashboard needs sufficient space)
   - Try `--dashboard-refresh` with longer interval

4. **No Tasks Generated**
   - Check puzzle file exists and is readable
   - Verify file extension is recognized
   - Use `--verbose` flag for debugging

5. **Legacy Compatibility**
   - Use `--legacy` flag to run old system
   - Check `main_legacy.py` exists

### Debug Mode
```bash
python main.py puzzle.txt --debug --verbose
```

This enables:
- Detailed logging to `enhanced_crypto_hunter.log`
- Step-by-step task execution details
- Performance timing information
- Error stack traces

## 🔄 Migration from Old System

### Gradual Migration
1. Keep old system as fallback: `python main.py --legacy`
2. Test enhanced system on known puzzles
3. Compare results between systems
4. Gradually migrate to enhanced system

### Key Differences
- **Task-based**: Analysis broken into discrete tasks
- **Parallel**: Multiple analyzers run simultaneously
- **Adaptive**: System adapts based on discoveries
- **Interactive**: Real-time monitoring and control

## 📈 Performance Optimization

### Tuning Parameters
- **max_workers**: Increase for faster analysis (CPU dependent)
- **max_iterations**: Increase for thorough analysis
- **timeout_minutes**: Adjust based on puzzle complexity

### Resource Management
- Monitor memory usage with complex puzzles
- Use `--create-archive` for result storage optimization
- Consider disk space for large binary extractions

## 🆘 Support

### Getting Help
1. Check logs: `enhanced_crypto_hunter.log`
2. Use verbose mode: `--verbose --debug`
3. Try legacy mode: `--legacy`
4. Verify installation: `python integrate_enhanced_system.py --verify-only`

### Reporting Issues
Include:
- Puzzle file (if shareable)
- Command line used
- Log file contents
- System specifications

## 🎉 Success!

Once integrated, you'll have:
- ✅ Intelligent task orchestration
- ✅ Real-time analysis dashboard
- ✅ Parallel analyzer execution
- ✅ LLM-guided strategy selection
- ✅ Comprehensive result generation
- ✅ Interactive puzzle solving

The enhanced system is designed to be more efficient, intelligent, and user-friendly than the original linear approach while maintaining full compatibility with your existing analyzers.
