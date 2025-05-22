# Contributing to Crypto Hunter

First off, thank you for considering contributing to Crypto Hunter! It's people like you that make this tool such a great resource for cryptography enthusiasts and puzzle solvers.

## Code of Conduct

By participating in this project, you are expected to uphold our Code of Conduct, which is to be respectful, inclusive, and collaborative.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for Crypto Hunter. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

**Before Submitting A Bug Report:**

* Check the [Issues](https://github.com/yourusername/crypto-hunter/issues) to see if the problem has already been reported.
* Make sure your issue is reproducible and provide clear steps to recreate it.

**How Do I Submit A Good Bug Report?**

Bugs are tracked as GitHub issues. Create an issue and provide the following information:

* Use a clear and descriptive title.
* Describe the exact steps to reproduce the problem.
* Provide specific examples to demonstrate the steps.
* Describe the behavior you observed after following the steps and why this is a problem.
* Explain which behavior you expected to see instead and why.
* Include screenshots or animated GIFs if possible.
* If the problem is with a specific puzzle file, attach it or share a link to it.
* Include details about your environment (OS, Python version, etc.).

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for Crypto Hunter, including completely new features or minor improvements to existing functionality.

**Before Submitting An Enhancement Suggestion:**

* Check the [Issues](https://github.com/yourusername/crypto-hunter/issues) to see if the enhancement has already been suggested.
* Make sure your idea aligns with the project's goals and scope.

**How Do I Submit A Good Enhancement Suggestion?**

Enhancement suggestions are tracked as GitHub issues. Create an issue and provide the following information:

* Use a clear and descriptive title.
* Provide a detailed description of the suggested enhancement.
* Explain why this enhancement would be useful to Crypto Hunter users.
* List any alternative solutions or features you've considered.
* Include examples of how this enhancement would work, if applicable.

### Pull Requests

* Fill in the required template.
* Follow the Python style guide (PEP 8).
* Document new code based on our documentation standards.
* End all files with a newline.
* Update the README.md with details of changes to the interface, if applicable.
* The PR should work for Python 3.8 and higher.
* Test your changes thoroughly.

## Development Setup

1. Fork and clone the repo
```bash
git clone https://github.com/yourusername/crypto-hunter.git
cd crypto-hunter
```

2. Create a virtual environment and install dependencies
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If there are separate dev requirements
```

3. Install pre-commit hooks
```bash
pre-commit install
```

## Development Process

1. Create your feature branch (`git checkout -b feature/amazing-feature`)
2. Make your changes
3. Run tests to ensure they pass
4. Commit your changes (`git commit -m 'Add some amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## Coding Standards

* Follow PEP 8 for Python code.
* Use meaningful variable, function, and class names.
* Document your functions and classes using docstrings.
* Keep functions small and focused on a single task.
* Write tests for new functionality.

## Adding a New Analyzer

1. Create a new file in the `analyzers/` directory (e.g., `analyzers/my_analyzer.py`).
2. Implement your analyzer using the register_analyzer decorator:

```python
from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

@register_analyzer("my_analyzer")
@analyzer_compatibility(requires_text=True)  # Or appropriate compatibility
def analyze_my_puzzle(state: State) -> State:
    """
    My custom analyzer for specific puzzle types.
    
    Args:
        state: Current puzzle state
        
    Returns:
        Updated state after analysis
    """
    if not state.puzzle_text:
        return state
        
    # Your analysis logic here
    
    # Add insights
    state.add_insight(
        "Discovered something interesting",
        analyzer="my_analyzer"
    )
    
    # Add transformations if needed
    state.add_transformation(
        name="my_transformation",
        description="Applied my custom transformation",
        input_data=state.puzzle_text,
        output_data="Transformed text",
        analyzer="my_analyzer"
    )
    
    return state
```

3. Register your analyzer in `analyzers/__init__.py`:

```python
import analyzers.my_analyzer
```

## Attribution

This Contributing Guide is adapted from the open-source contribution guides of several projects.
