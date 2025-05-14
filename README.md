# Crypto Hunter

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

<p align="center">
  <img src="docs/logo.png" alt="Crypto Hunter Logo" width="300" />
</p>

Crypto Hunter is an AI-powered cryptographic puzzle solver designed to analyze and break various encryption, encoding, and steganography challenges. Built with modern AI technologies including LangChain and LLMs, this tool can tackle a wide range of cryptographic puzzles automatically or assist you in interactive solving sessions.

## 🌟 Features

- **AI-Powered Analysis**: Leverages modern language models to guide the analysis process and interpret results
- **Modular Analyzer Framework**: Easily extensible with new analyzers for different types of cryptographic challenges
- **Comprehensive Puzzle Coverage**:
  - Classic Ciphers (Caesar, Vigenère, Substitution, Atbash, Rail Fence)
  - Modern Cryptography (XOR, AES, RSA)
  - Steganography (LSB in images, metadata analysis)
  - Binary Analysis (file signatures, hidden data)
  - Blockchain Data (Ethereum addresses, smart contracts)
  - Encodings (Base64, Hex, ASCII85, Binary, URL, Morse code)
- **Interactive Mode**: Step-by-step guidance for solving complex puzzles
- **Rich Visualization**: Detailed insights and transformations displayed in a user-friendly format
- **Extensible Architecture**: Easy to add new analyzers and capabilities

## 🔧 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/crypto-hunter.git
cd crypto-hunter
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables for API access (optional, for AI capabilities):
```bash
# For Anthropic Claude
export ANTHROPIC_API_KEY="your_api_key_here"

# For OpenAI
export OPENAI_API_KEY="your_api_key_here"

# For Ethereum blockchain analysis
export ETHERSCAN_API_KEY="your_api_key_here"
```

## 🚀 Quick Start

### Analyzing a Puzzle File

```bash
# Basic usage
python main.py --puzzle-file path/to/your/puzzle.txt

# With increased verbosity
python main.py --puzzle-file path/to/your/puzzle.txt --verbose

# Limit analysis iterations
python main.py --puzzle-file path/to/your/puzzle.txt --iterations 5

# Specify which analyzer to use
python main.py --puzzle-file path/to/your/puzzle.txt --analyzer text_analyzer
```

### Browsing and Selecting Puzzles

```bash
# Browse available puzzles
python main.py --browse-puzzles

# Browse puzzles and use clues if available
python main.py --browse-puzzles --use-clues

# Specify a custom puzzle directory
python main.py --browse-puzzles --puzzle-dir path/to/puzzles
```

When browsing puzzles, Crypto Hunter will:
- Show available puzzle categories
- List puzzles within each category
- Indicate which puzzles have clues available
- Allow you to select a puzzle to analyze
- Ask if you want to use available clues

## 📋 Available Analyzers

| Analyzer | Description | Best For |
|----------|-------------|----------|
| `text_analyzer` | Analyzes text patterns and encodings | Text-based puzzles, substitution ciphers |
| `binary_analyzer` | Analyzes binary files and data | File analysis, hidden data extraction |
| `image_analyzer` | Analyzes images for steganography | Image steganography, metadata analysis |
| `blockchain_analyzer` | Analyzes blockchain addresses and data | Ethereum/Bitcoin puzzles, smart contracts |
| `cipher_analyzer` | Detects and solves various ciphers | Caesar, Vigenère, substitution ciphers |
| `encoding_analyzer` | Detects and decodes encodings | Base64, Hex, ASCII85, URL encoding |

## 🔍 Example Use Cases

### Solving a Caesar Cipher

```bash
python main.py --puzzle-file examples/ciphers/caesar.txt
```

Output:
```
Analysis Results

Puzzle Information
┌────────────┬────────────────────────────────┐
│ Property   │ Value                          │
├────────────┼────────────────────────────────┤
│ File       │ examples/ciphers/caesar.txt    │
│ Type       │ txt                            │
│ Size       │ 152 bytes                      │
│ Status     │ solved                         │
│ Solution   │ the quick brown fox jumps...   │
└────────────┴────────────────────────────────┘

Analysis Insights
┌────────────┬────────────────┬──────────────────────────────────────────┐
│ Time       │ Analyzer       │ Insight                                  │
├────────────┼────────────────┼──────────────────────────────────────────┤
│ 14:25:32   │ cipher_analyzer│ Text appears to be a Caesar cipher...    │
└────────────┴────────────────┴──────────────────────────────────────────┘
```

### Detecting Steganography in Images

```bash
python main.py --puzzle-file examples/steganography/hidden_message.png
```

Output:
```
Analysis Results

Puzzle Information
┌────────────┬────────────────────────────────────────┐
│ Property   │ Value                                  │
├────────────┼────────────────────────────────────────┤
│ File       │ examples/steganography/hidden_message.png │
│ Type       │ png                                    │
│ Size       │ 45281 bytes                            │
│ Status     │ solved                                 │
│ Solution   │ the secret password is "hunter2"       │
└────────────┴────────────────────────────────────────┘

Analysis Insights
┌────────────┬────────────────┬──────────────────────────────────────────┐
│ Time       │ Analyzer       │ Insight                                  │
├────────────┼────────────────┼──────────────────────────────────────────┤
│ 14:26:17   │ image_analyzer │ Detected LSB steganography...            │
└────────────┴────────────────┴──────────────────────────────────────────┘
```

## 🛠️ Advanced Usage

### Using the API

You can use Crypto Hunter as a library in your own projects:

```python
from core.state import State
from core.agent import CryptoAgent

# Initialize the state with a puzzle file
state = State(puzzle_file="path/to/puzzle.txt")

# Create a crypto agent
agent = CryptoAgent(provider="anthropic")  # or "openai"

# Run analysis
final_state = agent.analyze(state, max_iterations=5)

# Get the solution
if final_state.solution:
    print(f"Solution found: {final_state.solution}")
else:
    print("No solution found")
```

### Custom Analyzers

You can create your own analyzer by adding a new module under the `analyzers` directory:

```python
# analyzers/my_custom_analyzer.py
from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility

@register_analyzer("my_custom_analyzer")
@analyzer_compatibility(requires_text=True)
def analyze_custom(state: State) -> State:
    """
    Custom analyzer for specialized puzzles.
    """
    if not state.puzzle_text:
        return state
    
    # Your analysis logic here
    text = state.puzzle_text
    
    # Add insights
    state.add_insight(
        "Found something interesting!",
        analyzer="my_custom_analyzer"
    )
    
    # Add transformations
    state.add_transformation(
        name="my_transformation",
        description="Applied my custom transformation",
        input_data=text,
        output_data="transformed text",
        analyzer="my_custom_analyzer"
    )
    
    return state
```

Then register it in `analyzers/__init__.py`.

## 🧩 Supported Puzzle Types

- **Classic Cryptography**
  - Substitution ciphers (Caesar, ROT13, Atbash)
  - Transposition ciphers (Rail Fence, Columnar)
  - Historical ciphers (Vigenère, etc.)

- **Modern Cryptography**
  - XOR encryption
  - Hash-based puzzles
  - Cryptographic protocol puzzles

- **Steganography**
  - Image-based steganography (LSB)
  - Metadata analysis
  - Text-based hidden data

- **Encodings**
  - Base64, Base32, Hex encodings
  - URL encoding
  - Binary encoding
  - Morse code

- **Blockchain/Cryptocurrency**
  - Ethereum address puzzles
  - Transaction data analysis
  - Smart contract puzzles

- **Binary Analysis**
  - File format analysis
  - Hidden data extraction
  - Entropy analysis

## 📚 Documentation

For detailed documentation, see the following:

- [API Reference](docs/api/README.md)
- [Analyzer Documentation](docs/analyzers/README.md)
- [Architecture Overview](docs/architecture.md)
- [Contributing Guide](CONTRIBUTING.md)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- [LangChain](https://github.com/hwchase17/langchain) for LLM integration capabilities
- [Rich](https://github.com/Textualize/rich) for beautiful terminal output
- [Pillow](https://github.com/python-pillow/Pillow) for image analysis
- [Cryptography](https://github.com/pyca/cryptography) for cryptographic operations
- [Web3.py](https://github.com/ethereum/web3.py) for blockchain interactions
