#!/usr/bin/env python3
"""
Test script for the enhanced image analyzer and state management
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def test_enhanced_state():
    """Test the enhanced state management"""
    print("Testing enhanced State management...")

    try:
        from core.state import State

        # Test basic state creation
        state = State()
        print("✓ State creation successful")

        # Test insight addition
        state.add_insight("Test insight", "test_analyzer")
        print(f"✓ Added insight: {len(state.insights)} insights")

        # Test transformation addition
        state.add_transformation(
            name="Test Transformation",
            description="Testing transformation system",
            input_data="test input",
            output_data="test output",
            analyzer="test_analyzer"
        )
        print(f"✓ Added transformation: {len(state.transformations)} transformations")

        # Test summary generation
        summary = state.get_summary()
        print(f"✓ Generated summary: {len(summary)} characters")

        return True

    except Exception as e:
        print(f"✗ State test failed: {e}")
        return False


def test_enhanced_image_analyzer():
    """Test the enhanced image analyzer"""
    print("\nTesting enhanced Image Analyzer...")

    try:
        from analyzers.image_analyzer import analyze_image
        from core.state import State

        print("✓ Image analyzer import successful")

        # Test with a simple PNG (create a minimal test image)
        test_png = create_test_png()

        state = State()
        state.set_binary_data(test_png)

        # Run the analyzer
        result_state = analyze_image(state)

        print(
            f"✓ Analysis completed: {len(result_state.insights)} insights, {len(result_state.transformations)} transformations")

        return True

    except Exception as e:
        print(f"✗ Image analyzer test failed: {e}")
        return False


def create_test_png():
    """Create a minimal test PNG for testing"""
    # Minimal PNG header + IEND chunk
    png_data = (
        b'\x89PNG\r\n\x1a\n'  # PNG signature
        b'\x00\x00\x00\rIHDR'  # IHDR chunk
        b'\x00\x00\x00\x01'  # Width: 1
        b'\x00\x00\x00\x01'  # Height: 1
        b'\x08\x02\x00\x00\x00'  # Bit depth: 8, Color type: 2 (RGB), Compression: 0, Filter: 0, Interlace: 0
        b'\x90wS\xde'  # CRC
        b'\x00\x00\x00\x0cIDAT'  # IDAT chunk
        b'x\x9cc```\x00\x00\x00\x04\x00\x01'  # Compressed data
        b'\n\x0c\x08\x00'  # CRC
        b'\x00\x00\x00\x00IEND'  # IEND chunk
        b'\xaeB`\x82'  # CRC
    )
    return png_data


def test_analyzer_registration():
    """Test that analyzers are properly registered"""
    print("\nTesting analyzer registration...")

    try:
        from analyzers.base import get_all_analyzers

        analyzers = get_all_analyzers()
        image_analyzers = [name for name in analyzers.keys() if 'image' in name.lower()]

        print(f"✓ Found {len(analyzers)} total analyzers")
        print(f"✓ Found {len(image_analyzers)} image-related analyzers: {image_analyzers}")

        return len(image_analyzers) > 0

    except Exception as e:
        print(f"✗ Analyzer registration test failed: {e}")
        return False


def test_dependencies():
    """Test that required dependencies are available"""
    print("\nTesting dependencies...")

    dependencies = {
        'PIL': 'pillow',
        'numpy': 'numpy',
        'cv2': 'opencv-python',
        'scipy': 'scipy',
        'bs4': 'beautifulsoup4'
    }

    available = {}
    for module, package in dependencies.items():
        try:
            __import__(module)
            available[module] = True
            print(f"✓ {module} ({package}) available")
        except ImportError:
            available[module] = False
            print(f"✗ {module} ({package}) not available")

    return all(available.values())


def main():
    """Run all tests"""
    print("=== Enhanced Crypto Hunter Implementation Test ===\n")

    tests = [
        ("Dependencies", test_dependencies),
        ("Enhanced State", test_enhanced_state),
        ("Analyzer Registration", test_analyzer_registration),
        ("Enhanced Image Analyzer", test_enhanced_image_analyzer),
    ]

    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"✗ {test_name} test crashed: {e}")
            results[test_name] = False

    print(f"\n=== Test Results ===")
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{test_name}: {status}")

    all_passed = all(results.values())
    print(f"\nOverall: {'✓ ALL TESTS PASSED' if all_passed else '✗ SOME TESTS FAILED'}")

    if not all_passed:
        print("\nNext steps:")
        if not results.get("Dependencies", True):
            print("- Install missing dependencies: pip install pillow numpy opencv-python scipy beautifulsoup4")
        if not results.get("Enhanced State", True):
            print("- Check core/state.py implementation")
        if not results.get("Enhanced Image Analyzer", True):
            print("- Check analyzers/image_analyzer.py implementation")

    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
