#!/usr/bin/env python3
"""
Test the complete Crypto Puzzle Hunter system
"""

import sys
import os


# Test all agent imports
def test_agent_imports():
    print("🧪 Testing agent imports...")

    try:
        from agents.agent import CryptoAgent
        print("✅ CryptoAgent imported successfully")
    except Exception as e:
        print(f"❌ CryptoAgent failed: {e}")

    try:
        from agents.code_agent import CodeAgent
        print("✅ CodeAgent imported successfully")
    except Exception as e:
        print(f"❌ CodeAgent failed: {e}")

    try:
        from agents.vision_agent import VisionAgent
        print("✅ VisionAgent imported successfully")
    except Exception as e:
        print(f"❌ VisionAgent failed: {e}")

    try:
        from agents.fileheader_agent import FileHeaderAgent
        print("✅ FileHeaderAgent imported successfully")
    except Exception as e:
        print(f"❌ FileHeaderAgent failed: {e}")

    try:
        from agents.text_extractor_agent import TextExtractorAgent
        print("✅ TextExtractorAgent imported successfully")
    except Exception as e:
        print(f"❌ TextExtractorAgent failed: {e}")

    try:
        from agents.private_key_constructor_agent import PrivateKeyConstructorAgent
        print("✅ PrivateKeyConstructorAgent imported successfully")
    except Exception as e:
        print(f"❌ PrivateKeyConstructorAgent failed: {e}")

    try:
        from agents.wallet_verifier_agent import WalletVerifierAgent
        print("✅ WalletVerifierAgent imported successfully")
    except Exception as e:
        print(f"❌ WalletVerifierAgent failed: {e}")

    try:
        from agents.vm_agent import VMAgent
        print("✅ VMAgent imported successfully")
    except Exception as e:
        print(f"❌ VMAgent failed: {e}")

    try:
        from agents.pgp_agent import PGPAgent
        print("✅ PGPAgent imported successfully")
    except Exception as e:
        print(f"❌ PGPAgent failed: {e}")

    try:
        from agents.web_agent import WebAgent
        print("✅ WebAgent imported successfully")
    except Exception as e:
        print(f"❌ WebAgent failed: {e}")


def test_orchestrator():
    print("\n🧪 Testing EnhancedOrchestrator...")

    try:
        from orchestrator import EnhancedOrchestrator
        print("✅ EnhancedOrchestrator imported successfully")

        # Try to initialize
        orch = EnhancedOrchestrator(verbose=True)
        print("✅ EnhancedOrchestrator initialized successfully")

        return True

    except Exception as e:
        print(f"❌ EnhancedOrchestrator failed: {e}")
        return False


def test_state_management():
    print("\n🧪 Testing WorkflowState...")

    try:
        from state_management import WorkflowState, MaterialType
        print("✅ WorkflowState imported successfully")

        state = WorkflowState()
        print("✅ WorkflowState initialized successfully")

        # Test basic functionality
        state.add_insight("Test insight", "test_agent")
        print("✅ Can add insights")

        return True

    except Exception as e:
        print(f"❌ WorkflowState failed: {e}")
        return False


def test_task_factory():
    print("\n🧪 Testing TaskFactory...")

    try:
        from task_factory import TaskFactory
        from state_management import WorkflowState
        print("✅ TaskFactory imported successfully")

        state = WorkflowState()
        factory = TaskFactory(state)
        print("✅ TaskFactory initialized successfully")

        return True

    except Exception as e:
        print(f"❌ TaskFactory failed: {e}")
        return False


def run_sample_analysis():
    print("\n🧪 Running sample analysis...")

    try:
        from state_management import WorkflowState
        from agents.fileheader_agent import FileHeaderAgent
        from agents.code_agent import CodeAgent

        # Create test data
        state = WorkflowState()

        # Test FileHeaderAgent
        agent = FileHeaderAgent(verbose=True)
        print("✅ FileHeaderAgent created")

        # Test CodeAgent
        code_agent = CodeAgent(verbose=True)
        print("✅ CodeAgent created")

        # Test code analysis
        test_code = """
import hashlib
import base64

def generate_key():
    secret = "hello world"
    key = hashlib.sha256(secret.encode()).hexdigest()
    return key

private_key = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
print(f"Key: {private_key}")
"""

        result = code_agent.analyze_code_snippet(test_code, "python")
        print(f"✅ Code analysis result: {result}")

        return True

    except Exception as e:
        print(f"❌ Sample analysis failed: {e}")
        return False


def main():
    print("🚀 Crypto Puzzle Hunter System Test")
    print("=" * 50)

    all_passed = True

    # Test imports
    test_agent_imports()

    # Test core components
    if not test_state_management():
        all_passed = False

    if not test_task_factory():
        all_passed = False

    if not test_orchestrator():
        all_passed = False

    # Test sample analysis
    if not run_sample_analysis():
        all_passed = False

    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 All tests passed! System is ready.")
    else:
        print("⚠️  Some tests failed. Check the output above.")

    print("\n📋 To run the full system:")
    print("python main.py puzzles/arweave11/image.png --provider openai --verbose")


if __name__ == "__main__":
    main()