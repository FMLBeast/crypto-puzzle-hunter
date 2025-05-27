# core/text_extractor_agent.py
"""
TextExtractorAgent
Extracts plain-text and printable strings from all materials,
adding each snippet as a state finding.
"""
import re
import logging
from enhanced_state_management import MaterialType

logger = logging.getLogger(__name__)

class TextExtractorAgent:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def run(self, state):
        """
        For each material:
        - If text, read entire content.
        - If binary, carve ASCII runs of length ≥20.
        Add each as a finding.
        """
        for mat in state.materials.values():
            path = mat.file_path
            try:
                if mat.material_type == MaterialType.TEXT:
                    text = open(path, encoding='utf8', errors='ignore').read()
                    if text.strip():
                        f = {
                            "source":      "text_extractor_agent",
                            "type":        "full_text",
                            "material_id": mat.id,
                            "text":        text
                        }
                        state.add_finding(f)
                        if self.verbose:
                            logger.info(f"[TextExtractor] full_text from {mat.id}")
                else:
                    data = open(path, 'rb').read()
                    # find printable ASCII of length ≥20
                    for match in re.finditer(br'[\x20-\x7E]{20,}', data):
                        s = match.group().decode('ascii', errors='ignore')
                        f = {
                            "source":      "text_extractor_agent",
                            "type":        "ascii_str",
                            "material_id": mat.id,
                            "text":        s
                        }
                        state.add_finding(f)
                    if self.verbose:
                        logger.info(f"[TextExtractor] scanned binary {mat.id}")
            except Exception as e:
                logger.warning(f"TextExtractorAgent failed on {mat.id}: {e}")
        return state
