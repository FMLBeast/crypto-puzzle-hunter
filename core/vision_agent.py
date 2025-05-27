"""
VisionAgent: OCR, QR-code scanning, simple image findings.
"""
import logging
from PIL import Image
import pytesseract

logger = logging.getLogger(__name__)
try:
    from pyzbar.pyzbar import decode as qr_decode
except ImportError:
    qr_decode = lambda img: []

class VisionAgent:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logger  = logging.getLogger(__name__)

    def run(self, state):
        for mat in state.materials.values():
            if mat.material_type.lower() != "image":
                continue
            try:
                img = Image.open(mat.file_path)
                # OCR
                text = pytesseract.image_to_string(img).strip()
                if text:
                    f = {
                        "source":      "vision_agent",
                        "type":        "ocr",
                        "material_id": mat.id,
                        "text":        text
                    }
                    state.add_finding(f)
                    if self.verbose:
                        self.logger.info(f"OCR from {mat.id}: {text[:50]!r}")
                # QR
                for code in qr_decode(img):
                    data = code.data.decode(errors="ignore")
                    f = {
                        "source":      "vision_agent",
                        "type":        "qr",
                        "material_id": mat.id,
                        "data":        data
                    }
                    state.add_finding(f)
                    if self.verbose:
                        self.logger.info(f"QR from {mat.id}: {data!r}")
            except Exception as e:
                self.logger.warning(f"VisionAgent failed on {mat.id}: {e}")
        return state
