# core/fileheader_agent.py
"""
FileHeaderAgent: extract hidden files from stego images using binwalk
or, if that’s unavailable, via manual magic‐header carving.
"""
import os
import re
import subprocess
import logging

from enhanced_state_management import Material, MaterialType

class FileHeaderAgent:
    def __init__(self, tools_dir: str = "extracted", verbose: bool = False):
        """
        tools_dir: where to write carved files
        verbose:   emit debug logs
        """
        self.tools_dir = tools_dir
        os.makedirs(self.tools_dir, exist_ok=True)
        self.verbose   = verbose
        self.logger    = logging.getLogger(__name__)

        # common file‐signature map
        self.signatures = {
            b"\x50\x4B\x03\x04": ".zip",
            b"%PDF-":           ".pdf",
            b"\xFF\xD8\xFF":    ".jpg",
            b"\x89PNG\r\n\x1a\n":".png"
        }

    def run(self, state):
        """
        Scan every image in state.materials, carve out hidden files,
        add them back into state as new materials, and log each extraction.
        """
        for mat in list(state.materials.values()):
            if mat.material_type.lower() != MaterialType.IMAGE:
                continue

            img_path = mat.file_path
            base      = os.path.splitext(os.path.basename(img_path))[0]
            workdir   = os.path.join(self.tools_dir, base)
            os.makedirs(workdir, exist_ok=True)

            # 1) Try binwalk
            try:
                if self.verbose:
                    self.logger.info(f"FileHeaderAgent: running binwalk on {img_path}")
                subprocess.run(
                    ["binwalk", "-e", "--directory", workdir, img_path],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                # register everything binwalk dropped
                for root, _, files in os.walk(workdir):
                    for fn in files:
                        fp = os.path.join(root, fn)
                        new_mat = Material(
                            id=f"{mat.id}-{fn}",
                            file_path=fp,
                            material_type=MaterialType.BINARY
                        )
                        state.add_material(new_mat)
                        state.add_insight(f"Binwalk extracted {fn} from {mat.id}",
                                          "fileheader_agent")
                continue

            except Exception as e:
                if self.verbose:
                    self.logger.warning(f"Binwalk failed on {mat.id}: {e}")

            # 2) Fallback: manual signature carving
            data = open(img_path, "rb").read()
            for sig, ext in self.signatures.items():
                for m in re.finditer(re.escape(sig), data):
                    start = m.start()
                    # carve until end‐of‐file
                    chunk = data[start:]
                    fn    = f"{base}_{start:06d}{ext}"
                    fp    = os.path.join(workdir, fn)
                    with open(fp, "wb") as out:
                        out.write(chunk)
                    new_mat = Material(
                        id=f"{mat.id}-{fn}",
                        file_path=fp,
                        material_type=MaterialType.BINARY
                    )
                    state.add_material(new_mat)
                    state.add_insight(f"Carved {fn} (sig {sig[:4].hex()}) from {mat.id}",
                                      "fileheader_agent")
        return state
