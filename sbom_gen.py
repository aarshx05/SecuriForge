#!/usr/bin/env python3
"""
sbom_gen.py

Software Bill of Materials (SBOM) Generator
Cross-platform: ELF / PE / Mach-O

Features:
  - Compiler options / build info
  - Linked libraries (dependencies)
  - Embedded resources (strings, config-like)
  - Metadata (hashes, size, format)
  - Output formats:
      * SPDX JSON
      * CycloneDX JSON

Dependencies:
  - lief (pip install lief)
"""

import os
import sys
import json
import hashlib
import lief
import re
from datetime import datetime
from typing import Dict, Any, List


# -------------------------
# Helpers
# -------------------------
def sha256sum(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode(errors="ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode(errors="ignore"))
    return out


def guess_embedded_resources(binary) -> List[str]:
    """Look for config-like strings in binary sections"""
    resources = []
    for s in getattr(binary, "sections", []):
        try:
            strings = extract_strings(bytes(s.content))
            for st in strings:
                if re.search(r"\.conf|\.ini|\.json|\.xml|BEGIN|PRIVATE KEY", st, re.I):
                    resources.append(st)
        except Exception:
            continue
    return list(set(resources))[:10]  # limit examples


def get_compiler_info(binary) -> str:
    """Extract compiler/build info if available"""
    if isinstance(binary, lief.ELF.Binary):
        comments = [s for s in binary.sections if s.name == ".comment"]
        if comments:
            try:
                return bytes(comments[0].content).decode(errors="ignore").strip()
            except Exception:
                return "unknown"
    elif isinstance(binary, lief.PE.Binary):
        return binary.rich_header.key if binary.has_rich_header else "unknown"
    elif isinstance(binary, lief.MachO.Binary):
        return binary.compiler if hasattr(binary, "compiler") else "unknown"
    return "unknown"


def build_metadata(path: str, binary) -> Dict[str, Any]:
    return {
        "path": os.path.abspath(path),
        "format": type(binary).__name__,
        "file_size": os.path.getsize(path),
        "sha256": sha256sum(path),
        "timestamp": datetime.utcnow().isoformat()
    }


# -------------------------
# Class Wrapper
# -------------------------
class SBOMGenerator:
    def __init__(self, binary_path: str):
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        self.binary_path = binary_path
        self.binary = lief.parse(binary_path)
        if not self.binary:
            raise ValueError(f"Failed to parse binary: {binary_path}")
        self.metadata = build_metadata(binary_path, self.binary)
        self.compiler = get_compiler_info(self.binary)
        self.libs = list(self.binary.libraries) if hasattr(self.binary, "libraries") else []
        self.resources = guess_embedded_resources(self.binary)

    def generate_spdx(self) -> Dict[str, Any]:
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": os.path.basename(self.metadata["path"]),
            "documentNamespace": f"http://spdx.org/spdxdocs/{self.metadata['sha256']}",
            "creationInfo": {
                "created": self.metadata["timestamp"],
                "creators": ["Tool: sbom_gen.py"]
            },
            "packages": [
                {
                    "name": os.path.basename(self.metadata["path"]),
                    "SPDXID": "SPDXRef-Package",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "originator": f"Compiler: {self.compiler}",
                    "externalRefs": [
                        {"referenceCategory": "SECURITY", "referenceType": "sha256",
                         "referenceLocator": self.metadata["sha256"]}
                    ],
                    "dependencies": self.libs,
                    "resources": self.resources
                }
            ]
        }

    def generate_cyclonedx(self) -> Dict[str, Any]:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": self.metadata["timestamp"],
                "tools": [{"vendor": "custom", "name": "sbom_gen.py"}],
                "component": {
                    "type": "application",
                    "name": os.path.basename(self.metadata["path"]),
                    "version": "unknown",
                    "hashes": [{"alg": "SHA-256", "content": self.metadata["sha256"]}],
                    "properties": [
                        {"name": "file_size", "value": str(self.metadata["file_size"])},
                        {"name": "format", "value": self.metadata["format"]},
                        {"name": "compiler", "value": self.compiler}
                    ]
                }
            },
            "components": [
                {"type": "library", "name": lib, "version": "unknown"} for lib in self.libs
            ],
            "services": [],
            "resources": self.resources
        }

    def generate(self, fmt: str = "spdx-json") -> Dict[str, Any]:
        if fmt == "spdx-json":
            return self.generate_spdx()
        elif fmt == "cyclonedx":
            return self.generate_cyclonedx()
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    def run_all(self) -> Dict[str, Any]:
        """Return combined SBOMs + metadata"""
        return {
            "_meta": self.metadata,
            "spdx": self.generate_spdx(),
            "cyclonedx": self.generate_cyclonedx()
        }


# -------------------------
# CLI Entrypoint
# -------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="SBOM Generator (SPDX / CycloneDX)")
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("--format", choices=["spdx-json", "cyclonedx"], default="spdx-json")
    parser.add_argument("--output", help="Output file (JSON)", default=None)
    args = parser.parse_args()

    try:
        generator = SBOMGenerator(args.binary)
        if args.format == "spdx-json":
            sbom = generator.generate_spdx()
        elif args.format == "cyclonedx":
            sbom = generator.generate_cyclonedx()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(sbom, f, indent=2)
        print(f"[+] SBOM written to {args.output}")
    else:
        print(json.dumps(sbom, indent=2))


if __name__ == "__main__":
    main()
