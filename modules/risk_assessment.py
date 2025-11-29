"""
risk_assessment.py

Industry-grade Reverse Engineering Risk Assessment
Cross-platform: PE / ELF / Mach-O
Features:
  - Symbol analysis (descriptive, exported, imported)
  - Control flow complexity heuristics (cyclomatic)
  - Packing / obfuscation detection (entropy, stripped, known packers, overlay)
  - Strings analysis (sensitive info, URLs, emails, keys)
  - Hardening absence integration (from hardening report)
  - Weighted risk scoring and interpretation
Dependencies:
  - lief (pip install lief)
  - capstone (pip install capstone)
"""

import os
import json
import math
import re
import lief
from capstone import *
from typing import List, Dict, Any
import string
from datetime import datetime

# -------------------------
# Helper Functions
# -------------------------
def entropy(data: bytes) -> float:
    """Compute Shannon entropy of bytes."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    e = 0.0
    for f in freq:
        if f:
            p = f / len(data)
            e -= p * math.log2(p)
    return e

def is_descriptive(name: str) -> bool:
    """Heuristic: function/variable name is descriptive if readable and longer than 3 chars"""
    if len(name) < 4:
        return False
    allowed = string.ascii_letters + string.digits + "_"
    return all(c in allowed for c in name) and not name.startswith(("sub_", "func_"))

def list_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extract printable ASCII strings from bytes."""
    result = []
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                result.append(current.decode("ascii"))
            current = bytearray()
    if len(current) >= min_len:
        result.append(current.decode("ascii"))
    return result

def classify_strings(strings: List[str]) -> Dict[str, List[str]]:
    """Classify strings into URLs, emails, keys, and generic"""
    urls = [s for s in strings if s.startswith(("http://","https://"))]
    emails = [s for s in strings if re.match(r"[^@]+@[^@]+\.[^@]+", s)]
    keys = [s for s in strings if re.search(r"(key|token|secret|password|license)", s, re.I)]
    others = [s for s in strings if s not in urls + emails + keys]
    return {"urls": urls, "emails": emails, "keys": keys, "others": others}

def detect_packing(binary) -> Dict[str, Any]:
    """Detect high-entropy sections, stripped symbols, known packer signatures, overlay data"""
    high_entropy_sections = []
    stripped = False
    known_packers = ["UPX", "MEW", "ASPack", "MPRESS", "PECompact"]
    sections = getattr(binary, "sections", [])
    
    for s in sections:
        try:
            ent = entropy(bytes(s.content))
            if ent > 7.0 and len(s.content) > 64:  # slightly lower threshold for small sections
                high_entropy_sections.append({"name": s.name, "entropy": ent})
        except Exception:
            continue

    symbols = getattr(binary, "symbols", None)
    stripped = symbols is None or len(symbols) == 0

    packer_flags = [s.name for s in sections if any(k.upper() in s.name.upper() for k in known_packers)]

    # Detect overlay for PE files (extra data appended to the file)
    overlay_size = 0
    if hasattr(binary, "overlay") and binary.overlay:
        overlay_size = len(binary.overlay)

    return {
        "high_entropy_sections": high_entropy_sections,
        "num_high_entropy": len(high_entropy_sections),
        "stripped": stripped,
        "known_packer_sections": packer_flags,
        "overlay_bytes": overlay_size,
        "risk_score": min(1.0, len(high_entropy_sections)/3 + (1.0 if stripped else 0))
    }

def estimate_cyclomatic(md, code_bytes: bytes) -> float:
    """Estimate cyclomatic complexity from instruction stream"""
    total = 0
    branches = 0
    for ins in md.disasm(code_bytes, 0x0):
        total += 1
        if ins.mnemonic.startswith(('j','call','ret')):
            branches += 1
    if total == 0:
        return 1.0  # max risk if no code
    return 1.0 - (branches / total)

# -------------------------
# Main Class
# -------------------------
class ReverseEngineeringRisk:
    def __init__(self, path: str, hardening_report: Dict[str, Any] = None):
        if not os.path.exists(path):
            raise FileNotFoundError(f"Binary not found: {path}")
        self.path = os.path.abspath(path)
        self.binary = lief.parse(path)
        if self.binary is None:
            raise ValueError("Failed to parse binary")
        self.format = type(self.binary).__name__
        self.hardening_report = hardening_report or {}
        self.report = {}
        self.md = self._get_capstone_disassembler()

    def _get_capstone_disassembler(self):
        """Assume x86/x64 for now"""
        try:
            return Cs(CS_ARCH_X86, CS_MODE_64)
        except Exception:
            return None

    # -------------------------
    # Symbol Analysis
    # -------------------------
    def analyze_symbols(self):
        symbols = []
        try:
            if self.format == "ELF.Binary":
                symbols = [s.name for s in self.binary.symbols if s.name]
            elif self.format == "PE.Binary":
                # Symbols, exports, imports
                symbols = [s.name for s in getattr(self.binary, "symbols", []) if s.name]
                if not symbols:
                    symbols = [e for e in getattr(self.binary, "exported_functions", []) if e]
                imports = [i.name for i in getattr(self.binary, "imports", []) if i.name]
                symbols += imports
            elif self.format == "MachO.Binary":
                symbols = [s.name for s in getattr(self.binary, "symbols", []) if s.name]
        except Exception:
            symbols = []

        descriptive = [s for s in symbols if is_descriptive(s)]
        self.report['symbols'] = {
            "total_symbols": len(symbols),
            "descriptive_symbols": len(descriptive),
            "examples": descriptive[:10],
            "risk_score": min(1.0, len(descriptive)/max(len(symbols),1))
        }

    # -------------------------
    # Control Flow Analysis
    # -------------------------
    def analyze_control_flow(self):
        code_sections = []
        try:
            if self.format == "ELF.Binary":
                code_sections = [s for s in self.binary.sections if "text" in s.name.lower() or "code" in s.name.lower()]
            elif self.format == "PE.Binary":
                code_sections = [s for s in self.binary.sections if s.characteristics & 0x20]
            elif self.format == "MachO.Binary":
                code_sections = [s for s in self.binary.segments if s.name.lower().startswith("__text")]
            code_sections = [s for s in code_sections if len(s.content) > 0]
        except Exception:
            code_sections = []

        total_score = 0
        total_count = 0
        for sec in code_sections:
            try:
                data = bytes(sec.content)
                score = estimate_cyclomatic(self.md, data)
                total_score += score
                total_count += 1
            except Exception:
                continue
        self.report['control_flow'] = {
            "sections_analyzed": total_count,
            "avg_risk_score": round(total_score/total_count,2) if total_count else 1.0,
            "risk_score": round(total_score/total_count,2) if total_count else 1.0
        }

    # -------------------------
    # Packing / Obfuscation
    # -------------------------
    def analyze_packing(self):
        self.report['packing'] = detect_packing(self.binary)

    # -------------------------
    # Strings Analysis
    # -------------------------
    def analyze_strings(self):
        sections = getattr(self.binary, "sections", [])
        all_strings = []
        for s in sections:
            try:
                all_strings.extend(list_strings(bytes(s.content)))
            except Exception:
                continue
        classified = classify_strings(all_strings)
        self.report['strings'] = {
            "num_strings": len(all_strings),
            "examples": all_strings[:10],
            "classified": {k: v[:5] for k,v in classified.items()},
            "risk_score": min(1.0, len(all_strings)/50)
        }

    # -------------------------
    # Hardening Absence
    # -------------------------
    def analyze_hardening_absence(self):
        absent_features = []
        risk_score = 0.0
        weights = {"ASLR":0.2,"DEP/NX":0.15,"CFG":0.25,"SafeSEH":0.2,"StackCookie":0.1,"DigitalSignature":0.1}
        for check, val in self.hardening_report.items():
            if check in ("_meta","error"): 
                continue
            if not val.get("passed", True):
                absent_features.append(check)
                risk_score += weights.get(check,0.1)
        self.report['hardening_absence'] = {
            "missing_features": absent_features,
            "risk_score": min(1.0,risk_score)
        }

    # -------------------------
    # Overall Risk
    # -------------------------
    def compute_overall_risk(self):
        scores = []
        weights = {"symbols":0.15,"control_flow":0.25,"packing":0.25,"strings":0.15,"hardening_absence":0.2}
        for k,w in weights.items():
            if k in self.report:
                scores.append(self.report[k].get("risk_score",0)*w)
        total = sum(scores)
        self.report['overall_risk'] = {
            "score": round(min(1.0,total),2),
            "interpretation": ("Low" if total<=0.4 else "Medium" if total<=0.7 else "High")
        }

    # -------------------------
    # Run all analyses
    # -------------------------
    def run_all(self):
        self.analyze_symbols()
        self.analyze_control_flow()
        self.analyze_packing()
        self.analyze_strings()
        if self.hardening_report:
            self.analyze_hardening_absence()
        self.compute_overall_risk()
        self.report["_meta"] = {
            "path": self.path,
            "format": self.format,
            "file_size_bytes": os.path.getsize(self.path),
            "timestamp": datetime.now().isoformat()
        }
        return self.report

    def to_json(self, indent=2):
        return json.dumps(self.run_all(), indent=indent)

# -------------------------
# CLI Interface
# -------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Reverse Engineering Risk Assessment")
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("--hardening", help="JSON hardening report", default=None)
    parser.add_argument("--json", help="Output JSON report file", default=None)
    args = parser.parse_args()

    hardening_report = {}
    if args.hardening and os.path.exists(args.hardening):
        with open(args.hardening, "r") as f:
            hardening_report = json.load(f)

    rar = ReverseEngineeringRisk(args.binary, hardening_report)
    report = rar.run_all()

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report,f,indent=2)
        print(f"Wrote JSON report to {args.json}")
    else:
        print(json.dumps(report, indent=2))
