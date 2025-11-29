#!/usr/bin/env python3
"""
mal_check.py - Robust Malware Injection & Tampering Detection (industry-grade)

Improvements over the original:
 - Fixed duplicated yara_rules_path assignment
 - UTF-16 string extraction (optional)
 - Corrected PE WX bitmasks (IMAGE_SCN_MEM_EXECUTE / WRITE)
 - Better overlay & declared-size detection (uses section file offsets)
 - Deterministic section overlap sorting
 - Normalized overall risk based on actual weights
 - More robust YARA compilation (dir/file handling + externals injection)
 - Additional string classifiers (IPs, registry keys, crypto terms)
 - Defensive LIEF access with fallbacks
 - CLI flags: --fail-on-yara, --utf16
"""

from __future__ import annotations
import os
import sys
import math
import json
import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
from datetime import datetime

try:
    import lief
except Exception as e:
    raise ImportError("lief is required: pip install lief. Import error: " + str(e))

try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

LOG = logging.getLogger("mal_check")
LOG.addHandler(logging.NullHandler())

# ---------------------------
# Defaults & heuristics (weights)
# ---------------------------
DEFAULT_HIGH_ENTROPY = 7.5
DEFAULT_LOW_ENTROPY = 1.0

# Weights (used for normalized overall scoring)
WEIGHTS = {
    "entropy": 0.30,
    "unexpected_sections": 0.15,
    "imports": 0.25,
    "size_overlay": 0.10,
    "wx_sections": 0.20,
    "strings": 0.10,
    "section_overlaps": 0.15,
    "yara": 0.60,  # handled specially (outside regular sum)
}

# Known-good whitelists (can be expanded)
KNOWN_SECTIONS = {
    "ELF": {".text", ".data", ".bss", ".rodata", ".init", ".fini", ".plt", ".got", ".dynamic", ".dynsym", ".dynstr", ".rela.plt", ".rela.dyn", ".comment"},
    "PE": {".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc", ".edata", ".idata", ".tls", ".CRT", ".bss"},
    "MACHO": {"__TEXT", "__DATA", "__LINKEDIT", "__TEXT_EXEC", "__DATA_CONST"},
}

# Suspicious import heuristics
SUSPICIOUS_PE_APIS = {
    "kernel32.dll": {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "LoadLibraryA", "GetProcAddress", "VirtualProtect"},
    "ntdll.dll": {"NtCreateThreadEx", "NtWriteVirtualMemory"},
    "advapi32.dll": {"RegSetValueExA", "RegCreateKeyExA"},
    "wininet.dll": {"InternetOpenA", "InternetConnectA"},
    "ws2_32.dll": {"socket", "connect", "send", "recv"},
}

SUSPICIOUS_ELF_FUNCS = {"ptrace", "mprotect", "execve", "prctl", "clone", "dlopen", "open", "chmod"}
SUSPICIOUS_MACHO_FUNCS = {"dlopen", "dlsym", "mach_vm_allocate", "mach_vm_write"}

# suspicious string keywords (tokens, keys, secrets)
SUSPICIOUS_STRING_PATTERNS = [
    re.compile(r"(api[_-]?key|secret|token|password|passwd|pwd|private_key|ssh-rsa)", re.I),
    re.compile(r"https?://[^\s/$.?#].[^\s]*", re.I),
    re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"),  # base64-looking long strings (heuristic)
    re.compile(r"[A-Fa-f0-9]{32,}"),  # long hex (possible keys)
    re.compile(r"[\w\.-]+@[\w\.-]+\.\w+"),  # emails
]

IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
REGISTRY_RE = re.compile(r"(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU)\\[^\s\\]+", re.I)
CRYPTO_RE = re.compile(r"\b(AES|DES|RC4|RSA|SHA1|SHA256|HMAC)\b", re.I)

# ---------------------------
# Utility Functions
# ---------------------------
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    e = 0.0
    length = len(data)
    for f in freq:
        if f:
            p = f / length
            e -= p * math.log2(p)
    return e

def extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    result = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                try:
                    result.append(cur.decode("ascii", errors="ignore"))
                except Exception:
                    pass
            cur = bytearray()
    if len(cur) >= min_len:
        try:
            result.append(cur.decode("ascii", errors="ignore"))
        except Exception:
            pass
    return result

def extract_utf16le_strings(data: bytes, min_len: int = 4) -> List[str]:
    # Search for ASCII-range sequences inside UTF-16LE-decoded text
    try:
        txt = data.decode("utf-16le", errors="ignore")
        return re.findall(r"[ -~]{%d,}" % min_len, txt)
    except Exception:
        return []

def classify_strings(strings: List[str]) -> Dict[str, List[str]]:
    urls = []
    emails = []
    keys = []
    ips = []
    registry = []
    crypto = []
    others = []
    for s in strings:
        if re.match(r"https?://", s, re.I):
            urls.append(s)
        elif re.match(r"[\w\.-]+@[\w\.-]+\.\w+", s):
            emails.append(s)
        elif any(p.search(s) for p in SUSPICIOUS_STRING_PATTERNS):
            keys.append(s)
        elif IPV4_RE.search(s):
            ips.append(s)
        elif REGISTRY_RE.search(s):
            registry.append(s)
        elif CRYPTO_RE.search(s):
            crypto.append(s)
        else:
            others.append(s)
    return {"urls": urls, "emails": emails, "keys": keys, "ips": ips, "registry": registry, "crypto": crypto, "others": others}

def safe_bytes_of_section(s) -> bytes:
    """Robust conversion for LIEF section content to bytes."""
    try:
        return bytes(s.content)
    except Exception:
        try:
            # some LIEF objects may provide .content as array('B') or similar
            return s.content.tobytes()
        except Exception:
            return b""

def _sum_defined_section_sizes(secs) -> int:
    total = 0
    for s in secs:
        total += getattr(s, "size", 0) or 0
    return total

# ---------------------------
# Main Checker class
# ---------------------------
class MalwareChecker:
    def __init__(
        self,
        path: str,
        yara_rules: Optional[str] = None,
        high_entropy_threshold: float = DEFAULT_HIGH_ENTROPY,
        low_entropy_threshold: float = DEFAULT_LOW_ENTROPY,
        verbose: bool = False,
        extract_utf16: bool = True,
    ):
        if verbose:
            h = logging.StreamHandler(sys.stdout)
            h.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
            LOG.addHandler(h)
            LOG.setLevel(logging.DEBUG)

        if not os.path.exists(path):
            raise FileNotFoundError(f"Binary not found: {path}")
        self.path = os.path.abspath(path)

        # Parse safely
        try:
            self.binary = lief.parse(self.path)
        except Exception as e:
            raise ValueError(f"Failed to parse binary (unsupported/corrupted): {e}")

        if self.binary is None:
            raise ValueError("Failed to parse binary (unsupported or corrupted).")

        # Normalize format string
        self.format = (self.binary.format.name if getattr(self.binary, "format", None) else type(self.binary).__name__).upper()
        # canonical keys: ELF / PE / MACHO
        if self.format.startswith("ELF"):
            self.format = "ELF"
        elif self.format.startswith("PE"):
            self.format = "PE"
        elif "MACHO" in self.format:
            self.format = "MACHO"

        self.results: Dict[str, Any] = {}
        self._raw_findings = defaultdict(list)
        self.high_entropy_threshold = float(high_entropy_threshold)
        self.low_entropy_threshold = float(low_entropy_threshold)
        self.yara_rules_path = yara_rules
        self.yara_compiled = None
        self.extract_utf16 = bool(extract_utf16)

        # Prepare YARA if requested
        if yara_rules and YARA_AVAILABLE:
            self._prepare_yara(yara_rules)

    # ---------------------------
    # YARA helpers
    # ---------------------------
    def _prepare_yara(self, yara_rules_path: str) -> None:
        try:
            externals = {
                "filepath": self.path,
                "filename": os.path.basename(self.path),
                "extension": os.path.splitext(self.path)[1].lower(),
                "filesize": os.path.getsize(self.path),
                "filetype": self.format.lower(),
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            with open(self.path, "rb") as fh:
                data = fh.read()
                import hashlib
                externals["sha256"] = hashlib.sha256(data).hexdigest()
                externals["md5"] = hashlib.md5(data).hexdigest()

            sources = {}
            if os.path.isdir(yara_rules_path):
                for root, _, files in os.walk(yara_rules_path):
                    for fn in files:
                        if fn.lower().endswith((".yar", ".yara")):
                            full = os.path.join(root, fn)
                            try:
                                key = os.path.relpath(full, yara_rules_path).replace(os.sep, "_")
                                sources[key] = open(full, "r", encoding="utf-8", errors="ignore").read()
                            except Exception as e:
                                LOG.warning("Failed to read YARA file %s: %s", full, e)
            else:
                # single file
                try:
                    sources["single"] = open(yara_rules_path, "r", encoding="utf-8", errors="ignore").read()
                except Exception as e:
                    LOG.warning("Failed to read YARA file %s: %s", yara_rules_path, e)
                    sources = {}

            if not sources:
                LOG.warning("No YARA rules loaded from %s", yara_rules_path)
                return

            # Compile with fallback for undefined externals
            while True:
                try:
                    self.yara_compiled = yara.compile(sources=sources, externals=externals) if len(sources) > 1 else yara.compile(source=next(iter(sources.values())), externals=externals)
                    LOG.debug("YARA rules compiled")
                    break
                except yara.SyntaxError as e:
                    # try to detect undefined externals and inject empty defaults
                    m = re.search(r'undefined identifier \"(.*?)\"', str(e))
                    if m:
                        ident = m.group(1)
                        LOG.warning("Injecting missing external '%s' = '' for YARA compilation", ident)
                        externals[ident] = ""
                    else:
                        LOG.warning("YARA compile failed: %s", e)
                        break
                except Exception as e:
                    LOG.warning("YARA compile exception: %s", e)
                    break
        except Exception as e:
            LOG.warning("Failed to prepare YARA rules: %s", e)

    # ---------------------------
    # Section / layout checks
    # ---------------------------
    def _sections(self) -> List[Any]:
        return list(getattr(self.binary, "sections", []) or [])

    def entropy_per_section(self) -> Dict[str, Any]:
        findings = []
        for s in self._sections():
            data = safe_bytes_of_section(s)
            ent = shannon_entropy(data)
            note = ""
            score = 0.0
            if ent >= self.high_entropy_threshold and len(data) > 64:
                note = "high_entropy"
                score = 1.0
            elif ent <= self.low_entropy_threshold and len(data) > 0:
                note = "low_entropy"
                score = 0.6
            item = {"section": getattr(s, "name", "<noname>"), "entropy": round(ent, 3), "size": len(data), "note": note}
            findings.append(item)
            if score > 0:
                self._raw_findings["high_entropy_sections"].append(item)
        self.results["entropy"] = {"per_section": findings, "high_entropy_threshold": self.high_entropy_threshold}
        high_count = len(self._raw_findings.get("high_entropy_sections", []))
        entropy_score = min(1.0, high_count / 3.0)  # heuristic
        self.results["entropy"]["score"] = round(entropy_score * WEIGHTS["entropy"], 3)
        LOG.debug("Entropy score: %s", self.results["entropy"]["score"])
        return self.results["entropy"]

    def detect_wx_sections(self) -> Dict[str, Any]:
        wx = []
        for s in self._sections():
            is_w = False
            is_x = False
            # Try LIEF attributes first
            try:
                is_w = bool(getattr(s, "writable", False))
                is_x = bool(getattr(s, "executable", False))
            except Exception:
                is_w = is_x = False
            # Fallback for PE: use IMAGE_SCN_MEM_EXECUTE / WRITE bits
            if self.format == "PE" and hasattr(s, "characteristics"):
                try:
                    # IMAGE_SCN_MEM_EXECUTE = 0x20000000; IMAGE_SCN_MEM_WRITE = 0x80000000
                    is_x = bool(s.characteristics & 0x20000000)
                    is_w = bool(s.characteristics & 0x80000000)
                except Exception:
                    pass
            # Fallback for ELF segments: check segment flags (if section maps to a segment)
            if self.format == "ELF":
                try:
                    # Some ELF sections expose .flags or the segment mapping; try both
                    if hasattr(s, "flags"):
                        # flag bit for executable: SHF_EXECINSTR = 0x4; writable: SHF_WRITE = 0x1
                        is_x = bool(getattr(s, "flags", 0) & 0x4)
                        is_w = bool(getattr(s, "flags", 0) & 0x1)
                except Exception:
                    pass
            if is_w and is_x:
                wx.append({"section": getattr(s, "name", "<noname>"), "size": getattr(s, "size", None)})
        self.results["wx_sections"] = {"items": wx}
        wx_score = 1.0 if wx else 0.0
        self.results["wx_sections"]["score"] = round(wx_score * WEIGHTS["wx_sections"], 3)
        if wx:
            LOG.debug("Found executable+writeable sections: %s", wx)
        return self.results["wx_sections"]

    def detect_section_overlaps(self) -> Dict[str, Any]:
        buckets = []
        for s in self._sections():
            # Prefer file_offset/offset for overlay/overlap checks
            start = getattr(s, "offset", None) or getattr(s, "file_offset", None) or getattr(s, "virtual_address", None)
            size = getattr(s, "size", None) or getattr(s, "raw_size", None)
            if start is None or size is None:
                continue
            end = start + size
            buckets.append((int(start), int(end), getattr(s, "name", "<noname>")))
        overlaps = []
        buckets.sort(key=lambda x: x[0])
        for i in range(len(buckets)):
            a_start, a_end, a_name = buckets[i]
            for j in range(i + 1, len(buckets)):
                b_start, b_end, b_name = buckets[j]
                if b_start < a_end:
                    overlaps.append({"a": a_name, "b": b_name, "a_range": [a_start, a_end], "b_range": [b_start, b_end]})
        self.results["section_overlaps"] = {"items": overlaps, "count": len(overlaps)}
        overlap_score = min(1.0, len(overlaps) * 0.5)
        self.results["section_overlaps"]["score"] = round(overlap_score * WEIGHTS["section_overlaps"], 3)
        if overlaps:
            LOG.debug("Section overlaps found: %s", overlaps)
        return self.results["section_overlaps"]

    def unexpected_sections(self) -> Dict[str, Any]:
        expected = KNOWN_SECTIONS.get(self.format, set())
        unknown = []
        for s in self._sections():
            nm = getattr(s, "name", "")
            if not nm:
                continue
            # Normalize names sometimes lacking leading dot
            check_name = nm if nm.startswith(".") or nm.startswith("__") else ("." + nm if self.format == "ELF" else nm)
            if check_name not in expected:
                unknown.append({"section": nm, "size": getattr(s, "size", None)})
        self.results["unexpected_sections"] = {"items": unknown, "count": len(unknown)}
        sec_score = min(1.0, len(unknown) / 5.0)
        self.results["unexpected_sections"]["score"] = round(sec_score * WEIGHTS["unexpected_sections"], 3)
        if unknown:
            LOG.debug("Unexpected sections: %s", unknown)
        return self.results["unexpected_sections"]

    # ---------------------------
    # Import / API anomalies
    # ---------------------------
    def import_anomalies(self) -> Dict[str, Any]:
        suspicious = []
        total_imports = 0
        try:
            if self.format == "PE":
                for lib in getattr(self.binary, "imports", []) or []:
                    lib_name = (getattr(lib, "name", "") or "").lower()
                    for entry in getattr(lib, "entries", []) or []:
                        total_imports += 1
                        fname = getattr(entry, "name", None) or getattr(entry, "ordinal", None)
                        if not fname:
                            continue
                        # compare case-insensitive
                        if lib_name in SUSPICIOUS_PE_APIS and str(fname) in SUSPICIOUS_PE_APIS[lib_name]:
                            suspicious.append({"dll": lib.name, "func": fname})
            elif self.format == "ELF":
                # imported functions are available via imported_functions or dynamic_entries/DT_NEEDED
                for sym in getattr(self.binary, "imported_functions", []) or []:
                    total_imports += 1
                    if sym in SUSPICIOUS_ELF_FUNCS:
                        suspicious.append({"func": sym})
            else:  # MACHO & others
                for sym in getattr(self.binary, "imported_functions", []) or []:
                    total_imports += 1
                    if sym in SUSPICIOUS_MACHO_FUNCS:
                        suspicious.append({"func": sym})
        except Exception as e:
            LOG.warning("Import analysis failed: %s", e)

        self.results["imports"] = {"suspicious": suspicious, "total_imports": total_imports}
        import_score = min(1.0, len(suspicious) / 3.0)
        self.results["imports"]["score"] = round(import_score * WEIGHTS["imports"], 3)
        if suspicious:
            LOG.debug("Suspicious imports: %s", suspicious)
        return self.results["imports"]

    # ---------------------------
    # Overlay / size anomalies
    # ---------------------------
    def size_and_overlay(self) -> Dict[str, Any]:
        file_size = os.path.getsize(self.path)
        declared_size = 0
        # compute declared_size as sum of raw sizes and also compute last end offset (for overlay)
        last_end = 0
        for s in self._sections():
            # prefer file offset + size if available
            size = getattr(s, "size", None) or getattr(s, "raw_size", None) or 0
            declared_size += size
            start = getattr(s, "offset", None) or getattr(s, "file_offset", None) or 0
            try:
                start = int(start)
            except Exception:
                start = 0
            end = start + (int(size) if size else 0)
            if end > last_end:
                last_end = end

        overlay = 0
        if file_size > last_end:
            overlay = file_size - last_end

        size_anomaly = {}
        # if file is much larger than declared sections (heuristic), flag it
        if declared_size > 0 and file_size > declared_size * 1.5:
            size_anomaly["note"] = "file much larger than declared sections"
            size_anomaly["file_size"] = file_size
            size_anomaly["declared_sections_size"] = declared_size

        if overlay > 0:
            size_anomaly["overlay_size"] = overlay

        self.results["size_overlay"] = {"details": size_anomaly, "file_size": file_size, "declared_sections_size": declared_size}
        s_score = 0.0
        if size_anomaly:
            s_score = 1.0
        elif overlay > 0:
            s_score = 0.7
        self.results["size_overlay"]["score"] = round(s_score * WEIGHTS["size_overlay"], 3)
        if size_anomaly or overlay > 0:
            LOG.debug("Size/overlay anomaly: %s", self.results["size_overlay"])
        return self.results["size_overlay"]

    # ---------------------------
    # Strings & secrets
    # ---------------------------
    def analyze_strings(self) -> Dict[str, Any]:
        all_strings: List[str] = []
        for s in self._sections():
            data = safe_bytes_of_section(s)
            if not data:
                continue
            all_strings.extend(extract_ascii_strings(data, min_len=4))
            if self.extract_utf16:
                all_strings.extend(extract_utf16le_strings(data, min_len=4))

        # dedupe while preserving order (small scale)
        seen = set()
        deduped = []
        for st in all_strings:
            if st in seen:
                continue
            seen.add(st)
            deduped.append(st)

        classified = classify_strings(deduped)
        suspicious_keys = classified.get("keys", []) + classified.get("crypto", [])
        counts = {"total_strings": len(deduped), "urls": len(classified.get("urls", [])), "emails": len(classified.get("emails", [])), "keys": len(suspicious_keys)}
        self.results["strings"] = {"counts": counts, "examples": {k: (v[:10] if isinstance(v, list) else v) for k, v in classified.items()}}
        str_score = min(1.0, counts["keys"] / 5.0)
        self.results["strings"]["score"] = round(str_score * WEIGHTS["strings"], 3)
        if suspicious_keys:
            LOG.debug("Suspicious strings/keys found: %s", suspicious_keys[:5])
        return self.results["strings"]

    # ---------------------------
    # YARA scanning
    # ---------------------------
    def run_yara(self) -> Dict[str, Any]:
        if not self.yara_compiled:
            self.results["yara"] = {"available": False, "matches": []}
            return self.results["yara"]

        matches = []
        try:
            # Prefer matching by file path (faster / uses file features); fallback to matching in-memory
            try:
                m = self.yara_compiled.match(filepath=self.path)
            except TypeError:
                # some yara-python builds expect different signature
                try:
                    m = self.yara_compiled.match(self.path)
                except Exception:
                    with open(self.path, "rb") as fh:
                        data = fh.read()
                    m = self.yara_compiled.match(data=data)
            except yara.Error:
                with open(self.path, "rb") as fh:
                    data = fh.read()
                m = self.yara_compiled.match(data=data)

            for entry in m:
                matches.append({"rule": getattr(entry, "rule", getattr(entry, "identifier", str(entry))), "tags": getattr(entry, "tags", [])})
        except Exception as e:
            LOG.warning("YARA scan failed: %s", e)
            self.results["yara"] = {"available": True, "error": str(e), "matches": []}
            return self.results["yara"]

        self.results["yara"] = {"available": True, "matches": matches}
        yara_score = 1.0 if matches else 0.0
        self.results["yara"]["score"] = round(yara_score * WEIGHTS["yara"], 3)
        if matches:
            LOG.info("YARA matches: %s", matches)
        return self.results["yara"]

    # ---------------------------
    # Aggregation & reporting
    # ---------------------------
    def compute_overall_risk(self) -> Dict[str, Any]:
        scores = {
            "entropy": self.results.get("entropy", {}).get("score", 0.0),
            "unexpected_sections": self.results.get("unexpected_sections", {}).get("score", 0.0),
            "imports": self.results.get("imports", {}).get("score", 0.0),
            "size_overlay": self.results.get("size_overlay", {}).get("score", 0.0),
            "wx_sections": self.results.get("wx_sections", {}).get("score", 0.0),
            "strings": self.results.get("strings", {}).get("score", 0.0),
            "section_overlaps": self.results.get("section_overlaps", {}).get("score", 0.0),
            "yara": self.results.get("yara", {}).get("score", 0.0),
        }

        # Compute normalization denominator as sum of used weights
        denom = WEIGHTS["entropy"] + WEIGHTS["unexpected_sections"] + WEIGHTS["imports"] + WEIGHTS["size_overlay"] + WEIGHTS["wx_sections"] + WEIGHTS["strings"] + WEIGHTS["section_overlaps"] + WEIGHTS["yara"]
        # sum actual (already multiplied in sub-scores), so normalize by denom
        total = sum(scores.values())
        overall = min(1.0, (total / denom) if denom > 0 else total)
        interpretation = "Low" if overall <= 0.4 else "Medium" if overall <= 0.7 else "High"
        self.results["overall_risk"] = {"score": round(overall, 3), "interpretation": interpretation, "components": scores}
        return self.results["overall_risk"]

    def meta(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "format": self.format,
            "file_size_bytes": os.path.getsize(self.path),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def run_all(self) -> Dict[str, Any]:
        LOG.info("Running mal_check on %s (%s)", self.path, self.format)
        self.entropy_per_section()
        self.detect_wx_sections()
        self.detect_section_overlaps()
        self.unexpected_sections()
        self.import_anomalies()
        self.size_and_overlay()
        self.analyze_strings()
        self.run_yara()
        self.compute_overall_risk()
        result = {"_meta": self.meta(), "findings": self.results}
        return result

def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="mal_check - Malware/Tampering Detection (improved)")
    parser.add_argument("--input-binary", "-i", required=True, help="Path to binary (ELF/PE/Mach-O)")
    parser.add_argument("--output-json", "-o", help="Path to write JSON report (default stdout)")
    parser.add_argument("--yara-rules", "-y", help="Path to YARA rules file or directory (optional)")
    parser.add_argument("--high-entropy", type=float, default=DEFAULT_HIGH_ENTROPY, help="High entropy threshold (default 7.5)")
    parser.add_argument("--low-entropy", type=float, default=DEFAULT_LOW_ENTROPY, help="Low entropy threshold (default 1.0)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--fail-on-yara", action="store_true", help="Exit non-zero if any YARA match is found")
    parser.add_argument("--no-utf16", dest="utf16", action="store_false", help="Disable UTF-16 string extraction")
    args = parser.parse_args(argv)

    checker = MalwareChecker(
        args.input_binary,
        yara_rules=args.yara_rules,
        high_entropy_threshold=args.high_entropy,
        low_entropy_threshold=args.low_entropy,
        verbose=args.verbose,
        extract_utf16=args.utf16,
    )

    try:
        report = checker.run_all()
    except Exception as e:
        LOG.error("Check failed: %s", e)
        return 2

    out_json = json.dumps(report, indent=2)
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as fh:
            fh.write(out_json)
        if args.verbose:
            LOG.info("Wrote JSON report to %s", args.output_json)
    else:
        print(out_json)

    # Decide exit code by overall score, optionally fail on YARA hits
    yara_matches = report["findings"].get("yara", {}).get("matches", [])
    if args.fail_on_yara and yara_matches:
        LOG.info("Fail-on-yara enabled and matches were found -> exiting with code 2")
        return 2

    overall_score = report["findings"]["overall_risk"]["score"]
    if overall_score <= 0.4:
        return 0   # Low
    elif overall_score <= 0.7:
        return 1   # Medium
    else:
        return 2   # High

if __name__ == "__main__":
    sys.exit(main())
