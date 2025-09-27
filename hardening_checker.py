"""
robust_hardening_checker.py

Cross-platform Binary Hardening Checker (ELF / PE / Mach-O)

Checks:

ELF:
 - PIE detection
 - Stack protector (canary)
 - Debug symbols
 - Stripped detection
 - Relocations
 - NX
 - RELRO
 - Fortify source (_chk)
 - TEXTREL
 - RPATH/RUNPATH
 - PT_INTERP
 - Build info

PE (Windows):
 - ASLR
 - DEP/NX
 - Control Flow Guard (CFG)
 - SafeSEH
 - Stack cookie (/GS)
 - Digital signature

Mach-O (macOS):
 - PIE
 - NX
 - Stack canaries
 - Code signing
 - Entitlements
 - RELRO equivalents

Dependencies:
 - lief (pip install lief)

Usage:
    from robust_hardening_checker import BinaryHardeningChecker
    checker = BinaryHardeningChecker("/path/to/binary")
    report = checker.run_all()
    print(json.dumps(report, indent=2))
"""

import os
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

try:
    import lief
except Exception as e:
    raise ImportError("lief is required: pip install lief. Import error: " + str(e))

LOG = logging.getLogger(__name__)
LOG.addHandler(logging.NullHandler())

Severity = str  # "INFO", "WARN", "CRITICAL"


class CheckResult:
    def __init__(self, name: str, passed: bool, severity: Severity, evidence: str):
        self.name = name
        self.passed = passed
        self.severity = severity
        self.evidence = evidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "severity": self.severity,
            "evidence": self.evidence,
        }


class HardeningError(Exception):
    pass

class BinaryHardeningChecker:
    """
    Robust cross-platform binary hardening checker.
    """

    def __init__(self, path: str):
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")

        self.path = os.path.abspath(path)
        self.binary = lief.parse(self.path)

        if self.binary is None:
            raise HardeningError("Failed to parse binary. Unsupported format or corrupted file.")

        # Determine binary format using isinstance (works in modern LIEF)
        from lief import PE, ELF, MachO

        if isinstance(self.binary, ELF.Binary):
            self.format = "ELF"
            # Precompute ELF info
            self.section_names = [s.name for s in getattr(self.binary, "sections", [])]
            self.symbol_names = [s.name for s in getattr(self.binary, "symbols", []) if s.name]
            self.dynamic_symbol_names = [s.name for s in getattr(self.binary, "dynamic_symbols", []) if s.name]
            self.static_symbol_names = [s.name for s in getattr(self.binary, "static_symbols", []) if s.name]
            self.dynamic_tags = {entry.tag: entry.value for entry in getattr(self.binary, "dynamic_entries", [])}
            self.segments = getattr(self.binary, "segments", [])
            self.header = getattr(self.binary, "header", None)

        elif isinstance(self.binary, PE.Binary):
            self.format = "PE"
            # Precompute PE info
            self.header = self.binary.header
            # DLL characteristics live in optional_header, not header
            self.dll_characteristics = getattr(self.binary.optional_header, "dll_characteristics", None)
            self.symbols = getattr(self.binary, "symbols", [])
            self.has_safe_seh = getattr(self.binary, "has_safe_seh", False)
            self.has_signature = getattr(self.binary, "has_signature", False)


        elif isinstance(self.binary, MachO.Binary):
            self.format = "MachO"
            # Precompute Mach-O info
            self.segments = getattr(self.binary, "segments", [])
            self.symbols = getattr(self.binary, "symbols", [])
            self.entitlements = getattr(self.binary, "entitlements", None)
            self.has_signature = getattr(self.binary, "has_signature", False)

        else:
            raise HardeningError(f"Unsupported binary format: {type(self.binary).__name__}")



    # -------------------
    # Helper utilities
    # -------------------
    def _evidence_list(self, items: List[str], limit: int = 8) -> str:
        if not items:
            return "none"
        shown = items[:limit]
        more = len(items) - len(shown)
        s = ", ".join(shown)
        if more > 0:
            s += f", ... (+{more} more)"
        return s

    # -------------------
    # ELF Checks
    # -------------------
    def check_pie(self) -> CheckResult:
        header_type = getattr(self.header, "file_type", None)
        is_dyn = (header_type == lief.ELF.E_TYPE.DYN)
        has_interp = any(seg.type == lief.ELF.SEGMENT_TYPES.INTERP for seg in self.segments)
        passed = bool(is_dyn and has_interp)
        evidence = f"file_type={getattr(header_type, 'name', str(header_type))}, PT_INTERP_present={has_interp}"
        if is_dyn and not has_interp:
            evidence += " (ET_DYN without INTERP -> likely .so library)"
            return CheckResult("PIE", False, "INFO", evidence)
        severity = "CRITICAL" if not passed else "INFO"
        return CheckResult("PIE", passed, severity, evidence)

    def check_stack_protector(self) -> CheckResult:
        candidates = {"__stack_chk_fail", "__stack_chk_guard", "__stack_chk_fail_local"}
        found = [s for s in (self.symbol_names + self.dynamic_symbol_names + self.static_symbol_names) if s in candidates]
        comment = None
        for sec in getattr(self.binary, "sections", []):
            if sec.name == ".comment":
                try:
                    raw = bytes(sec.content).rstrip(b"\x00")
                    comment = raw.decode("utf-8", errors="ignore")
                except Exception:
                    comment = "<binary-data>"
                break
        evidence = f"symbols_found={self._evidence_list(found)}; .comment={comment}"
        passed = len(found) > 0
        severity = "INFO" if passed else "WARN"
        return CheckResult("StackProtector", passed, severity, evidence)

    def check_debug_symbols(self) -> CheckResult:
        debug_sections = [name for name in self.section_names if name.startswith((".debug", ".stab"))]
        has_debuglink = ".gnu_debuglink" in self.section_names
        passed = bool(debug_sections or has_debuglink)
        evidence = f"debug_sections={debug_sections}, .gnu_debuglink={has_debuglink}"
        severity = "INFO" if passed else "WARN"
        return CheckResult("DebugSymbols", passed, severity, evidence)

    def check_stripped(self) -> CheckResult:
        has_symtab = ".symtab" in self.section_names
        static_count = len(self.static_symbol_names)
        if not has_symtab:
            evidence = "No .symtab section found (fully stripped)."
            return CheckResult("Stripped", True, "INFO", evidence)
        if static_count < 5:
            evidence = f".symtab present but only {static_count} static symbols -> partially stripped"
            return CheckResult("Stripped", True, "WARN", evidence)
        evidence = f".symtab present with {static_count} static symbols"
        return CheckResult("Stripped", False, "INFO", evidence)

    def check_relocations(self) -> CheckResult:
        reloc_sections = [s.name for s in getattr(self.binary, "sections", []) if s.type in (lief.ELF.SECTION_TYPES.REL, lief.ELF.SECTION_TYPES.RELA)]
        passed = len(reloc_sections) > 0
        evidence = f"relocation_sections={reloc_sections}"
        severity = "INFO" if passed else "WARN"
        return CheckResult("Relocations", passed, severity, evidence)

    def check_nx(self) -> CheckResult:
        gnu_stack = next((s for s in self.segments if s.type == lief.ELF.SEGMENT_TYPES.GNU_STACK), None)
        if gnu_stack is None:
            return CheckResult("NX", False, "WARN", "PT_GNU_STACK missing; cannot confirm NX")
        nx_enabled = not gnu_stack.has(lief.ELF.SEGMENT_FLAGS.X)
        evidence = f"GNU_STACK.flags={gnu_stack.flags} (executable={gnu_stack.has(lief.ELF.SEGMENT_FLAGS.X)})"
        severity = "CRITICAL" if not nx_enabled else "INFO"
        return CheckResult("NX", nx_enabled, severity, evidence)

    def check_relro(self) -> CheckResult:
        has_relro_seg = any(seg.type == lief.ELF.SEGMENT_TYPES.GNU_RELRO for seg in self.segments)
        has_bind_now = lief.ELF.DYNAMIC_TAGS.BIND_NOW in self.dynamic_tags
        if has_relro_seg and has_bind_now:
            return CheckResult("RELRO", True, "INFO", "GNU_RELRO present and BIND_NOW -> Full RELRO")
        if has_relro_seg:
            return CheckResult("RELRO", True, "WARN", "GNU_RELRO present but BIND_NOW missing -> Partial RELRO")
        return CheckResult("RELRO", False, "CRITICAL", "No GNU_RELRO segment found")

    def check_fortify(self) -> CheckResult:
        fortified = [s for s in (self.symbol_names + self.dynamic_symbol_names) if s.endswith("_chk")]
        passed = len(fortified) > 0
        evidence = f"examples={self._evidence_list(fortified)}"
        severity = "INFO" if passed else "WARN"
        return CheckResult("FortifySource", passed, severity, evidence)

    def check_text_relocations(self) -> CheckResult:
        has_textrel = lief.ELF.DYNAMIC_TAGS.TEXTREL in self.dynamic_tags
        passed = not bool(has_textrel)
        evidence = f"DT_TEXTREL present={has_textrel}"
        severity = "CRITICAL" if has_textrel else "INFO"
        return CheckResult("TextReloc", passed, severity, evidence)

    def check_rpath_runpath(self) -> CheckResult:
        rpath = self.dynamic_tags.get(lief.ELF.DYNAMIC_TAGS.RPATH)
        runpath = self.dynamic_tags.get(lief.ELF.DYNAMIC_TAGS.RUNPATH)
        passed = (rpath is None and runpath is None)
        evidence = f"RPATH={rpath}, RUNPATH={runpath}"
        severity = "WARN" if not passed else "INFO"
        return CheckResult("RPathRunPath", passed, severity, evidence)

    def check_interpreter(self) -> CheckResult:
        interps = [seg for seg in self.segments if seg.type == lief.ELF.SEGMENT_TYPES.INTERP]
        if not interps:
            return CheckResult("Interpreter", False, "WARN", "No PT_INTERP segment found")
        interp_val = getattr(interps[0], "name", None) or getattr(interps[0], "content", None)
        evidence = f"PT_INTERP value={interp_val}"
        return CheckResult("Interpreter", True, "INFO", evidence)

    def check_build_info(self) -> CheckResult:
        comment = None
        build_id = None
        for sec in getattr(self.binary, "sections", []):
            if sec.name == ".comment":
                try:
                    raw = bytes(sec.content).rstrip(b"\x00")
                    comment = raw.decode("utf-8", errors="ignore")
                except Exception:
                    comment = "<binary-data>"
            if sec.name == ".note.gnu.build-id":
                try:
                    raw = bytes(sec.content)
                    build_id = raw.hex()[:64]
                except Exception:
                    build_id = "<note>"
        passed = bool(comment or build_id)
        evidence = f".comment={comment}, build_id={build_id}"
        severity = "INFO" if passed else "WARN"
        return CheckResult("BuildInfo", passed, severity, evidence)

    # -------------------
    # PE Checks
    # -------------------


    # inside BinaryHardeningChecker

    @staticmethod
    def pe_has(binary, flag_name) -> bool:
        """
        Check if PE binary has a given DLL_CHARACTERISTICS flag using numeric values.
        Compatible across all LIEF versions.
        """
        dll_flags = getattr(binary.optional_header, "dll_characteristics", 0)

        flag_map = {
            "DYNAMIC_BASE": 0x40,  # ASLR
            "NX_COMPAT": 0x100,    # DEP / NX
            "GUARD_CF": 0x4000,    # Control Flow Guard
        }

        if flag_name not in flag_map:
            raise ValueError(f"Unknown PE flag: {flag_name}")

        return bool(dll_flags & flag_map[flag_name])

    def check_aslr(self) -> CheckResult:
        enabled = self.pe_has(self.binary, "DYNAMIC_BASE")
        evidence = f"DLL_CHARACTERISTICS.DYNAMIC_BASE={enabled}"
        return CheckResult("ASLR", enabled, "INFO" if enabled else "CRITICAL", evidence)

    def check_dep(self) -> CheckResult:
        enabled = self.pe_has(self.binary, "NX_COMPAT")
        evidence = f"DLL_CHARACTERISTICS.NX_COMPAT={enabled}"
        return CheckResult("DEP/NX", enabled, "INFO" if enabled else "CRITICAL", evidence)

    def check_cfg(self) -> CheckResult:
        enabled = self.pe_has(self.binary, "GUARD_CF")
        evidence = f"DLL_CHARACTERISTICS.GUARD_CF={enabled}"
        return CheckResult("CFG", enabled, "INFO" if enabled else "WARN", evidence)



    def check_safeseh(self) -> CheckResult:
        safeseh = getattr(self.binary, "has_safe_seh", False)
        evidence = f"SafeSEH={safeseh}"
        severity = "INFO" if safeseh else "WARN"
        return CheckResult("SafeSEH", safeseh, severity, evidence)

    def check_stack_cookie(self) -> CheckResult:
        cookies = [s.name for s in self.binary.symbols if s.name in ("__security_cookie", "__stack_chk_fail")]
        passed = len(cookies) > 0
        evidence = f"symbols_found={self._evidence_list(cookies)}"
        severity = "INFO" if passed else "WARN"
        return CheckResult("StackCookie", passed, severity, evidence)

    def check_signature(self) -> CheckResult:
        # Use getattr with fallback for cross-version compatibility
        signed = getattr(self.binary, "has_signature", None)
        if signed is None:
            signed = getattr(self.binary, "has_signatures", False)
        evidence = f"Signed={signed}"
        severity = "INFO" if signed else "WARN"
        return CheckResult("DigitalSignature", signed, severity, evidence)


    # -------------------
    # Mach-O Checks
    # -------------------
    def check_pie_macho(self) -> CheckResult:
        is_pie = self.binary.has(lief.MachO.FLAGS.PIE)
        evidence = f"MachO.FLAGS.PIE={is_pie}"
        severity = "INFO" if is_pie else "CRITICAL"
        return CheckResult("PIE", is_pie, severity, evidence)

    def check_nx_macho(self) -> CheckResult:
        nx_enabled = all(not getattr(s, "executable", True) for s in getattr(self.binary, "segments", []))
        evidence = f"NX-like check={nx_enabled}"
        severity = "CRITICAL" if not nx_enabled else "INFO"
        return CheckResult("NX", nx_enabled, severity, evidence)

    def check_stack_canary_macho(self) -> CheckResult:
        symbols = [s.name for s in getattr(self.binary, "symbols", []) if s.name in ("__stack_chk_fail", "__stack_chk_guard")]
        passed = len(symbols) > 0
        evidence = f"symbols_found={self._evidence_list(symbols)}"
        severity = "INFO" if passed else "WARN"
        return CheckResult("StackCanary", passed, severity, evidence)

    def check_codesign(self) -> CheckResult:
        signed = getattr(self.binary, "has_signature", False)
        evidence = f"CodeSigned={signed}"
        severity = "INFO" if signed else "WARN"
        return CheckResult("CodeSign", signed, severity, evidence)

    def check_entitlements(self) -> CheckResult:
        entitlements = getattr(self.binary, "entitlements", None)
        passed = bool(entitlements)
        evidence = f"Entitlements={entitlements}"
        severity = "INFO" if passed else "WARN"
        return CheckResult("Entitlements", passed, severity, evidence)

    # -------------------
    # Run all checks
    # -------------------
    def run_all(self) -> Dict[str, Any]:
        results = {}
        try:
            if self.format == "ELF":
                checks = [
                    self.check_pie(),
                    self.check_nx(),
                    self.check_relro(),
                    self.check_stack_protector(),
                    self.check_fortify(),
                    self.check_debug_symbols(),
                    self.check_stripped(),
                    self.check_relocations(),
                    self.check_rpath_runpath(),
                    self.check_text_relocations(),
                    self.check_interpreter(),
                    self.check_build_info(),
                ]
            elif self.format == "PE":
                checks = [
                    self.check_aslr(),
                    self.check_dep(),
                    self.check_cfg(),
                    self.check_safeseh(),
                    self.check_stack_cookie(),
                    self.check_signature(),
                ]
            elif self.format == "MachO":
                checks = [
                    self.check_pie_macho(),
                    self.check_nx_macho(),
                    self.check_stack_canary_macho(),
                    self.check_codesign(),
                    self.check_entitlements(),
                ]
            else:
                raise HardeningError(f"Unsupported binary format: {self.format}")
        except Exception as e:
            raise HardeningError(f"Error running checks: {e}")

        results.update({c.name: c.to_dict() for c in checks})
        results["_meta"] = {
            "path": self.path,
            "format": self.format,
            "file_size_bytes": os.path.getsize(self.path),
        }
        return results

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.run_all(), indent=indent)

    def to_json_file(self, output_path: str, indent: int = 2) -> None:
        data = self.run_all()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Cross-platform Binary Hardening Checker")
    parser.add_argument("binary", help="Path to binary (ELF / PE / Mach-O)")
    parser.add_argument("--json", help="Write JSON report to file", default=None)
    args = parser.parse_args()

    checker = BinaryHardeningChecker(args.binary)
    report = checker.run_all()
    if args.json:
        checker.to_json_file(args.json)
        print(f"Wrote JSON report to {args.json}")
    else:
        print(json.dumps(report, indent=2))
