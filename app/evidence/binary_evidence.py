"""Binary and Linker Evidence Evaluator for Automotive ECUs (Phase 3 B3).

Evaluates whether vulnerable third-party library functions are actually compiled
and linked into the final ECU binary, or whether dead-code elimination
(-ffunction-sections -Wl,--gc-sections) successfully stripped the vulnerable symbol.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import Optional, Set, Tuple, Union
from app.models.enums import BinaryExposureState

class BinaryEvidenceEvaluator:
    """Evaluates binary-level exposure from GNU ld linker map files, symbol dumps, or ELF binaries."""

    @staticmethod
    def parse_ld_map(map_path_or_content: Union[str, Path]) -> Tuple[Set[str], Set[str]]:
        """
        Parses a GNU ld linker map file.

        Returns:
            (retained_symbols_and_sections, discarded_sections)
        """
        content = ""
        if isinstance(map_path_or_content, Path) or (isinstance(map_path_or_content, str) and Path(map_path_or_content).exists()):
            content = Path(map_path_or_content).read_text(encoding="utf-8", errors="ignore")
        else:
            content = str(map_path_or_content)

        discarded: Set[str] = set()
        retained: Set[str] = set()

        in_discarded_section = False
        in_memory_map = False

        for line in content.splitlines():
            line_str = line.strip()
            if not line_str:
                continue

            if "Discarded input sections" in line:
                in_discarded_section = True
                in_memory_map = False
                continue
            elif "Memory Configuration" in line or "Linker script and memory map" in line:
                in_discarded_section = False
                if "Linker script and memory map" in line:
                    in_memory_map = True
                continue

            if in_discarded_section:
                # E.g. .text.vulnerable_cipher_decrypt
                match = re.match(r"^(\.[a-zA-Z0-9_.]+)", line_str)
                if match:
                    discarded.add(match.group(1))
            elif in_memory_map:
                # Look for section names or symbols
                sec_match = re.match(r"^(\.[a-zA-Z0-9_.]+)", line_str)
                if sec_match:
                    retained.add(sec_match.group(1))
                # Look for standalone symbol names (words without dots)
                sym_match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]+)$", line_str)
                if sym_match:
                    retained.add(sym_match.group(1))

        return retained, discarded

    @staticmethod
    def parse_symbols_list(sym_path_or_content: Union[str, Path]) -> Set[str]:
        """Parses symbol names from an nm or text symbol table dump."""
        content = ""
        if isinstance(sym_path_or_content, Path) or (isinstance(sym_path_or_content, str) and Path(sym_path_or_content).exists()):
            content = Path(sym_path_or_content).read_text(encoding="utf-8", errors="ignore")
        else:
            content = str(sym_path_or_content)

        symbols: Set[str] = set()
        for line in content.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            # Last token is typically the symbol name in nm output: "0000000000401040 T my_func"
            symbols.add(parts[-1])
        return symbols

    def evaluate_exposure(
        self,
        vulnerable_symbol: Optional[str],
        map_path: Optional[Union[str, Path]] = None,
        symbol_list_path: Optional[Union[str, Path]] = None,
        vex_justification: Optional[str] = None
    ) -> Tuple[BinaryExposureState, str]:
        """
        Determines the formal BinaryExposureState for a component vulnerability.

        Rules:
          1. If no symbol is specified by the advisory: defaults to POTENTIALLY_EXPOSED.
          2. If map shows the section is discarded: NOT_PRESENT_IN_BINARY.
          3. If map/symbol list confirms symbol is retained: CONFIRMED_IN_BINARY.
          4. If VEX claims 'vulnerable_code_not_in_execute_path':
             - If symbol is confirmed stripped -> NOT_PRESENT_IN_BINARY (corroborated).
             - If symbol is confirmed present -> POTENTIALLY_EXPOSED with contradiction flag.
             - If no binary evidence -> LIKELY_PRESENT or POTENTIALLY_EXPOSED with unverified note.
        """
        if not vulnerable_symbol:
            return (
                BinaryExposureState.POTENTIALLY_EXPOSED,
                "Advisory does not specify vulnerable function/symbol; static reachability assumed."
            )

        symbol_clean = vulnerable_symbol.strip()
        section_pattern = f".text.{symbol_clean}"

        # 1. Evaluate linker map if available
        if map_path and Path(map_path).exists():
            retained_sections, discarded_sections = self.parse_ld_map(map_path)

            if section_pattern in discarded_sections or symbol_clean in discarded_sections:
                return (
                    BinaryExposureState.NOT_PRESENT_IN_BINARY,
                    f"Linker map proves symbol '{symbol_clean}' was discarded by --gc-sections."
                )

            if symbol_clean in retained_sections or section_pattern in retained_sections:
                if vex_justification == "vulnerable_code_not_in_execute_path":
                    return (
                        BinaryExposureState.POTENTIALLY_EXPOSED,
                        f"Contradiction: VEX claims code not executed, but symbol '{symbol_clean}' is retained in binary."
                    )
                return (
                    BinaryExposureState.CONFIRMED_IN_BINARY,
                    f"Linker map confirms symbol '{symbol_clean}' is linked into final executable."
                )

        # 2. Evaluate symbol table dump if available
        if symbol_list_path and Path(symbol_list_path).exists():
            symbols = self.parse_symbols_list(symbol_list_path)
            if symbol_clean in symbols:
                if vex_justification == "vulnerable_code_not_in_execute_path":
                    return (
                        BinaryExposureState.POTENTIALLY_EXPOSED,
                        f"Contradiction: VEX claims not executed, but symbol '{symbol_clean}' is present in symbol table."
                    )
                return (
                    BinaryExposureState.CONFIRMED_IN_BINARY,
                    f"Symbol table confirms symbol '{symbol_clean}' is present in binary."
                )
            else:
                return (
                    BinaryExposureState.NOT_PRESENT_IN_BINARY,
                    f"Symbol '{symbol_clean}' is absent from final binary symbol table."
                )

        # 3. Fallback without binary evidence
        if vex_justification == "vulnerable_code_not_in_execute_path":
            return (
                BinaryExposureState.POTENTIALLY_EXPOSED,
                "VEX claims code not in execution path, but no linker map or binary evidence was provided to corroborate."
            )

        return (
            BinaryExposureState.POTENTIALLY_EXPOSED,
            "No binary evidence artifact provided; conservative static dependency assumed."
        )
