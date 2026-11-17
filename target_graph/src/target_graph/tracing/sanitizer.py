"""Parse AddressSanitizer and UndefinedBehaviorSanitizer crash reports."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class StackFrame:
    frame_index: int
    pc: str
    function_name: str
    source_file: str
    line_number: int


@dataclass
class SanitizerReport:
    sanitizer_type: str  # ASan, UBSan, etc.
    error_type: str      # heap-buffer-overflow, SEGV, etc.
    fault_pc: str
    frames: List[StackFrame]
    raw_text: str

    @property
    def crash_frame(self) -> Optional[StackFrame]:
        # Return the first application frame with valid source file and line
        for frame in self.frames:
            if frame.source_file and frame.line_number > 0 and not frame.function_name.startswith("__asan"):
                return frame
        return self.frames[0] if self.frames else None


def parse_sanitizer_output(text: str) -> Optional[SanitizerReport]:
    """Parse sanitizer output and extract structured stack trace."""
    # Look for ASan error header: "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..."
    asan_match = re.search(r"ERROR:\s+(AddressSanitizer|UndefinedBehaviorSanitizer):\s+([^\s]+)", text)
    if not asan_match:
        # Check SEGV or general sanitizer pattern
        asan_match = re.search(r"SUMMARY:\s+(AddressSanitizer|UndefinedBehaviorSanitizer):\s+([^\s]+)", text)
        if not asan_match:
            return None

    sanitizer_kind = asan_match.group(1)
    error_type = asan_match.group(2)

    # Parse frames: #0 0x401234 in func /path/to/file.c:42:10
    frame_regex = re.compile(
        r"#(\d+)\s+(0x[0-9a-fA-F]+)\s+(?:in\s+([^\s]+))?\s+(?:(?:at\s+)?([^:]+):(\d+))?"
    )

    frames: List[StackFrame] = []
    fault_pc = ""

    for line in text.splitlines():
        m = frame_regex.search(line)
        if m:
            idx = int(m.group(1))
            pc = m.group(2)
            fn = m.group(3) or "unknown"
            src_file = m.group(4) or ""
            line_no = int(m.group(5)) if m.group(5) else 0

            if not fault_pc:
                fault_pc = pc

            # Exclude internal sanitizer runtime frames if present
            if "asan" not in src_file.lower():
                frames.append(StackFrame(
                    frame_index=idx,
                    pc=pc,
                    function_name=fn,
                    source_file=src_file,
                    line_number=line_no,
                ))

    return SanitizerReport(
        sanitizer_type=sanitizer_kind,
        error_type=error_type,
        fault_pc=fault_pc,
        frames=frames,
        raw_text=text,
    )
