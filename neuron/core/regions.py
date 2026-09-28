import difflib


def get_aligned_regions(vul_code, patched_code, context_lines=1):
    """Union of diff hunks and up to N matched context lines on each boundary."""
    if not isinstance(context_lines, int) or context_lines < 0:
        raise ValueError("context_lines must be a nonnegative integer")
    matcher = difflib.SequenceMatcher(
        None, vul_code.split('\n'), patched_code.split('\n'), autojunk=False
    )
    vulnerable, patched = set(), set()
    for group in matcher.get_grouped_opcodes(n=context_lines):
        for _, i1, i2, j1, j2 in group:
            vulnerable.update(range(i1, i2))
            patched.update(range(j1, j2))
    return sorted(vulnerable), sorted(patched)
