"""Version string normaliser and constraint checker."""

import re
from typing import Optional, Tuple
from packaging.version import Version, InvalidVersion

def normalise_version(raw_version: Optional[str]) -> Tuple[Optional[str], bool, bool]:
    """
    Normalises a version string while preserving its semantic meaning.
    
    Returns:
        (canonical_version, is_valid_semver_or_pep440, is_modified)
    """
    if raw_version is None:
        return None, False, False
    
    cleaned = str(raw_version).strip()
    if not cleaned or cleaned.lower() in {"unknown", "none", "null", "n/a", "latest"}:
        return None, False, False
    
    # Strip common git or tag prefixes (e.g. 'v1.2.3' -> '1.2.3', 'release-1.2.3' -> '1.2.3')
    modified = False
    original = cleaned
    
    cleaned = re.sub(r"^(?:v|ver|version|release)[-_.]?", "", cleaned, flags=re.IGNORECASE).strip()
    if cleaned != original:
        modified = True
    
    # Test with packaging.version
    try:
        parsed = Version(cleaned)
        return str(parsed), True, modified or (str(parsed) != cleaned)
    except InvalidVersion:
        # Return cleaned non-standard version with validity=False
        return cleaned, False, modified

def parse_comparable_version(v_str: str) -> tuple:
    """Parses version into comparable tuple of (type_flag, value) tokens."""
    tokens = re.findall(r"(\d+|[a-zA-Z]+)", v_str)
    res = []
    for t in tokens:
        if t.isdigit():
            res.append((0, int(t)))
        else:
            res.append((1, t.lower()))
    return tuple(res)

def matches_version_constraint(version_str: str, constraint_str: str) -> bool:
    """
    Checks if a component version satisfies an affected or fixed version constraint.
    Supports exact match, prefix match, and range operators (<, <=, >, >=, ==, !=).
    Handles both standard PEP440/SemVer and letter-suffixed versions (e.g. OpenSSL 1.1.1u).
    """
    if not version_str or not constraint_str:
        return False
    
    v_norm, v_valid, _ = normalise_version(version_str)
    if not v_norm:
        return False
    
    c_clean = constraint_str.strip()
    if c_clean in {"*", "all"}:
        return True
    
    # Exact equality
    if c_clean == v_norm or c_clean == version_str:
        return True
    
    # Check operator prefix
    op_match = re.match(r"^(<=|>=|<|>|==|!=)\s*(.+)$", c_clean)
    if op_match:
        op = op_match.group(1)
        target_v = op_match.group(2).strip()
        t_norm, t_valid, _ = normalise_version(target_v)
        target_comp = t_norm or target_v
        
        # Try packaging.version first if both are valid standard versions
        if v_valid and t_valid:
            try:
                from packaging.specifiers import SpecifierSet
                return Version(v_norm) in SpecifierSet(c_clean)
            except Exception:
                pass
        
        # Fallback to tokenized tuple comparison
        v_tuple = parse_comparable_version(v_norm)
        t_tuple = parse_comparable_version(target_comp)
        if op == "<":
            return v_tuple < t_tuple
        elif op == "<=":
            return v_tuple <= t_tuple
        elif op == ">":
            return v_tuple > t_tuple
        elif op == ">=":
            return v_tuple >= t_tuple
        elif op == "==":
            return v_tuple == t_tuple
        elif op == "!=":
            return v_tuple != t_tuple
            
    # Default fallback: equality or prefix match
    return v_norm == c_clean or v_norm.startswith(c_clean)

