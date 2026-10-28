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

def matches_version_constraint(version_str: str, constraint_str: str) -> bool:
    """
    Checks if a component version satisfies an affected or fixed version constraint.
    Supports exact match, prefix match, and simple range operators (<, <=, >, >=, ==, !=).
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
    
    if not v_valid:
        # Fallback to simple string match
        return v_norm == c_clean
    
    try:
        from packaging.specifiers import SpecifierSet
        spec = SpecifierSet(c_clean)
        return Version(v_norm) in spec
    except Exception:
        # If constraint is a bare version e.g. "1.2.3", test equality
        c_norm, c_valid, _ = normalise_version(c_clean)
        if c_valid:
            try:
                return Version(v_norm) == Version(c_norm)
            except Exception:
                pass
        return v_norm.startswith(c_clean)
