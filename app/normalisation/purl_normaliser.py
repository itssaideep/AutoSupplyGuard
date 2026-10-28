"""Package URL (PURL) normaliser and validator."""

from typing import Optional, Tuple
from packageurl import PackageURL

def normalise_purl(raw_purl: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], bool]:
    """
    Parses and normalises a Package URL.
    
    Returns:
        (canonical_purl, ecosystem, name, version, is_valid)
    """
    if not raw_purl or not isinstance(raw_purl, str):
        return None, None, None, None, False
    
    cleaned = raw_purl.strip()
    if not cleaned.startswith("pkg:"):
        return None, None, None, None, False
    
    try:
        parsed = PackageURL.from_string(cleaned)
        canonical = parsed.to_string()
        ecosystem = parsed.type.lower() if parsed.type else None
        name = parsed.name
        if parsed.namespace:
            name = f"{parsed.namespace}/{parsed.name}"
        version = parsed.version
        return canonical, ecosystem, name, version, True
    except Exception:
        return None, None, None, None, False

def construct_purl(ecosystem: str, name: str, version: Optional[str] = None, namespace: Optional[str] = None) -> Optional[str]:
    """Constructs a standard PURL string from component attributes."""
    if not ecosystem or not name:
        return None
    try:
        purl_obj = PackageURL(
            type=ecosystem.lower().strip(),
            namespace=namespace.strip() if namespace else None,
            name=name.strip(),
            version=version.strip() if version else None
        )
        return purl_obj.to_string()
    except Exception:
        return None
