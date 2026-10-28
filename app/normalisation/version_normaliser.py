"""Version string normaliser and constraint checker.

Supports automotive SemVer, OpenSSL letter-suffix patches (e.g. 1.1.1t < 1.1.1u),
epochs (e.g. 2:1.0 > 1:2.0), pre-releases (alpha < beta < rc < final < letter_patch),
vendor prefixes (e.g. ubuntu-1.0 == 1.0), and unparseable sentinels.
"""

from __future__ import annotations
import re
from typing import Optional, Tuple, Any, Union
from functools import total_ordering
from packaging.version import Version, InvalidVersion


class UnparseableVersion:
    """Sentinel representing a version string that cannot be deterministically ordered."""

    def __init__(self, raw: str):
        self.raw = raw

    def __repr__(self) -> str:
        return f"UnparseableVersion({self.raw!r})"

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, UnparseableVersion):
            return self.raw == other.raw
        return False

    def __lt__(self, other: Any) -> bool:
        # Unparseable versions have no valid mathematical ordering
        return False

    def __le__(self, other: Any) -> bool:
        return self == other

    def __gt__(self, other: Any) -> bool:
        return False

    def __ge__(self, other: Any) -> bool:
        return self == other


@total_ordering
class ComparableVersion:
    """
    Mathematical comparable version model guaranteeing totality, antisymmetry, and transitivity.
    """

    def __init__(
        self,
        epoch: int,
        release_tokens: Tuple[int, ...],
        pre_phase: int,  # 0=dev, 1=alpha, 2=beta, 3=rc, 4=final, 5=letter_patch
        pre_num: int,
        letter_patch: str,
        raw: str
    ):
        self.epoch = epoch
        self.release_tokens = release_tokens
        self.pre_phase = pre_phase
        self.pre_num = pre_num
        self.letter_patch = letter_patch
        self.raw = raw

    @property
    def _sort_key(self) -> Tuple[int, Tuple[int, ...], int, int, str]:
        return (
            self.epoch,
            self.release_tokens,
            self.pre_phase,
            self.pre_num,
            self.letter_patch
        )

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, UnparseableVersion):
            return False
        if not isinstance(other, ComparableVersion):
            return False
        return self._sort_key == other._sort_key

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, UnparseableVersion):
            return False
        if not isinstance(other, ComparableVersion):
            return NotImplemented
        return self._sort_key < other._sort_key

    def __repr__(self) -> str:
        return f"ComparableVersion({self.raw!r})"


def parse_comparable_version(v_str: Optional[str]) -> Union[ComparableVersion, UnparseableVersion]:
    """
    Parses a version string into a ComparableVersion or an UnparseableVersion sentinel.

    Handles:
      - Epochs: '2:1.0.0' -> epoch 2
      - Vendor prefixes: 'ubuntu-1.0.0', 'v1.2.3'
      - OpenSSL letter patches: '1.1.1t', '1.0.2zk'
      - Pre-release identifiers: '1.0.0-alpha.1', '1.0.0-rc2'
      - Malformed input: returns UnparseableVersion
    """
    if v_str is None:
        return UnparseableVersion("None")

    cleaned = str(v_str).strip()
    if not cleaned or cleaned.lower() in {"unknown", "none", "null", "n/a", "latest", "*"}:
        return UnparseableVersion(cleaned)

    # Check for epoch
    epoch = 0
    epoch_match = re.match(r"^(\d+):(.*)$", cleaned)
    if epoch_match:
        epoch = int(epoch_match.group(1))
        cleaned = epoch_match.group(2).strip()

    # Strip known vendor and release prefixes
    cleaned = re.sub(
        r"^(?:ubuntu|debian|rh|rhel|alpine|rel|release|ver|version|v)[-_.]?",
        "",
        cleaned,
        flags=re.IGNORECASE
    ).strip()

    if not cleaned:
        return UnparseableVersion(v_str)

    # Must contain at least one digit in the version string to be comparable
    if not re.search(r"\d", cleaned):
        return UnparseableVersion(v_str)

    # Split into numeric release segments and suffix (pre-release or letter patch)
    # Match standard leading digits e.g. 1.2.3 or 1.1.1t
    # Pattern: extract leading dotted numbers
    parts = re.split(r"[-_+~]", cleaned)
    base_part = parts[0]
    extra_parts = parts[1:] if len(parts) > 1 else []

    # Extract numeric segments from base_part
    # Handle OpenSSL style attached letter suffix: e.g. '1.1.1u' or '1.0.2zk'
    base_match = re.match(r"^((?:\d+\.)*\d+)([a-zA-Z]+)?$", base_part)
    if not base_match:
        # Fallback regex extraction of numbers
        nums = [int(n) for n in re.findall(r"\d+", base_part)]
        if not nums:
            return UnparseableVersion(v_str)
        release_tokens = tuple(nums)
        attached_letters = ""
    else:
        release_tokens = tuple(int(x) for x in base_match.group(1).split("."))
        attached_letters = (base_match.group(2) or "").lower()

    # Determine pre_phase, pre_num, and letter_patch
    pre_phase = 4  # Default: final release
    pre_num = 0
    letter_patch = ""

    # Check for attached letter patch in base (OpenSSL style: 1.1.1a ... 1.1.1u, 1.0.2zk)
    if attached_letters:
        if attached_letters == "dev":
            pre_phase = 0
        elif attached_letters == "alpha":
            pre_phase = 1
        elif attached_letters == "beta":
            pre_phase = 2
        elif attached_letters == "rc":
            pre_phase = 3
        else:
            # Letter patch post-release (e.g. 'a', 'b', 't', 'u', 'z', 'zk'): 1.1.1 < 1.1.1a
            pre_phase = 5
            letter_patch = attached_letters

    # Inspect extra parts (e.g. -rc1, -beta.2, -alpha)
    for extra in extra_parts:
        extra_lower = extra.lower()
        if "dev" in extra_lower:
            pre_phase = min(pre_phase, 0)
        elif "alpha" in extra_lower or re.match(r"^a\d*$", extra_lower):
            pre_phase = min(pre_phase, 1)
        elif "beta" in extra_lower or re.match(r"^b\d*$", extra_lower):
            pre_phase = min(pre_phase, 2)
        elif "rc" in extra_lower or "pre" in extra_lower or re.match(r"^c\d*$", extra_lower):
            pre_phase = min(pre_phase, 3)

        num_match = re.search(r"\d+", extra)
        if num_match:
            pre_num = int(num_match.group(0))

    return ComparableVersion(
        epoch=epoch,
        release_tokens=release_tokens,
        pre_phase=pre_phase,
        pre_num=pre_num,
        letter_patch=letter_patch,
        raw=str(v_str)
    )


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

    modified = False
    original = cleaned

    cleaned = re.sub(r"^(?:v|ver|version|release)[-_.]?", "", cleaned, flags=re.IGNORECASE).strip()
    if cleaned != original:
        modified = True

    try:
        parsed = Version(cleaned)
        return str(parsed), True, modified or (str(parsed) != cleaned)
    except InvalidVersion:
        return cleaned, False, modified


def matches_version_constraint(version_str: str, constraint_str: str) -> bool:
    """
    Checks if a component version satisfies an affected or fixed version constraint.
    Supports exact match, prefix match, and range operators (<, <=, >, >=, ==, !=).
    Handles both standard PEP440/SemVer and letter-suffixed versions (e.g. OpenSSL 1.1.1u).
    Propagates unparseable versions safely without crashing.
    """
    if not version_str or not constraint_str:
        return False

    c_clean = constraint_str.strip()
    if c_clean in {"*", "all"}:
        return True

    v_norm, v_valid, _ = normalise_version(version_str)
    if not v_norm:
        return False

    # Exact equality check
    if c_clean == v_norm or c_clean == version_str:
        return True

    # Check operator prefix
    op_match = re.match(r"^(<=|>=|<|>|==|!=)\s*(.+)$", c_clean)
    if op_match:
        op = op_match.group(1)
        target_v = op_match.group(2).strip()
        t_norm, t_valid, _ = normalise_version(target_v)
        target_comp = t_norm or target_v

        # Try packaging.version first if both are standard
        if v_valid and t_valid:
            try:
                from packaging.specifiers import SpecifierSet
                return Version(v_norm) in SpecifierSet(c_clean)
            except Exception:
                pass

        # ComparableVersion ordering
        v_comp = parse_comparable_version(v_norm)
        t_comp = parse_comparable_version(target_comp)

        if isinstance(v_comp, UnparseableVersion) or isinstance(t_comp, UnparseableVersion):
            return False

        if op == "<":
            return v_comp < t_comp
        elif op == "<=":
            return v_comp <= t_comp
        elif op == ">":
            return v_comp > t_comp
        elif op == ">=":
            return v_comp >= t_comp
        elif op == "==":
            return v_comp == t_comp
        elif op == "!=":
            return v_comp != t_comp

    return v_norm == c_clean or v_norm.startswith(c_clean)
