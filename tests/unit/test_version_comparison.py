"""Parametrised and property-based tests for automotive version comparison (A1)."""

import pytest
from hypothesis import given, strategies as st
from app.normalisation.version_normaliser import (
    parse_comparable_version,
    ComparableVersion,
    UnparseableVersion,
    matches_version_constraint
)

@pytest.mark.parametrize("v1,v2,expected_lt", [
    ("1.1.1t", "1.1.1u", True),
    ("1.0.2z", "1.0.2zk", True),
    ("1.1.1", "1.1.1a", True),
    ("1.0.0-alpha", "1.0.0-beta", True),
    ("1.0.0-beta", "1.0.0-rc1", True),
    ("1.0.0-rc1", "1.0.0", True),
    ("1:2.0.0", "2:1.0.0", True),
    ("v1.2.3", "v1.2.4", True),
    ("ubuntu-1.0.0", "debian-1.0.1", True),
])
def test_specific_automotive_version_ordering(v1, v2, expected_lt):
    """Tests critical version comparisons specified in Phase 1 A1."""
    cv1 = parse_comparable_version(v1)
    cv2 = parse_comparable_version(v2)
    assert isinstance(cv1, ComparableVersion)
    assert isinstance(cv2, ComparableVersion)
    assert (cv1 < cv2) == expected_lt

def test_openssl_zk_greater_than_z():
    """Explicitly verify 1.0.2zk > 1.0.2z."""
    cv_zk = parse_comparable_version("1.0.2zk")
    cv_z = parse_comparable_version("1.0.2z")
    assert cv_zk > cv_z

def test_vendor_prefix_equivalence():
    """Verify vendor prefix stripping results in exact semantic equality."""
    assert parse_comparable_version("ubuntu-1.0.0") == parse_comparable_version("1.0.0")
    assert parse_comparable_version("v1.2.3") == parse_comparable_version("1.2.3")
    assert parse_comparable_version("rel-2.5") == parse_comparable_version("2.5")

@pytest.mark.parametrize("malformed", ["", "   ", "unknown", "none", "null", "n/a", "latest", "!@#$%^", "nodigits"])
def test_malformed_input_returns_unparseable_sentinel(malformed):
    """Verify malformed versions return UnparseableVersion and do not raise unhandled exceptions."""
    res = parse_comparable_version(malformed)
    assert isinstance(res, UnparseableVersion)
    # Unparseable version cannot satisfy numeric constraints
    assert not matches_version_constraint(malformed, "< 2.0.0")
    assert not matches_version_constraint("1.0.0", f"< {malformed}")

# Hypothesis strategies for version generation
version_strategy = st.builds(
    lambda maj, min_, patch, letter: f"{maj}.{min_}.{patch}{letter}",
    maj=st.integers(min_value=0, max_value=50),
    min_=st.integers(min_value=0, max_value=50),
    patch=st.integers(min_value=0, max_value=50),
    letter=st.sampled_from(["", "a", "b", "c", "t", "u", "z", "zk"])
)

@given(a_str=version_strategy, b_str=version_strategy)
def test_totality_property(a_str, b_str):
    """Property: Totality - For any valid versions A and B, (A <= B) or (B <= A) is True."""
    a = parse_comparable_version(a_str)
    b = parse_comparable_version(b_str)
    assert isinstance(a, ComparableVersion)
    assert isinstance(b, ComparableVersion)
    assert (a <= b) or (b <= a)

@given(a_str=version_strategy, b_str=version_strategy)
def test_antisymmetry_property(a_str, b_str):
    """Property: Antisymmetry - (A <= B and B <= A) implies A == B."""
    a = parse_comparable_version(a_str)
    b = parse_comparable_version(b_str)
    if (a <= b) and (b <= a):
        assert a == b
        assert not (a < b)
        assert not (b < a)

@given(a_str=version_strategy, b_str=version_strategy, c_str=version_strategy)
def test_transitivity_property(a_str, b_str, c_str):
    """Property: Transitivity - (A <= B and B <= C) implies A <= C."""
    a = parse_comparable_version(a_str)
    b = parse_comparable_version(b_str)
    c = parse_comparable_version(c_str)
    if (a <= b) and (b <= c):
        assert a <= c
