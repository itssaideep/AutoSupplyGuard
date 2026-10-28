"""Unit tests for Phase 3 B3 Binary Exposure Model."""

from pathlib import Path
import pytest
from app.evidence.binary_evidence import BinaryEvidenceEvaluator
from app.models.enums import BinaryExposureState

FIXTURES_DIR = Path("tests/fixtures/binary_evidence")

@pytest.fixture
def evaluator():
    return BinaryEvidenceEvaluator()

def test_default_status_without_binary_evidence(evaluator):
    """With no evidence, status is potentially_exposed and no exploitability is claimed."""
    state, notes = evaluator.evaluate_exposure(
        vulnerable_symbol="vulnerable_cipher_decrypt",
        map_path=None,
        symbol_list_path=None
    )
    assert state == BinaryExposureState.POTENTIALLY_EXPOSED
    assert "No binary evidence" in notes

def test_linker_map_stripped_downgrades_to_not_present(evaluator):
    """When linker map shows symbol under Discarded input sections, status is downgraded."""
    stripped_map = FIXTURES_DIR / "libtinycrypto_stripped.map"
    state, notes = evaluator.evaluate_exposure(
        vulnerable_symbol="vulnerable_cipher_decrypt",
        map_path=stripped_map
    )
    assert state == BinaryExposureState.NOT_PRESENT_IN_BINARY
    assert "discarded by --gc-sections" in notes

def test_linker_map_retained_confirms_presence(evaluator):
    """When linker map shows symbol in active .text section, status is confirmed_in_binary."""
    unstripped_map = FIXTURES_DIR / "libtinycrypto_unstripped.map"
    state, notes = evaluator.evaluate_exposure(
        vulnerable_symbol="vulnerable_cipher_decrypt",
        map_path=unstripped_map
    )
    assert state == BinaryExposureState.CONFIRMED_IN_BINARY
    assert "linked into final executable" in notes

def test_symbol_list_stripped_yields_not_present(evaluator):
    """When symbol dump lacks the vulnerable function, status is not_present_in_binary."""
    stripped_syms = FIXTURES_DIR / "symbols_stripped.txt"
    state, notes = evaluator.evaluate_exposure(
        vulnerable_symbol="vulnerable_cipher_decrypt",
        symbol_list_path=stripped_syms
    )
    assert state == BinaryExposureState.NOT_PRESENT_IN_BINARY
    assert "absent from final binary" in notes

def test_vex_without_evidence_remains_potentially_exposed(evaluator):
    """VEX claiming code not executed without binary evidence never becomes not affected."""
    state, notes = evaluator.evaluate_exposure(
        vulnerable_symbol="vulnerable_cipher_decrypt",
        vex_justification="vulnerable_code_not_in_execute_path"
    )
    assert state == BinaryExposureState.POTENTIALLY_EXPOSED
    assert "no linker map or binary evidence was provided" in notes

def test_contradictory_vex_versus_binary_presence(evaluator):
    """When VEX claims code not executed but binary evidence confirms symbol presence, flag contradiction."""
    unstripped_map = FIXTURES_DIR / "libtinycrypto_unstripped.map"
    state, notes = evaluator.evaluate_exposure(
        vulnerable_symbol="vulnerable_cipher_decrypt",
        map_path=unstripped_map,
        vex_justification="vulnerable_code_not_in_execute_path"
    )
    assert state == BinaryExposureState.POTENTIALLY_EXPOSED
    assert "Contradiction" in notes
