"""Manager module coordinating format detection and SBOM parsing."""

import json
import hashlib
from pathlib import Path
from typing import Dict, Any, Union, Optional
from app.ingestion.base import ParsedSBOMResult
from app.ingestion.spdx_parser import SPDXParser
from app.ingestion.cyclonedx_parser import CycloneDXParser
from app.models.enums import SBOMFormat, SBOMValidationStatus
from app.models.sbom import SBOM

def calculate_sha256(content_bytes: bytes) -> str:
    """Calculates SHA-256 hex digest of raw file bytes."""
    return hashlib.sha256(content_bytes).hexdigest()

class SBOMIngestionManager:
    """Dispatches SBOM documents to appropriate parser based on inspection."""

    def __init__(self):
        self.parsers = [
            SPDXParser(),
            CycloneDXParser(),
        ]

    def parse_file(self, file_path: Union[str, Path]) -> ParsedSBOMResult:
        """Parses an SBOM from a local file path."""
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"SBOM file not found: {p}")

        raw_bytes = p.read_bytes()
        sha256_hash = calculate_sha256(raw_bytes)
        source_id = p.name

        try:
            raw_text = raw_bytes.decode("utf-8")
            raw_data = json.loads(raw_text)
        except Exception as e:
            # File is malformed / invalid JSON
            sbom = SBOM(
                internal_id=f"sbom-malformed-{sha256_hash[:8]}",
                format=SBOMFormat.UNKNOWN,
                source_identifier=source_id,
                sha256_checksum=sha256_hash,
                validation_status=SBOMValidationStatus.MALFORMED,
                validation_errors=[f"JSON decoding error: {str(e)}"]
            )
            return ParsedSBOMResult(
                sbom=sbom,
                components=[],
                dependencies=[],
                errors=[f"JSON decoding error: {str(e)}"]
            )

        return self.parse_dict(raw_data, source_identifier=source_id, sha256_checksum=sha256_hash)

    def parse_dict(self, raw_data: Dict[str, Any], source_identifier: str = "memory", sha256_checksum: Optional[str] = None) -> ParsedSBOMResult:
        """Parses an in-memory dictionary representation of an SBOM."""
        if sha256_checksum is None:
            raw_bytes = json.dumps(raw_data, sort_keys=True).encode("utf-8")
            sha256_checksum = calculate_sha256(raw_bytes)

        for parser in self.parsers:
            if parser.can_parse(raw_data):
                try:
                    return parser.parse(raw_data, source_identifier=source_identifier, sha256_checksum=sha256_checksum)
                except Exception as e:
                    sbom = SBOM(
                        internal_id=f"sbom-error-{sha256_checksum[:8]}",
                        format=SBOMFormat.UNKNOWN,
                        source_identifier=source_identifier,
                        sha256_checksum=sha256_checksum,
                        validation_status=SBOMValidationStatus.MALFORMED,
                        validation_errors=[f"Parser exception: {str(e)}"]
                    )
                    return ParsedSBOMResult(
                        sbom=sbom,
                        components=[],
                        dependencies=[],
                        errors=[f"Parser exception: {str(e)}"]
                    )

        # Unsupported format / schema
        sbom = SBOM(
            internal_id=f"sbom-unsupported-{sha256_checksum[:8]}",
            format=SBOMFormat.UNKNOWN,
            source_identifier=source_identifier,
            sha256_checksum=sha256_checksum,
            validation_status=SBOMValidationStatus.UNSUPPORTED_VERSION,
            validation_errors=["Document format not recognized as valid SPDX or CycloneDX JSON."]
        )
        return ParsedSBOMResult(
            sbom=sbom,
            components=[],
            dependencies=[],
            errors=["Document format not recognized as valid SPDX or CycloneDX JSON."]
        )
