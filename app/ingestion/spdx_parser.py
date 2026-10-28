"""SPDX 2.2 and 2.3 JSON parser."""

import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
from app.ingestion.base import BaseSBOMParser, ParsedSBOMResult
from app.models.enums import (
    SBOMFormat,
    SBOMValidationStatus,
    IdentityResolutionStatus,
    DependencyScope
)
from app.models.sbom import SBOM, DependencyEdge
from app.models.component import Component
from app.normalisation.purl_normaliser import normalise_purl
from app.normalisation.version_normaliser import normalise_version

class SPDXParser(BaseSBOMParser):
    """Parses SPDX documents in JSON format (SPDX-2.2 and SPDX-2.3)."""
    
    def can_parse(self, raw_data: Dict[str, Any]) -> bool:
        if not isinstance(raw_data, dict):
            return False
        spdx_ver = raw_data.get("spdxVersion")
        return bool(isinstance(spdx_ver, str) and spdx_ver.startswith("SPDX-"))
    
    def parse(self, raw_data: Dict[str, Any], source_identifier: str, sha256_checksum: str) -> ParsedSBOMResult:
        errors: List[str] = []
        warnings: List[str] = []
        components: List[Component] = []
        dependencies: List[DependencyEdge] = []
        
        spdx_version = raw_data.get("spdxVersion", "Unknown")
        doc_name = raw_data.get("name")
        creation_info = raw_data.get("creationInfo", {})
        
        # Parse timestamp
        created_str = creation_info.get("created")
        created_dt: Optional[datetime] = None
        if created_str:
            try:
                # Handle ISO timestamps like 2023-01-01T12:00:00Z
                created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            except Exception:
                warnings.append(f"Could not parse creation timestamp: '{created_str}'")
        
        # Extract creators/author
        creators = creation_info.get("creators", [])
        author = "; ".join(creators) if creators else None
        
        sbom_id = f"sbom-spdx-{uuid.uuid4().hex[:12]}"
        
        raw_packages = raw_data.get("packages", [])
        if not raw_packages:
            warnings.append("SPDX document contains no packages.")
        
        # Map original SPDXID -> canonical internal_id
        spdx_id_to_internal: Dict[str, str] = {}
        seen_identities: Dict[str, int] = {}
        
        for pkg in raw_packages:
            if not isinstance(pkg, dict):
                continue
            
            raw_spdx_id = pkg.get("SPDXID", "").strip()
            raw_name = pkg.get("name", "").strip()
            raw_version = pkg.get("versionInfo")
            raw_supplier = pkg.get("supplier")
            
            if not raw_spdx_id:
                raw_spdx_id = f"SPDXRef-Anon-{uuid.uuid4().hex[:8]}"
                warnings.append(f"Package missing SPDXID; generated '{raw_spdx_id}' for name='{raw_name}'")
            
            # Extract PURL and CPE from externalRefs
            purl_val: Optional[str] = None
            cpe_val: Optional[str] = None
            for ref in pkg.get("externalRefs", []):
                ref_type = str(ref.get("referenceType", "")).lower()
                locator = ref.get("referenceLocator")
                if "purl" in ref_type and locator:
                    purl_val = locator
                elif ("cpe" in ref_type) and locator:
                    cpe_val = locator
            
            # Normalise PURL and Version
            norm_purl, purl_ecosystem, purl_name, purl_version, is_valid_purl = normalise_purl(purl_val)
            norm_version, is_valid_semver, _ = normalise_version(raw_version or purl_version)
            
            comp_name = purl_name or raw_name or "unknown-package"
            comp_version = norm_version or (raw_version.strip() if raw_version else None)
            
            # Assign identity resolution status
            if comp_name != "unknown-package" and comp_version and is_valid_purl:
                identity_status = IdentityResolutionStatus.RESOLVED_EXACT
            elif comp_name != "unknown-package" and comp_version:
                identity_status = IdentityResolutionStatus.RESOLVED_PARTIAL
            elif comp_name != "unknown-package":
                identity_status = IdentityResolutionStatus.UNRESOLVED
                warnings.append(f"Package '{comp_name}' ({raw_spdx_id}) is missing version metadata.")
            else:
                identity_status = IdentityResolutionStatus.UNRESOLVED
                errors.append(f"Package '{raw_spdx_id}' lacks both name and PURL.")
            
            # Check duplicate package identities
            identity_key = f"{comp_name}@{comp_version}"
            seen_identities[identity_key] = seen_identities.get(identity_key, 0) + 1
            if seen_identities[identity_key] > 1:
                warnings.append(f"Duplicate component identity detected: '{identity_key}'")
            
            # Normalise supplier string
            supplier_clean = None
            if raw_supplier and raw_supplier not in {"NOASSERTION", "NONE"}:
                supplier_clean = raw_supplier.replace("Organization:", "").replace("Person:", "").strip()
            
            # License info
            license_declared = pkg.get("licenseDeclared")
            license_concluded = pkg.get("licenseConcluded")
            lic = license_declared if (license_declared and license_declared != "NOASSERTION") else license_concluded
            if lic in {"NOASSERTION", "NONE"}:
                lic = None
            
            internal_comp_id = f"comp-{uuid.uuid4().hex[:12]}"
            spdx_id_to_internal[raw_spdx_id] = internal_comp_id
            
            component = Component(
                internal_id=internal_comp_id,
                name=comp_name,
                version=comp_version,
                purl=norm_purl,
                cpe=cpe_val,
                supplier=supplier_clean,
                ecosystem=purl_ecosystem,
                license=lic,
                source_sbom_id=sbom_id,
                original_id=raw_spdx_id,
                original_name=raw_name if raw_name else None,
                original_version=raw_version if raw_version else None,
                identity_status=identity_status
            )
            components.append(component)
        
        # Parse relationships
        raw_relationships = raw_data.get("relationships", [])
        for rel in raw_relationships:
            if not isinstance(rel, dict):
                continue
            src = rel.get("spdxElementId")
            tgt = rel.get("relatedSpdxElement")
            rel_type = rel.get("relationshipType", "DEPENDS_ON")
            
            if not src or not tgt:
                continue
            
            # Filter out top-level document packaging relations like DESCRIBES/DESCRIBED_BY
            if src == "SPDXRef-DOCUMENT" or tgt == "SPDXRef-DOCUMENT":
                continue
            
            # Map relationship direction:
            # If A DEPENDS_ON B -> source is A, target is B
            # If B DEPENDENCY_OF A -> source is A, target is B
            edge_src = src
            edge_tgt = tgt
            if rel_type == "DEPENDENCY_OF":
                edge_src = tgt
                edge_tgt = src
                rel_type = "DEPENDS_ON"
            
            internal_src = spdx_id_to_internal.get(edge_src)
            internal_tgt = spdx_id_to_internal.get(edge_tgt)
            
            if not internal_src:
                warnings.append(f"Unresolved dependency source reference: '{edge_src}'")
            if not internal_tgt:
                warnings.append(f"Unresolved dependency target reference: '{edge_tgt}'")
            
            if internal_src and internal_tgt:
                dependencies.append(DependencyEdge(
                    source_component_id=internal_src,
                    target_component_id=internal_tgt,
                    relationship_type=rel_type,
                    scope=DependencyScope.RUNTIME,
                    raw_source_ref=edge_src,
                    raw_target_ref=edge_tgt
                ))
        
        # Validation status
        val_status = SBOMValidationStatus.VALID
        if errors:
            val_status = SBOMValidationStatus.MALFORMED
        elif warnings:
            val_status = SBOMValidationStatus.VALID_WITH_WARNINGS
        
        sbom = SBOM(
            internal_id=sbom_id,
            format=SBOMFormat.SPDX,
            format_version="JSON",
            spec_version=spdx_version.replace("SPDX-", ""),
            document_name=doc_name,
            author=author,
            creation_timestamp=created_dt,
            source_identifier=source_identifier,
            sha256_checksum=sha256_checksum,
            component_count=len(components),
            dependency_count=len(dependencies),
            validation_status=val_status,
            validation_errors=errors + warnings
        )
        
        return ParsedSBOMResult(
            sbom=sbom,
            components=components,
            dependencies=dependencies,
            errors=errors,
            warnings=warnings
        )
