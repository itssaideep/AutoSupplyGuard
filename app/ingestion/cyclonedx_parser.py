"""CycloneDX 1.3, 1.4, 1.5 JSON parser."""

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

class CycloneDXParser(BaseSBOMParser):
    """Parses CycloneDX SBOMs in JSON format (spec versions 1.2 through 1.6)."""

    def can_parse(self, raw_data: Dict[str, Any]) -> bool:
        if not isinstance(raw_data, dict):
            return False
        bom_format = raw_data.get("bomFormat")
        return bool(isinstance(bom_format, str) and bom_format.lower() == "cyclonedx")

    def parse(self, raw_data: Dict[str, Any], source_identifier: str, sha256_checksum: str) -> ParsedSBOMResult:
        errors: List[str] = []
        warnings: List[str] = []
        components: List[Component] = []
        dependencies: List[DependencyEdge] = []

        spec_version = str(raw_data.get("specVersion", "1.4"))
        metadata = raw_data.get("metadata", {})

        # Parse timestamp
        timestamp_str = metadata.get("timestamp")
        created_dt: Optional[datetime] = None
        if timestamp_str:
            try:
                created_dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except Exception:
                warnings.append(f"Could not parse CycloneDX timestamp: '{timestamp_str}'")

        # Tools / Authors
        authors: List[str] = []
        tools = metadata.get("tools")
        if isinstance(tools, list):
            for t in tools:
                if isinstance(t, dict):
                    tool_name = t.get("name")
                    tool_ver = t.get("version")
                    authors.append(f"{tool_name} {tool_ver}".strip())
                elif isinstance(t, str):
                    authors.append(t)
        elif isinstance(tools, dict):  # CycloneDX 1.5+ tools dict
            components_tools = tools.get("components", [])
            for c in components_tools:
                if isinstance(c, dict):
                    authors.append(f"{c.get('name')} {c.get('version')}".strip())

        author_str = "; ".join([a for a in authors if a]) if authors else None

        sbom_id = f"sbom-cdx-{uuid.uuid4().hex[:12]}"

        # Gather all raw component objects (metadata.component + components list)
        raw_component_list = []
        root_component = metadata.get("component")
        if isinstance(root_component, dict):
            raw_component_list.append((root_component, True))

        for c in raw_data.get("components", []):
            if isinstance(c, dict):
                raw_component_list.append((c, False))

        if not raw_component_list:
            warnings.append("CycloneDX document contains no components.")

        ref_to_internal: Dict[str, str] = {}
        seen_identities: Dict[str, int] = {}

        for raw_comp, is_root in raw_component_list:
            raw_ref = raw_comp.get("bom-ref") or raw_comp.get("ref") or ""
            raw_name = raw_comp.get("name", "").strip()
            raw_version = raw_comp.get("version")
            raw_purl = raw_comp.get("purl")
            raw_cpe = raw_comp.get("cpe")

            if not raw_ref:
                raw_ref = f"bom-ref-anon-{uuid.uuid4().hex[:8]}"
                warnings.append(f"Component missing bom-ref; generated '{raw_ref}' for name='{raw_name}'")

            # Normalise PURL and Version
            norm_purl, purl_ecosystem, purl_name, purl_version, is_valid_purl = normalise_purl(raw_purl)
            norm_version, is_valid_semver, _ = normalise_version(raw_version or purl_version)

            comp_name = purl_name or raw_name or "unknown-package"
            comp_version = norm_version or (raw_version.strip() if raw_version else None)

            # Identity resolution status
            if comp_name != "unknown-package" and comp_version and is_valid_purl:
                identity_status = IdentityResolutionStatus.RESOLVED_EXACT
            elif comp_name != "unknown-package" and comp_version:
                identity_status = IdentityResolutionStatus.RESOLVED_PARTIAL
            elif comp_name != "unknown-package":
                identity_status = IdentityResolutionStatus.UNRESOLVED
                warnings.append(f"Component '{comp_name}' ({raw_ref}) missing version metadata.")
            else:
                identity_status = IdentityResolutionStatus.UNRESOLVED
                errors.append(f"Component '{raw_ref}' lacks name.")

            # Duplicate check
            identity_key = f"{comp_name}@{comp_version}"
            seen_identities[identity_key] = seen_identities.get(identity_key, 0) + 1
            if seen_identities[identity_key] > 1:
                warnings.append(f"Duplicate component identity detected: '{identity_key}'")

            # Supplier / publisher
            supplier_name = None
            supplier_dict = raw_comp.get("supplier")
            if isinstance(supplier_dict, dict):
                supplier_name = supplier_dict.get("name")
            elif isinstance(supplier_dict, str):
                supplier_name = supplier_dict
            if not supplier_name and raw_comp.get("publisher"):
                supplier_name = str(raw_comp.get("publisher")).strip()

            # License extraction
            licenses_list = raw_comp.get("licenses", [])
            lic_str = None
            if isinstance(licenses_list, list) and licenses_list:
                first_lic = licenses_list[0]
                if isinstance(first_lic, dict):
                    if "license" in first_lic and isinstance(first_lic["license"], dict):
                        lic_str = first_lic["license"].get("id") or first_lic["license"].get("name")
                    elif "expression" in first_lic:
                        lic_str = first_lic.get("expression")

            internal_comp_id = f"comp-{uuid.uuid4().hex[:12]}"
            ref_to_internal[raw_ref] = internal_comp_id

            component = Component(
                internal_id=internal_comp_id,
                name=comp_name,
                version=comp_version,
                purl=norm_purl,
                cpe=raw_cpe,
                supplier=supplier_name,
                ecosystem=purl_ecosystem or raw_comp.get("type"),
                license=lic_str,
                source_sbom_id=sbom_id,
                original_id=raw_ref,
                original_name=raw_name if raw_name else None,
                original_version=raw_version if raw_version else None,
                identity_status=identity_status
            )
            components.append(component)

        # Parse dependency graph
        for dep in raw_data.get("dependencies", []):
            if not isinstance(dep, dict):
                continue
            parent_ref = dep.get("ref")
            child_refs = dep.get("dependsOn", [])

            if not parent_ref or not isinstance(child_refs, list):
                continue

            parent_id = ref_to_internal.get(parent_ref)
            if not parent_id:
                warnings.append(f"Unresolved dependency parent ref: '{parent_ref}'")
                continue

            for child_ref in child_refs:
                child_id = ref_to_internal.get(child_ref)
                if not child_id:
                    warnings.append(f"Unresolved dependency child ref: '{child_ref}' in parent '{parent_ref}'")
                    continue

                dependencies.append(DependencyEdge(
                    source_component_id=parent_id,
                    target_component_id=child_id,
                    relationship_type="DEPENDS_ON",
                    scope=DependencyScope.RUNTIME,
                    raw_source_ref=parent_ref,
                    raw_target_ref=child_ref
                ))

        val_status = SBOMValidationStatus.VALID
        if errors:
            val_status = SBOMValidationStatus.MALFORMED
        elif warnings:
            val_status = SBOMValidationStatus.VALID_WITH_WARNINGS

        sbom = SBOM(
            internal_id=sbom_id,
            format=SBOMFormat.CYCLONEDX,
            format_version="JSON",
            spec_version=spec_version,
            document_name=raw_data.get("serialNumber"),
            author=author_str,
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
