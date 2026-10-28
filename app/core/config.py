"""Core configuration and settings for AutoSupplyGuard."""

from pathlib import Path
from pydantic import BaseModel

class Settings(BaseModel):
    PROJECT_NAME: str = "AutoSupplyGuard"
    VERSION: str = "0.1.0"
    DESCRIPTION: str = "Evidence-Driven Cybersecurity Assurance for Multi-Tier Automotive Supply Chains"

    # Base paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    RAW_DATA_DIR: Path = DATA_DIR / "raw"
    INTERIM_DATA_DIR: Path = DATA_DIR / "interim"
    PROCESSED_DATA_DIR: Path = DATA_DIR / "processed"
    SAMPLES_DIR: Path = DATA_DIR / "samples"
    SYNTHETIC_DIR: Path = DATA_DIR / "synthetic"
    MANIFESTS_DIR: Path = DATA_DIR / "manifests"

    # Evidence & Assurance thresholds
    EVIDENCE_FRESHNESS_DAYS: int = 90  # Default 90-day review freshness window
    STALE_WARNING_DAYS: int = 180      # Critical staleness threshold

    # Prioritisation weights (calibrated per research/metrics.md)
    WEIGHT_SEVERITY: float = 0.4
    WEIGHT_DEPENDENCY_IMPACT: float = 0.3
    WEIGHT_PRODUCT_CONTEXT: float = 0.3

settings = Settings()
