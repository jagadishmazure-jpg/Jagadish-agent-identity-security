"""Agent identity security: posture for humans, workload identities and AI agents on Azure."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config"
DATA = ROOT / "data"
TENANT_DATA = DATA / "tenant"
DETECTIONS = ROOT / "detections"

__version__ = "0.1.0"
