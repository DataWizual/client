"""
CRUD Operations Bridge - Auditor Core Professional.
Optimized for high-speed batch processing of security scan results.
"""

import logging
from typing import List, Iterable, Optional
import uuid
from sqlalchemy.orm import Session
from sqlalchemy import func, insert
from pathlib import Path

# Updated models and types
from auditor.core.engine import Finding
from auditor.core.policy import Decision
from auditor.database import models

logger = logging.getLogger(__name__)


def _sanitize(value: object) -> object:
    """Last-resort NUL-byte sanitizer before DB insert.
    Runs even if engine.py already cleaned — defence in depth."""
    return value.replace("", "") if isinstance(value, str) else value


class CrudBridge:
    """
    Handles database interactions for scan persistence and policy retrieval.
    Implements optimized batch processing for high-volume security data.
    """

    def __init__(self, db: Session):
        self.db = db

    def get_active_rules(self, project_id: uuid.UUID) -> List[models.BaselineRule]:
        """
        Retrieves active baseline rules for false positive filtering.
        """
        return (
            self.db.query(models.BaselineRule)
            .filter(
                models.BaselineRule.project_id == project_id,
                models.BaselineRule.is_active.is_(True),
            )
            .all()
        )

    def persist_scan_results(
        self,
        project_id: uuid.UUID,
        findings: Iterable[Finding],
        decision: Decision,
        batch_size: int = 500,
    ) -> Optional[models.ScanRecord]:
        db = self.db
        findings_list = list(findings)
        if not findings_list:
            logger.info(
                "Database: No findings to persist. Skipping scan record creation."
            )
            return None

        try:
            with db.begin_nested():

                db_scan = models.ScanRecord(
                    project_id=project_id,
                    status="COMPLETED",
                    decision_action=getattr(decision, "action", None),
                    rationale=getattr(decision, "rationale", None),
                )
                db.add(db_scan)
                db.flush()

                findings_to_save = []

                for f in findings_list:

                    def _clean(v: object) -> object:
                        if not isinstance(v, str):
                            return v
                        v = v.replace("\x00", "")
                        return "".join(
                            ch if (ch >= " " or ch in "\t\n\r") else " " for ch in v
                        )

                    findings_to_save.append(
                        {
                            "scan_id": db_scan.id,
                            "rule_id": _clean(f.rule_id),
                            "file_path": _clean(f.file_path),
                            "line": f.line,
                            "severity": _clean(f.severity),
                            "cvss_score": getattr(f, "cvss_score", 0.0),
                            "description": _clean(
                                str(getattr(f, "description", "") or "")
                            ),
                        }
                    )

                    if len(findings_to_save) >= batch_size:
                        db.execute(insert(models.FindingRecord), findings_to_save)
                        findings_to_save = []

                if findings_to_save:
                    db.execute(insert(models.FindingRecord), findings_to_save)

            return db_scan

        except Exception:
            logger.exception("Database persistence failed")
            raise

    @staticmethod
    def create_project(db: Session, project_id, client_id, name: str):
        """Creates a new project record in the system."""
        new_project = models.Project(
            id=project_id,
            client_id=client_id,
            name=name,
        )

        with db.begin():
            db.add(new_project)

        return new_project
