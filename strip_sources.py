#!/usr/bin/env python3
"""
strip_sources.py — удаляет оригинальные .py файлы после Cython-компиляции.
ТОЛЬКО для подготовки дистрибутива. НЕ запускать в dev-окружении!

Usage: python strip_sources.py [--dry-run]
"""
import sys
import glob
from pathlib import Path

PROTECTED_MODULES = ['auditor/security/guard.py', 'auditor/security/posture_engine.py', 'auditor/security/taint_engine.py', 'auditor/security/validation_engine.py', 'auditor/security/report_sanity.py', 'auditor/core/engine.py', 'auditor/core/risk_taxonomy.py', 'auditor/core/policy.py', 'auditor/core/intake.py', 'auditor/core/baseline.py', 'auditor/ai/external_llm.py', 'auditor/ai/base.py', 'auditor/ai/factory.py', 'auditor/ai/local_llm.py', 'auditor/ai/rule_based.py', 'auditor/ai/templates.py', 'auditor/intelligence_lab/intelligence_engine.py', 'orchestrator.py', 'auditor/chain/chain_analyzer.py']

DRY_RUN = "--dry-run" in sys.argv

print("🔥 Source stripping for distribution")
if DRY_RUN:
    print("   (DRY RUN — no files will be deleted)")
print()

stripped = 0
skipped = 0

for py_file in PROTECTED_MODULES:
    py_path = Path(py_file)
    if not py_path.exists():
        continue

    # Проверяем что .so существует (иначе не удаляем!)
    so_files = list(py_path.parent.glob(py_path.stem + "*.so"))
    if not so_files:
        print(f"⚠️  SKIP (no .so found): {py_file}")
        skipped += 1
        continue

    print(f"   Strip: {py_file} → {so_files[0].name}")
    if not DRY_RUN:
        py_path.unlink()
    stripped += 1

print()
print(f"✅  Done: {stripped} stripped, {skipped} skipped (no .so)")
if DRY_RUN:
    print("   Run without --dry-run to actually delete files")
