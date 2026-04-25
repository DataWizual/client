#!/usr/bin/env python3
"""
clean_artifacts.py — Удаляет сгенерированные Cython файлы (.so, .c, .html)
и временные директории (build, __pycache__).

Usage:
    python clean_artifacts.py          # удалить всё без подтверждения
    python clean_artifacts.py --dry-run  # показать, что будет удалено
    python clean_artifacts.py --keep-so  # удалять .c и .html, но оставить .so
"""

import os
import sys
import shutil
from pathlib import Path

# Расширения для удаления (если не указан --keep-so)
EXTENSIONS = {".c", ".html"}
SO_EXTENSIONS = {".so", ".pyd", ".dll"}  # .dll на случай Windows

DIRS_TO_REMOVE = {"build", "__pycache__", "dist", "auditor.egg-info"}

def clean_artifacts(dry_run=False, keep_so=False):
    """Удаляет артефакты сборки Cython."""
    extensions = EXTENSIONS.copy()
    if not keep_so:
        extensions.update(SO_EXTENSIONS)

    root = Path(".")
    deleted_count = 0

    # Удаляем файлы по расширениям
    for ext in extensions:
        for file_path in root.rglob(f"*{ext}"):
            # Пропускаем, если файл находится внутри директории, которая будет удалена
            if any(part in DIRS_TO_REMOVE for part in file_path.parts):
                continue
            if dry_run:
                print(f"[DRY RUN] Would delete: {file_path}")
            else:
                file_path.unlink()
                print(f"Deleted: {file_path}")
            deleted_count += 1

    # Удаляем целые директории
    for dir_name in DIRS_TO_REMOVE:
        for dir_path in root.rglob(dir_name):
            if not dir_path.is_dir():
                continue
            if dry_run:
                print(f"[DRY RUN] Would remove dir: {dir_path}")
            else:
                shutil.rmtree(dir_path, ignore_errors=True)
                print(f"Removed dir: {dir_path}")
            deleted_count += 1

    if dry_run:
        print(f"\n[DRY RUN] Total {deleted_count} items would be deleted.")
    else:
        print(f"\n✅ Cleaned {deleted_count} items.")

if __name__ == "__main__":
    dry = "--dry-run" in sys.argv
    keep = "--keep-so" in sys.argv
    if dry:
        print("🔍 DRY RUN MODE — no files will be deleted")
    clean_artifacts(dry_run=dry, keep_so=keep)