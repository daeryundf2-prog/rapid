#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
confine_path.py — Lazy 공통 경로 격리 참조 구현 (Python)

규칙 (모든 Lazy 레포 동일):
  1. 입력 경로의 모든 컴포넌트에 대해 symlink/reparse point 거부 (lstat)
  2. realpath로 canonicalize
  3. 해소된 경로가 허용 root 내부인지 검증
  4. TOCTOU 방지: 반환된 경로 사용 시에도 open 시점 재검증 권장

imported manifest의 경로는 권한 부여가 아니라 데이터다 — 이 함수를 통과하기
전에는 파일을 열거나 쓰지 않는다.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path


class PathConfinementError(Exception):
    pass


def _has_symlink_component(path: Path, root: Path) -> bool:
    """root 이후 컴포넌트 중 symlink가 있으면 True."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        # root 바깥이면 별도 검증에서 걸림 — 여기선 절대경로 기준으로 검사
        rel = path
    current = root if path.is_relative_to(root) else Path(path.anchor)
    for part in rel.parts:
        current = current / part
        try:
            if stat.S_ISLNK(os.lstat(current).st_mode):
                return True
        except FileNotFoundError:
            # 마지막 컴포넌트는 아직 없을 수 있다(생성 대상) — 중간 컴포넌트만 검사
            return False
    return False


def confine_path(p: str | Path, allowed_root: str | Path,
                 *, must_exist: bool = False) -> Path:
    """경로를 허용 root 안으로 격리한다. 위반 시 PathConfinementError.

    - allowed_root 자체는 canonicalize한다.
    - p는 lstat 기반 symlink 검사 → realpath → root 내부 검증 순서.
    - must_exist=True면 실재하지 않는 경로를 거부한다.
    """
    root = Path(allowed_root).resolve()
    if not root.is_dir():
        raise PathConfinementError(f"허용 root가 디렉터리가 아닙니다: {root}")

    cand = Path(p)
    if not cand.is_absolute():
        cand = root / cand

    # 1) symlink 컴포넌트 거부 (해소 전 원본 기준)
    if _has_symlink_component(cand, root):
        raise PathConfinementError(f"symlink 컴포넌트 포함 경로 거부: {p}")

    # 2) canonicalize → 3) root 내부 검증
    resolved = cand.resolve()
    if must_exist and not resolved.exists():
        raise PathConfinementError(f"경로가 존재하지 않습니다: {resolved}")
    try:
        resolved.relative_to(root)
    except ValueError:
        raise PathConfinementError(
            f"허용 root 밖 경로 거부: {resolved} (root: {root})")
    return resolved


def open_no_follow(path: str | Path, flags: int = os.O_RDONLY,
                   *, allowed_root: str | Path) -> int:
    """TOCTOU 방지를 위해 O_NOFOLLOW로 여는 헬퍼. fd를 반환한다."""
    resolved = confine_path(path, allowed_root, must_exist=True)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    return os.open(resolved, flags | nofollow)
