"""Path Safety Validation - Prevent catastrophic deletions and modifications."""

from pathlib import Path
from .constants import PROJECT_ROOT, ALLOWED_DELETE_DIRS, PROTECTED_PROJECT_DIRS


class PathSafetyError(Exception):
    """Raised when a path operation is blocked for safety."""


def is_path_safe_to_delete(path: str, allow_in_project: bool = False) -> bool:
    """Validate that a path is safe to delete.

    Args:
        path: Path to validate
        allow_in_project: If True, allows deletion within project (with safeguards).
                          If False, only allows deletion within ALLOWED_DELETE_DIRS.

    Returns:
        True if path is safe

    Raises:
        PathSafetyError: If path is unsafe to delete
    """
    p = Path(path).resolve()

    if not p.exists():
        return True

    path_str = str(p)

    if path_str.strip() in ["", ".", "./", ".\\"]:
        raise PathSafetyError("Cannot delete current directory")

    drive_letter = (
        path_str[0].upper() if len(path_str) > 1 and path_str[1] == ":" else None
    )
    if drive_letter:
        drive_paths = [f"{drive_letter}:\\", f"{drive_letter}:/"]
        path_upper = path_str.upper()
        normalized_path = path_upper.rstrip("\\/")
        if any(normalized_path == d.upper().rstrip("\\/") for d in drive_paths):
            raise PathSafetyError(f"Cannot delete drive root: {path}")

    for dangerous in ["\\Windows\\", "/Windows/", "\\Program Files", "/Program Files"]:
        if dangerous.replace("\\", "/") in path_str.replace("\\", "/"):
            raise PathSafetyError(f"Cannot delete system directory: {path}")

    if allow_in_project:
        try:
            rel_path = p.relative_to(PROJECT_ROOT)

            for part in rel_path.parts:
                if part in PROTECTED_PROJECT_DIRS:
                    raise PathSafetyError(
                        f"Cannot delete protected project directory: {path}"
                    )

            if p == PROJECT_ROOT:
                raise PathSafetyError("Cannot delete project root")

        except ValueError:
            pass
    else:
        allowed = False
        for parent in [p] + list(p.parents):
            if parent.name.lower() in ALLOWED_DELETE_DIRS:
                allowed = True
                break
        if not allowed:
            if p.is_dir():
                allowed_list = ", ".join(sorted(ALLOWED_DELETE_DIRS))
                raise PathSafetyError(
                    f"Path '{p}' not in allowed directories. "
                    f"Only delete from: {allowed_list}"
                )

    return True


def is_path_safe_to_modify(path: str) -> bool:
    """Validate that a path is safe to modify (edit/write).

    Unlike is_path_safe_to_delete which guards against catastrophic deletion,
    this function allows editing within the project while still protecting
    critical directories (.git, agent code, configs, etc.).

    Args:
        path: Path to validate for editing

    Returns:
        True if path is safe to modify

    Raises:
        PathSafetyError: If path is unsafe to modify
    """
    if not path:
        raise PathSafetyError("Empty path")

    p = Path(path).resolve()

    if not p.exists():
        return True

    path_str = str(p)

    # Never allow modifying system directories
    for dangerous in ["\\Windows\\", "/Windows/", "\\Program Files", "/Program Files"]:
        if dangerous.replace("\\", "/") in path_str.replace("\\", "/"):
            raise PathSafetyError(f"Cannot modify system directory: {path}")

    try:
        rel_path = p.relative_to(PROJECT_ROOT)

        # Protect critical agent/config infrastructure
        for part in rel_path.parts:
            if part in (".git",):
                raise PathSafetyError(
                    f"Cannot modify protected directory: {path}"
                )

        if p == PROJECT_ROOT:
            raise PathSafetyError("Cannot modify project root")

    except ValueError:
        pass

    return True


def safe_delete(path: str, allow_in_project: bool = False) -> bool:
    """Safely delete a path after validation.

    Args:
        path: Path to delete
        allow_in_project: If False, only allows deletion within ALLOWED_DELETE_DIRS

    Returns:
        True if deleted successfully

    Raises:
        PathSafetyError: If path is unsafe
    """
    import shutil

    try:
        is_path_safe_to_delete(path, allow_in_project)
    except PathSafetyError:
        raise

    p = Path(path)
    if p.exists():
        shutil.rmtree(path, ignore_errors=True)
        return True

    return False
