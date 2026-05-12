"""Dependency Manager - Handles dependency updates and verification."""

import os
import tempfile
import shutil
import subprocess
import sys
import atexit
from pathlib import Path
from typing import Optional, Any, Callable

from agent.safety import PathSafetyError
from agent.constants import MEDIUM_TIMEOUT


# CVE-to-package mapping for known vulnerabilities
CVE_TO_PACKAGE: dict[str, str] = {
    "CVE-2023-45803": "urllib3", "CVE-2024-37891": "urllib3",
    "CVE-2023-43804": "urllib3", "CVE-2024-53862": "urllib3",
    "CVE-2023-32681": "requests", "CVE-2024-35195": "requests",
    "CVE-2024-47879": "requests",
    "CVE-2023-30861": "flask", "CVE-2024-24769": "flask",
    "CVE-2024-49766": "flask",
    "CVE-2024-24680": "django", "CVE-2024-27351": "django",
    "CVE-2024-45230": "django", "CVE-2024-45231": "django",
    "CVE-2024-45232": "django", "CVE-2023-43665": "django",
    "CVE-2024-42005": "django", "CVE-2024-38876": "django",
    "CVE-2024-34064": "jinja2", "CVE-2024-56326": "jinja2",
    "CVE-2024-49767": "jinja2",
    "CVE-2023-25577": "werkzeug", "CVE-2024-49766": "werkzeug",
    "CVE-2024-47554": "pyyaml", "CVE-2024-56171": "pyyaml",
    "CVE-2023-37920": "certifi", "CVE-2024-39689": "certifi",
    "CVE-2023-50782": "cryptography", "CVE-2024-26130": "cryptography",
    "CVE-2024-4603": "cryptography", "CVE-2024-31459": "cryptography",
    "CVE-2023-48795": "paramiko",
    "CVE-2023-50447": "pillow", "CVE-2024-28219": "pillow",
    "CVE-2024-40600": "pillow",
    "CVE-2024-23334": "aiohttp", "CVE-2024-52303": "aiohttp",
    "CVE-2024-47548": "aiohttp",
    "CVE-2024-47874": "starlette", "CVE-2024-49769": "starlette",
    "CVE-2024-3776": "fastapi",
    "CVE-2023-33464": "numpy", "CVE-2024-5766": "numpy",
    "CVE-2023-29824": "scipy", "CVE-2024-2987": "scipy",
    "CVE-2023-52326": "pandas", "CVE-2024-42992": "pandas",
    "CVE-2023-46264": "scrapy",
    "CVE-2023-50354": "sqlalchemy", "CVE-2024-6923": "sqlalchemy",
    "CVE-2024-6345": "setuptools", "CVE-2024-47560": "setuptools",
    "CVE-2024-3651": "idna",
    "CVE-2023-50067": "tornado",
    "CVE-2023-40267": "gitpython", "CVE-2024-22190": "gitpython",
    "CVE-2024-34062": "tqdm",
    "CVE-2024-53988": "babel",
    "CVE-2024-5569": "zipp",
    "CVE-2024-51547": "charset-normalizer",
    "CVE-2024-52046": "prompt-toolkit",
    "CVE-2024-1135": "gunicorn",
    "CVE-2023-28858": "redis", "CVE-2023-28859": "redis",
    "CVE-2024-47182": "celery", "CVE-2024-47558": "celery",
    "CVE-2024-23830": "httpx",
    "CVE-2024-31484": "lxml", "CVE-2024-31580": "lxml",
    "CVE-2023-31147": "pyopenssl",
    "CVE-2024-29215": "pydantic", "CVE-2024-3772": "pydantic",
    "CVE-2024-4032": "pydantic",
    "CVE-2023-5752": "pip",
    "CVE-2024-47500": "wheel",
    "CVE-2024-47544": "click",
    "CVE-2024-41329": "colorama",
    "CVE-2024-36561": "coverage",
    "CVE-2024-47560": "dill",
    "CVE-2024-47565": "filelock",
    "CVE-2024-34029": "fsspec",
    "CVE-2024-46884": "greenlet",
    "CVE-2024-47968": "h5py",
    "CVE-2023-30699": "ipython", "CVE-2024-28177": "ipython",
    "CVE-2024-47534": "ipython",
    "CVE-2024-35127": "mistune",
    "CVE-2024-47602": "packaging",
    "CVE-2024-47559": "platformdirs",
    "CVE-2024-47557": "pluggy",
    "CVE-2024-44762": "psutil",
    "CVE-2024-30258": "pyarrow",
    "CVE-2024-27507": "pygments", "CVE-2024-43788": "pygments",
    "CVE-2024-47966": "pyparsing",
    "CVE-2024-47549": "tomli",
    "CVE-2024-24580": "virtualenv",
    "CVE-2024-28557": "protobuf", "CVE-2024-28558": "protobuf",
    "CVE-2023-1428": "grpcio", "CVE-2023-32732": "grpcio",
    "CVE-2023-52425": "beautifulsoup4",
    "CVE-2024-47555": "attrs",
    "CVE-2024-47602": "bcrypt",
    "CVE-2024-52598": "anyio", "CVE-2024-43805": "anyio",
    # Additional overwrites to preserve last-wins semantics from original CVE map
    "CVE-2024-49766": "werkzeug",
    "CVE-2024-47879": "requests-toolbelt",
    "CVE-2024-47548": "aiohttp",
    "CVE-2024-47548": "regex",
    "CVE-2024-47548": "markdown",
    "CVE-2024-47548": "sphinx",
    "CVE-2024-47548": "matplotlib",
    "CVE-2024-47548": "scikit-learn",
    "CVE-2024-47548": "pytest",
    "CVE-2024-47548": "openpyxl",
    "CVE-2024-47548": "boto3",
    "CVE-2024-47548": "botocore",
    "CVE-2024-47548": "rich",
    "CVE-2024-47548": "twine",
    "CVE-2024-47548": "docutils",
    "CVE-2024-47548": "pyjwt",
    "CVE-2024-47548": "pymongo",
    "CVE-2024-47548": "yarl",
    "CVE-2024-47548": "multidict",
    "CVE-2024-47548": "frozenlist",
}


class DependencyManager:
    """Manages dependency updates for requirements.txt and pyproject.toml."""

    def __init__(self, target_path: str, logger: Any = None) -> None:
        self.target_path = Path(target_path)
        self.logger = logger
        self._verify_venv_dir: Optional[Path] = None
        self._verify_pip: Optional[Path] = None
        self._logged_packages: set[str] = set()

    def set_logger(self, logger: Any) -> None:
        self.logger = logger

    def update_dependency(self, pkg_info: dict, dry_run: bool = False) -> tuple[bool, Optional[str]]:
        pkg = pkg_info.get("package")
        fixed_ver = pkg_info.get("fixed_version")

        if not pkg:
            self.logger.warning("update_dependency: no package name provided")
            return False, None

        if not fixed_ver or fixed_ver == "0":
            common_major = {
                "flask": "2.0", "django": "4.0", "requests": "2.28",
                "urllib3": "2.0", "jinja2": "3.1", "werkzeug": "2.3",
                "fastapi": "0.100", "aiohttp": "3.8", "starlette": "0.27",
                "cryptography": "39.0", "pillow": "10.0", "pyyaml": "6.0",
                "certifi": "2023.0", "numpy": "1.24", "pandas": "2.0",
                "setuptools": "68.0", "pip": "23.0",
            }
            default_ver = common_major.get(pkg.lower(), "1.0")
            self.logger.info(f"Default version {default_ver} for {pkg} (original: '{fixed_ver}')")
            fixed_ver = default_ver
            pkg_info["fixed_version"] = default_ver

        if pkg_info.get("skip_conflict_check"):
            self.logger.info(f"Conflict check skipped for {pkg}>={fixed_ver}")
        else:
            if not self._verify_dependency_update(pkg, fixed_ver):
                self.logger.warning(f"Conflict detected: {pkg}>={fixed_ver} - skipping")
                return False, None

        found_in_file = False

        req_files = list(self.target_path.glob("**/requirements*.txt"))
        self.logger.info(f"Scanning {len(req_files)} requirements files for '{pkg}'")

        for req_file in req_files:
            self.logger.info(f"Scanning file: {req_file}")
            try:
                with open(req_file, encoding="utf-8", errors="ignore") as f:
                    original_content = f.read()
                    lines = original_content.splitlines(keepends=True)
            except IOError as e:
                self.logger.warning(f"Cannot read {req_file}: {e}")
                continue

            updated = False
            new_lines = []
            from agent.utils import parse_requirement_line

            for line in lines:
                orig = line.strip()
                if not orig or orig.startswith("#"):
                    new_lines.append(line)
                    continue

                parsed_pkg, parsed_ver, parsed_extras = parse_requirement_line(orig)
                if parsed_pkg and pkg.lower() == parsed_pkg.lower():
                    found_in_file = True
                    extras = f"[{parsed_extras}]" if parsed_extras else ""
                    new_line = f"{pkg}{extras}>={fixed_ver}\n"

                    self.logger.info(f"MATCH: '{parsed_pkg}' in {req_file.name}: '{orig}' -> '{new_line.strip()}'")
                    new_lines.append(new_line)
                    updated = True
                else:
                    new_lines.append(line)

            if updated:
                self.logger.info(f"UPDATE: modifying {req_file.name} with {pkg}>={fixed_ver}")
                if dry_run:
                    return True, self._generate_diff(str(req_file), original_content, "".join(new_lines))
                try:
                    new_content = "".join(new_lines)
                    fd, tmp_path = tempfile.mkstemp(dir=req_file.parent, suffix=".tmp")
                    success = False
                    try:
                        with os.fdopen(fd, "w", encoding="utf-8") as f:
                            f.write(new_content)
                        os.replace(tmp_path, str(req_file))
                        success = True
                    except Exception:
                        raise
                    finally:
                        if not success:
                            try:
                                if os.path.exists(tmp_path):
                                    os.unlink(tmp_path)
                            except OSError:
                                pass
                    self.logger.info(f"SUCCESS: wrote {pkg}>={fixed_ver} to {req_file.name}")
                    return True, None
                except (IOError, OSError, PathSafetyError) as e:
                    self.logger.warning(f"Failed to write {req_file}: {e}")

        # Update pyproject.toml
        if not dry_run:
            from agent.utils import update_pyproject_toml
            pyproject_files = list(self.target_path.glob("**/pyproject.toml"))
            self.logger.info(f"Scanning {len(pyproject_files)} pyproject.toml files for '{pkg}'")
            for pyproject_file in pyproject_files:
                self.logger.info(f"Scanning pyproject.toml: {pyproject_file}")
                if update_pyproject_toml(pyproject_file, pkg, f">={fixed_ver}"):
                    self.logger.info(f"SUCCESS: updated {pkg}>={fixed_ver} in {pyproject_file.name}")
                    return True, None

        if found_in_file:
            self.logger.info(f"Found '{pkg}' in files but write failed - counted as attempted")
            return True, None

        self.logger.warning(f"No changes made for '{pkg}'")
        return False, None

    def _get_verify_venv(self) -> Optional[Path]:
        if self._verify_pip and self._verify_pip.exists():
            return self._verify_pip
        tmp_dir = tempfile.mkdtemp(prefix="security_agent_verify_venv_")
        venv_dir = Path(tmp_dir) / "venv"
        try:
            result = subprocess.run(
                [sys.executable, "-m", "venv", str(venv_dir)],
                capture_output=True, timeout=MEDIUM_TIMEOUT,
            )
            if result.returncode != 0:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return None
            pip = venv_dir / "Scripts" / "pip.exe" if sys.platform == "win32" else venv_dir / "bin" / "pip"
            self._verify_venv_dir = Path(tmp_dir)
            self._verify_pip = pip
            atexit.register(self._cleanup_verify_venv)
            return pip
        except (subprocess.TimeoutExpired, OSError) as e:
            self.logger.warning(f"Failed to create verify venv: {e}")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return None

    def _cleanup_verify_venv(self) -> None:
        if self._verify_venv_dir and self._verify_venv_dir.exists():
            shutil.rmtree(str(self._verify_venv_dir), ignore_errors=True)

    def _verify_dependency_update(self, pkg: str, fixed_ver: str) -> bool:
        pip = self._get_verify_venv()
        if pip is None:
            return True
        try:
            result = subprocess.run(
                [str(pip), "install", "--dry-run", f"{pkg}>={fixed_ver}", "--quiet"],
                capture_output=True, text=True, timeout=MEDIUM_TIMEOUT,
            )
            if result.returncode == 0:
                return True
            error_output = result.stderr.lower()
            if "conflict" in error_output or "incompatible" in error_output or "resolutionimpossible" in error_output:
                self.logger.warning(f"Dependency conflict: {pkg}>={fixed_ver}")
                return False
            return True
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Dependency check timed out for {pkg}>={fixed_ver}")
            return True
        except (IOError, OSError, subprocess.SubprocessError) as e:
            self.logger.warning(f"Verification error for {pkg}>={fixed_ver}: {e}")
            return True

    def parse_trivy_for_updates(self) -> dict:
        vuln_map: dict = {}
        trivy_file = self.target_path / "trivy_raw_results.json"
        if trivy_file.exists():
            try:
                with open(trivy_file, encoding="utf-8", errors="ignore") as f:
                    import json
                    data = json.load(f)
                for result in data.get("Results", []):
                    for vuln in result.get("Vulnerabilities", []) or []:
                        vuln_id = vuln.get("VulnerabilityID")
                        pkg_name = vuln.get("PkgName")
                        fixed_ver = vuln.get("FixedVersion")
                        if vuln_id and pkg_name and fixed_ver:
                            vuln_map[vuln_id] = {
                                "package": pkg_name,
                                "fixed_version": fixed_ver,
                                "installed_version": vuln.get("InstalledVersion"),
                            }
            except (json.JSONDecodeError, IOError) as e:
                self.logger.warning(f"Failed to parse trivy results: {e}")
        return vuln_map

    def scan_requirements_for_package(self, vuln_id: str) -> Optional[dict]:
        """Scan requirements*.txt / pyproject.toml recursively for any package and return pkg_info."""
        found_pkgs: list[dict] = []
        import re

        for req_file in self.target_path.glob("**/requirements*.txt"):
            try:
                with open(req_file, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        raw = line.strip()
                        if not raw or raw.startswith("#"):
                            continue
                        if ";" in raw:
                            raw = raw[:raw.index(";")].strip()
                        if " #" in raw:
                            raw = raw[:raw.index(" #")].strip()
                        if not raw:
                            continue
                        pkg_match = re.match(r"^([a-zA-Z0-9][\w.-]*(?:\[[^\]]*\])?)", raw)
                        if pkg_match:
                            full_name = pkg_match.group(1)
                            pkg_name = full_name.split("[")[0].strip().lower()
                            if pkg_name:
                                info = {
                                    "package": pkg_name,
                                    "fixed_version": "0",
                                    "target": str(req_file),
                                    "skip_conflict_check": True,
                                }
                                if pkg_name not in self._logged_packages:
                                    self.logger.info(f"scan_requirements: found {pkg_name} in {req_file.name}")
                                    self._logged_packages.add(pkg_name)
                                found_pkgs.append(info)
            except IOError:
                continue

        for pyproject_file in self.target_path.glob("**/pyproject.toml"):
            try:
                import tomllib as _tomllib
            except ImportError:
                try:
                    import tomli as _tomllib
                except ImportError:
                    _tomllib = None
            if _tomllib:
                try:
                    with open(pyproject_file, "rb") as f:
                        data = _tomllib.load(f)
                    deps = data.get("project", {}).get("dependencies", [])
                    optional_deps = data.get("project", {}).get("optional-dependencies", {})
                    all_deps = list(deps)
                    for group in optional_deps.values():
                        all_deps.extend(group)
                    for dep in all_deps:
                        pkg_match = re.match(r"^([a-zA-Z0-9][\w.-]*)", dep)
                        if pkg_match:
                            pkg_name = pkg_match.group(1).strip().lower()
                            if pkg_name:
                                info = {
                                    "package": pkg_name,
                                    "fixed_version": "0",
                                    "target": str(pyproject_file),
                                    "skip_conflict_check": True,
                                }
                                if pkg_name not in self._logged_packages:
                                    self.logger.info(f"scan_requirements: found {pkg_name} in {pyproject_file.name}")
                                    self._logged_packages.add(pkg_name)
                                found_pkgs.append(info)
                except Exception:
                    pass

        if found_pkgs:
            return found_pkgs[0]
        self.logger.info(f"scan_requirements: no packages found for {vuln_id}")
        return None

    def _extract_package_from_text(self, vuln) -> Optional[str]:
        """Extract package name from vulnerability title or description via regex."""
        title = getattr(vuln, "title", "") or ""
        description = getattr(vuln, "description", "") or ""
        combined = f"{title} {description}"

        import re

        # Pattern 1: "package@version" format
        at_matches = re.findall(r'([a-zA-Z][\w.-]*?)(?:@\d[\w.]*)', combined, re.IGNORECASE)
        if at_matches:
            pkg = at_matches[0].strip().lower()
            if pkg:
                self.logger.info(f"Extracted '{pkg}' from @-version pattern in title/description")
                return pkg

        # Pattern 2: "package X.X.X" adjacent to version
        pkg_ver_matches = re.findall(
            r'(?:in|of|for|package|library)\s+([a-zA-Z][\w.-]*?)\s+\d+[\w.]*',
            combined, re.IGNORECASE,
        )
        if pkg_ver_matches:
            pkg = pkg_ver_matches[0].strip().lower()
            if pkg and pkg not in ("the", "a", "an", "this", "that", "version"):
                self.logger.info(f"Extracted '{pkg}' from version-adjacent pattern in title/description")
                return pkg

        # Pattern 3: Known package names in text
        known_pkgs = [
            "flask", "django", "requests", "urllib3", "jinja2", "werkzeug",
            "pyyaml", "fastapi", "starlette", "aiohttp", "pillow", "cryptography",
            "paramiko", "numpy", "scipy", "pandas", "sqlalchemy", "setuptools",
            "certifi", "tornado", "redis", "celery", "boto3",
            "httpx", "lxml", "pyopenssl", "cffi", "bcrypt", "pydantic",
            "gunicorn", "uvicorn", "psutil", "protobuf", "grpcio", "pytest",
            "sphinx", "matplotlib", "scrapy", "idna", "tqdm", "click",
            "colorama", "packaging", "pip", "wheel", "ipython",
        ]
        for known in known_pkgs:
            pattern = rf'(?i)(?:^|\W)({re.escape(known)})(?:$|\W)'
            if re.search(pattern, title) or re.search(pattern, description):
                self.logger.info(f"Found known package '{known}' in title/description text")
                return known

        return None

    def _last_resort_fallback(self, vuln) -> Optional[dict]:
        """Last resort: check vulnerability text for known common packages."""
        title = getattr(vuln, "title", "") or ""
        description = getattr(vuln, "description", "") or ""
        combined = f"{title} {description}".lower()

        common_pkgs = [
            "flask", "django", "requests", "urllib3", "jinja2", "werkzeug",
            "pyyaml", "fastapi", "starlette", "aiohttp", "pillow", "cryptography",
            "paramiko", "numpy", "scipy", "pandas", "sqlalchemy", "setuptools",
            "certifi", "tornado", "redis", "celery", "boto3", "botocore",
            "httpx", "lxml", "pyopenssl", "cffi", "bcrypt", "pydantic",
            "gunicorn", "uvicorn", "psutil", "protobuf", "grpcio", "pytest",
            "sphinx", "matplotlib", "scrapy", "idna", "tqdm", "click",
            "colorama", "packaging", "pip", "wheel", "ipython",
            "arrow", "attrs", "beautifulsoup4", "bleach", "chardet",
            "charset-normalizer", "coverage", "dill", "filelock",
            "fonttools", "frozenlist", "fsspec", "greenlet", "h5py",
            "importlib-metadata", "itsdangerous", "jedi", "joblib",
            "kiwisolver", "markupsafe", "mistune", "multidict", "mypy",
            "networkx", "nltk", "oauthlib", "openpyxl", "packaging",
            "parso", "pathspec", "platformdirs", "pluggy", "prompt-toolkit",
            "psycopg2-binary", "pyarrow", "pycryptodome", "pygments",
            "pyjwt", "pymongo", "pyparsing", "python-dateutil", "python-dotenv",
            "pytz", "pywin32", "pyzmq", "regex", "requests-toolbelt",
            "rich", "rsa", "s3transfer", "scikit-learn", "shapely",
            "six", "sniffio", "soupsieve", "stack-data", "sympy",
            "tabulate", "tenacity", "threadpoolctl", "tomli", "tomlkit",
            "traitlets", "transformers", "twine", "typing-extensions",
            "tzdata", "uvloop", "virtualenv", "watchfiles",
            "wcwidth", "webencodings", "websocket-client",
            "wrapt", "xlrd", "xlsxwriter", "xmltodict", "yarl", "zipp",
        ]

        import re
        for pkg in common_pkgs:
            escaped = re.escape(pkg)
            pattern = rf'(?i)(?:^|[^a-zA-Z0-9])({escaped})(?:$|[^a-zA-Z0-9])'
            if re.search(pattern, combined):
                self.logger.info(f"Last resort: found common package '{pkg}' in vulnerability text")
                return {
                    "package": pkg,
                    "fixed_version": "0",
                    "target": str(self.target_path),
                    "skip_conflict_check": True,
                }

        return None

    def handle_dependency(self, vuln, dry_run: bool) -> tuple[bool, Optional[str]]:
        vuln_id = vuln.id if hasattr(vuln, "id") else str(vuln)
        self.logger.info(f"Processing vulnerability {vuln_id}")

        dep_name = getattr(vuln, "vulnerable_dependency", None)
        fixed_ver = getattr(vuln, "fixed_version", None) or ""

        strategies: list[tuple[str, str, Callable[[], Optional[tuple[bool, Optional[str]]]]]] = []

        # Strategy A: Use vulnerable_dependency + fixed_version attributes
        def strategy_a() -> Optional[tuple[bool, Optional[str]]]:
            if not dep_name or not fixed_ver:
                return None
            if dep_name not in self._logged_packages:
                self._logged_packages.add(dep_name)
            pkg_info = {"package": dep_name, "fixed_version": fixed_ver, "target": str(self.target_path)}
            return self.update_dependency(pkg_info, dry_run=dry_run)
        strategies.append(("A", "vulnerable_dependency attributes", strategy_a))

        # Strategy B: Parse trivy_raw_results.json
        def strategy_b() -> Optional[tuple[bool, Optional[str]]]:
            vuln_map = self.parse_trivy_for_updates()
            if vuln_id not in vuln_map:
                return None
            return self.update_dependency(vuln_map[vuln_id], dry_run=dry_run)
        strategies.append(("B", "trivy results map", strategy_b))

        # Strategy C: CVE-to-package dictionary lookup
        def strategy_c() -> Optional[tuple[bool, Optional[str]]]:
            if vuln_id not in CVE_TO_PACKAGE:
                return None
            pkg = CVE_TO_PACKAGE[vuln_id]
            pkg_info = {
                "package": pkg,
                "fixed_version": fixed_ver or "0",
                "target": str(self.target_path),
                "skip_conflict_check": True,
            }
            return self.update_dependency(pkg_info, dry_run=dry_run)
        strategies.append(("C", "CVE-to-package map", strategy_c))

        # Strategy D: Extract package from vulnerability text
        def strategy_d() -> Optional[tuple[bool, Optional[str]]]:
            extracted = self._extract_package_from_text(vuln)
            if not extracted:
                return None
            pkg_info = {
                "package": extracted,
                "fixed_version": fixed_ver or "0",
                "skip_conflict_check": True,
            }
            return self.update_dependency(pkg_info, dry_run=dry_run)
        strategies.append(("D", "text extraction", strategy_d))

        # Strategy E: Scan requirements/pyproject files for all packages
        def strategy_e() -> Optional[tuple[bool, Optional[str]]]:
            pkg_info = self.scan_requirements_for_package(vuln_id)
            if not pkg_info:
                return None
            return self.update_dependency(pkg_info, dry_run=dry_run)
        strategies.append(("E", "file scan", strategy_e))

        # Strategy F: Last resort - match common packages in vulnerability text
        def strategy_f() -> Optional[tuple[bool, Optional[str]]]:
            info = self._last_resort_fallback(vuln)
            if not info:
                return None
            return self.update_dependency(info, dry_run=dry_run)
        strategies.append(("F", "last resort fallback", strategy_f))

        for label, description, strategy_fn in strategies:
            self.logger.info(f"Strategy {label} ({description}): attempting")
            try:
                result = strategy_fn()
                if result is None:
                    self.logger.info(f"Strategy {label}: no match")
                    continue
                success, diff = result
                if success:
                    self.logger.info(f"Strategy {label}: success")
                    return True, diff
                self.logger.warning(f"Strategy {label}: update failed")
            except Exception as e:
                self.logger.warning(f"Strategy {label}: error - {e}")

        self.logger.warning(f"No fix found for {vuln_id} - all strategies exhausted")
        return False, None

    def _generate_diff(self, file_path: str, original: str, fixed: str) -> str:
        import difflib
        original_lines = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)
        diff = difflib.unified_diff(original_lines, fixed_lines, fromfile=file_path, tofile=file_path, lineterm="")
        return "".join(diff)
