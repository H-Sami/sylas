"""Sylas - Structured Logging

Dual-handler logging: colored console output + JSON file for post-mortem analysis.
"""

import json
import logging
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict
from enum import Enum

try:
    from colorama import init as colorama_init, Fore, Style

    colorama_init(autoreset=True, strip=not sys.stdout.isatty())
    C = type(
        "Colors",
        (),
        {
            "RED": Fore.RED,
            "GREEN": Fore.GREEN,
            "YELLOW": Fore.YELLOW,
            "CYAN": Fore.CYAN,
            "MAGENTA": Fore.MAGENTA,
            "WHITE": Fore.WHITE,
            "RESET": Style.RESET_ALL,
            "BRIGHT": Style.BRIGHT,
        },
    )()
except ImportError:
    class C:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = BRIGHT = ""


class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class LogEntry:
    """Structured log entry for JSON output."""
    timestamp: str
    level: str
    logger: str
    message: str
    context: dict = field(default_factory=dict)
    exc_info: Optional[str] = None


class ColoredConsoleHandler(logging.Handler):
    """Handler that outputs colored messages to console."""

    def __init__(self):
        super().__init__()
        self._level_colors = {
            "DEBUG": C.CYAN,
            "INFO": C.GREEN,
            "WARNING": C.YELLOW,
            "ERROR": C.RED,
            "CRITICAL": C.RED + C.BRIGHT,
        }

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            level = record.levelname
            color = self._level_colors.get(level, C.WHITE)
            prefix = f"{color}[{level}]{C.RESET}" if level in self._level_colors else ""
            print(f"{prefix} {msg}" if prefix else msg)
        except (IOError, UnicodeEncodeError):
            self.handleError(record)


class JsonFileHandler(logging.Handler):
    """Handler that outputs structured JSON to file."""

    def __init__(self, log_dir: str = "agent/logs"):
        super().__init__()
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"agent_{timestamp}.jsonl"
        self._buffer: list[dict] = []

    def emit(self, record: logging.LogRecord):
        try:
            entry = LogEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                level=record.levelname,
                logger=record.name,
                message=record.getMessage(),
                context=getattr(record, "context", {}),
                exc_info=str(record.exc_info) if record.exc_info else None,
            )
            self._buffer.append(asdict(entry))

            if len(self._buffer) >= 10 or record.levelno >= logging.ERROR:
                self._flush()
        except (IOError, UnicodeEncodeError):
            self.handleError(record)

    def _flush(self):
        if self._buffer:
            with open(self.log_file, "a", encoding="utf-8") as f:
                for entry in self._buffer:
                    f.write(json.dumps(entry) + "\n")
            self._buffer.clear()

    def close(self):
        self._flush()
        super().close()


class SecurityAgentLogger:
    """Dual-handler logger for security remediation agent."""

    _instance: Optional["SecurityAgentLogger"] = None
    _lock: threading.Lock = threading.Lock()

    def __init__(
        self,
        name: str = "sylas",
        log_dir: str = "agent/logs",
        console_level: int = logging.INFO,
        file_level: int = logging.DEBUG,
    ):
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()

        console_handler = ColoredConsoleHandler()
        console_handler.setLevel(console_level)
        console_formatter = logging.Formatter("%(message)s")
        console_handler.setFormatter(console_formatter)

        file_handler = JsonFileHandler(log_dir)
        file_handler.setLevel(file_level)

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

        self._context: dict = {}

    @classmethod
    def get_instance(cls, **kwargs) -> "SecurityAgentLogger":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(**kwargs)
        return cls._instance

    def configure(
        self, log_dir: str = None, console_level: int = None, file_level: int = None
    ):
        if log_dir:
            self.log_dir = Path(log_dir)
            self.log_dir.mkdir(parents=True, exist_ok=True)
            for handler in self.logger.handlers:
                if isinstance(handler, JsonFileHandler):
                    handler.log_dir = self.log_dir

        if console_level:
            for handler in self.logger.handlers:
                if isinstance(handler, ColoredConsoleHandler):
                    handler.setLevel(console_level)

        if file_level:
            for handler in self.logger.handlers:
                if isinstance(handler, JsonFileHandler):
                    handler.setLevel(file_level)

    @classmethod
    def reset_instance(cls):
        with cls._lock:
            if cls._instance:
                for handler in cls._instance.logger.handlers:
                    handler.close()
                cls._instance.logger.handlers.clear()
            cls._instance = None

    def set_context(self, **kwargs):
        self._context.update(kwargs)

    def clear_context(self):
        self._context.clear()

    def _log(self, level: int, message: str, **kwargs):
        context = {**self._context, **kwargs}
        extra = {"context": context}
        self.logger.log(level, message, extra=extra)

    def debug(self, message: str, **kwargs):
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs):
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs):
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs):
        self._log(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs):
        self._log(logging.CRITICAL, message, **kwargs)

    def log_scanner_result(self, scanner: str, vulnerabilities: int, duration: float):
        self.info(
            f"Scanner '{scanner}' completed",
            scanner=scanner,
            vulnerabilities=vulnerabilities,
            duration_seconds=round(duration, 2),
        )

    def log_remediation(self, vuln_id: str, file_path: str, success: bool):
        level = logging.INFO if success else logging.ERROR
        self._log(
            level,
            f"Remediation {'succeeded' if success else 'failed'}",
            vulnerability_id=vuln_id,
            file_path=file_path,
            success=success,
        )

    def log_verification(self, vuln_id: str, passed: bool, tests_passed: bool):
        self.info(
            f"Verification {'passed' if passed else 'failed'}",
            vulnerability_id=vuln_id,
            passed=passed,
            tests_passed=tests_passed,
        )

    def log_git_operation(self, operation: str, branch: str, success: bool):
        level = logging.INFO if success else logging.ERROR
        self._log(
            level,
            f"Git {operation}",
            operation=operation,
            branch=branch,
            success=success,
        )

    def log_scan_started(self, scanner: str, target: str):
        self.info(
            f"Scan started: {scanner}",
            event="scan_started",
            scanner=scanner,
            target=target,
        )

    def log_scan_complete(self, scanner: str, vuln_count: int, vuln_ids: list):
        self.info(
            f"Scan complete: {scanner} found {vuln_count}",
            event="scan_complete",
            scanner=scanner,
            vulnerabilities_found=vuln_count,
            vulnerability_ids=vuln_ids[:50],
        )

    def log_pr_created(self, pr_number: int, pr_url: str, title: str):
        self.info(
            f"PR created: #{pr_number}",
            event="pr_created",
            pr_number=pr_number,
            pr_url=pr_url,
            title=title,
        )

    def log_error_with_traceback(self, error: Exception, context: dict):
        import traceback
        tb = "".join(traceback.format_tb(error.__traceback__))
        self.error(
            str(error),
            error_type=type(error).__name__,
            traceback=tb,
            **context,
        )


def get_logger(**kwargs) -> SecurityAgentLogger:
    """Convenience function to get logger instance."""
    return SecurityAgentLogger.get_instance(**kwargs)


def init_logging(
    name: str = "sylas",
    log_dir: str = "agent/logs",
    console_level: str = "INFO",
    file_level: str = "DEBUG",
) -> SecurityAgentLogger:
    """Initialize logging with specified levels."""
    levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }

    return SecurityAgentLogger(
        name=name,
        log_dir=log_dir,
        console_level=levels.get(console_level, logging.INFO),
        file_level=levels.get(file_level, logging.DEBUG),
    )
