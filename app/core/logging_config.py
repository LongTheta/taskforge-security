"""Structured JSON logging for TaskForge Security."""

import logging
import sys
from typing import Any

from pythonjsonlogger import json


class TaskForgeJsonFormatter(json.JsonFormatter):
    """Custom JSON formatter with request context support."""

    def add_fields(self, log_record: dict[str, Any], record: logging.LogRecord, message_dict: dict[str, Any]) -> None:
        super().add_fields(log_record, record, message_dict)
        log_record["level"] = record.levelname
        log_record["logger"] = record.name
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "request_id"):
            log_record["request_id"] = record.request_id
        if hasattr(record, "endpoint"):
            log_record["endpoint"] = record.endpoint
        if hasattr(record, "duration"):
            log_record["duration"] = record.duration
        if hasattr(record, "status"):
            log_record["status"] = record.status


def setup_logging(log_level: str = "INFO") -> None:
    """Configure structured JSON logging. No print statements."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        TaskForgeJsonFormatter(
            "%(timestamp)s %(level)s %(name)s %(message)s",
            timestamp=True,
        )
    )
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    # Reduce noise from third-party libs
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance."""
    return logging.getLogger(name)
