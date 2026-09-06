"""Output formatting for NetWatch."""

from __future__ import annotations

import csv
import io
import json
import sys
from typing import Any


def print_table(
    headers: list[str],
    rows: list[list[str]],
    file: Any = None,
) -> None:
    out = file or sys.stdout
    if not rows:
        out.write("(no data)\n")
        return

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(val)))

    fmt = "  ".join(f"{{:<{w}}}" for w in col_widths)
    out.write(fmt.format(*headers) + "\n")
    out.write(fmt.format(*["-" * w for w in col_widths]) + "\n")
    for row in rows:
        out.write(fmt.format(*[str(v) for v in row]) + "\n")


def print_json(data: Any, file: Any = None) -> None:
    out = file or sys.stdout
    out.write(json.dumps(data, indent=2, default=str) + "\n")


def print_csv(headers: list[str], rows: list[list[str]], file: Any = None) -> None:
    out = file or sys.stdout
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(headers)
    writer.writerows(rows)
    out.write(buf.getvalue())


def format_output(
    fmt: str,
    headers: list[str],
    rows: list[list[str]],
    json_data: Any = None,
    file: Any = None,
) -> None:
    if fmt == "json":
        print_json(json_data if json_data is not None else _rows_to_dicts(headers, rows), file=file)
    elif fmt == "csv":
        print_csv(headers, rows, file=file)
    else:
        print_table(headers, rows, file=file)


def _rows_to_dicts(headers: list[str], rows: list[list[str]]) -> list[dict]:
    return [dict(zip(headers, row)) for row in rows]
