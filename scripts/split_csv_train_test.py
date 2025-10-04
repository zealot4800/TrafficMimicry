"""Deterministic train/test splitter for CSV datasets."""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path
from typing import Iterable


TRAIN_RATIO = 0.8


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Split a CSV into train/test sets deterministically")
    parser.add_argument("input", type=Path, help="Source CSV file")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory to place train/test files (defaults to input parent)",
    )
    parser.add_argument(
        "--train-output",
        type=Path,
        default=None,
        help="Explicit path for the train CSV (overrides --output-dir)",
    )
    parser.add_argument(
        "--test-output",
        type=Path,
        default=None,
        help="Explicit path for the test CSV (overrides --output-dir)",
    )
    parser.add_argument(
        "--delimiter",
        default=",",
        help="CSV delimiter (default: ,)",
    )
    parser.add_argument(
        "--hash-salt",
        default="",
        help="Optional salt mixed into the deterministic hash",
    )
    return parser.parse_args()


def _deterministic_bucket(row: Iterable[str], salt: str) -> float:
    hasher = hashlib.sha256()
    hasher.update(salt.encode("utf-8"))
    for field in row:
        hasher.update(field.encode("utf-8"))
        hasher.update(b"\x1f")
    digest = hasher.digest()
    upper = int.from_bytes(digest[:8], "big", signed=False)
    return upper / 2**64


def _plan_assignments(
    source: Path,
    *,
    delimiter: str,
    salt: str,
) -> tuple[list[str], set[int]]:
    with source.open("r", newline="") as handle:
        reader = csv.reader(handle, delimiter=delimiter)
        header = next(reader, None)
        if header is None:
            raise ValueError("Input CSV is empty")

        hashed_rows: list[tuple[float, int]] = []
        for index, row in enumerate(reader):
            hashed_rows.append((_deterministic_bucket(row, salt), index))

    total_rows = len(hashed_rows)
    if total_rows == 0:
        raise ValueError("Input CSV has no data rows")

    target_train = int(TRAIN_RATIO * total_rows + 0.5)
    target_train = max(0, min(total_rows, target_train))
    sorted_rows = sorted(hashed_rows, key=lambda item: (item[0], item[1]))
    train_indices = {index for _, index in sorted_rows[:target_train]}
    return header, train_indices


def _resolve_outputs(args: argparse.Namespace) -> tuple[Path, Path]:
    if args.train_output and args.test_output:
        return args.train_output, args.test_output

    output_dir: Path
    if args.output_dir is not None:
        output_dir = args.output_dir
    else:
        output_dir = args.input.parent

    base = args.input.stem
    train_path = args.train_output or output_dir / f"{base}_train.csv"
    test_path = args.test_output or output_dir / f"{base}_test.csv"
    return Path(train_path), Path(test_path)


def _split_csv(
    source: Path,
    train_path: Path,
    test_path: Path,
    *,
    delimiter: str,
    salt: str,
) -> tuple[int, int]:
    train_path.parent.mkdir(parents=True, exist_ok=True)
    test_path.parent.mkdir(parents=True, exist_ok=True)

    header, train_indices = _plan_assignments(
        source,
        delimiter=delimiter,
        salt=salt,
    )

    with (
        source.open("r", newline="") as read_handle,
        train_path.open("w", newline="") as train_handle,
        test_path.open("w", newline="") as test_handle,
    ):
        reader = csv.reader(read_handle, delimiter=delimiter)
        train_writer = csv.writer(train_handle, delimiter=delimiter)
        test_writer = csv.writer(test_handle, delimiter=delimiter)

        _ = next(reader)  # discard header already captured
        train_writer.writerow(header)
        test_writer.writerow(header)

        train_count = 0
        test_count = 0
        for index, row in enumerate(reader):
            if index in train_indices:
                train_writer.writerow(row)
                train_count += 1
            else:
                test_writer.writerow(row)
                test_count += 1

    return train_count, test_count


def main() -> None:
    args = _parse_args()
    train_path, test_path = _resolve_outputs(args)

    train_count, test_count = _split_csv(
        args.input.resolve(),
        train_path.resolve(),
        test_path.resolve(),
        delimiter=args.delimiter,
        salt=args.hash_salt,
    )

    total = train_count + test_count
    print(
        f"Wrote {train_count} train rows and {test_count} test rows "
        f"({total} total) to {train_path} and {test_path}"
    )


if __name__ == "__main__":
    main()
