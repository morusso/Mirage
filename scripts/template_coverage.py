"""Top requested paths and tier 0 template coverage.

A request is *covered* when a persona route (anything except the catch-all) answers
it, i.e. it gets a bait response instead of the generic 404. Bait templates added
later as routes count automatically. Run against the live database:

    python -m scripts.template_coverage --days 7 --top 30 --target 80

Exit status is 1 when coverage is below ``--target`` (percent), so it can gate a
release. Paths are attacker-controlled: they are printed with ``repr`` so control
characters and escape sequences cannot reach the operator's terminal.
"""

import argparse
import asyncio
import sys
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from fastapi import FastAPI
from sqlalchemy import text
from starlette.routing import Match

from app.config import Settings
from app.main import create_app
from app.personas import catch_all, fake_api
from domain.db import create_engine


def is_covered(app: FastAPI, method: str, path: str) -> bool:
    """True if a template route (not a catch-all or a model-backed one) handles this request."""
    scope = {"type": "http", "method": method.upper(), "path": path, "root_path": ""}
    # Each persona is mounted with include_router; the catch-all and model-backed ones are skipped.
    for route in app.routes:
        if getattr(route, "original_router", None) in (catch_all.router, fake_api.model_router):
            continue
        if route.matches(scope)[0] == Match.FULL:
            return True
    return False


@dataclass
class Report:
    total: int = 0
    covered: int = 0
    # Uncovered request counts per path: where a new template pays off most.
    uncovered: Counter[str] = field(default_factory=Counter)
    top: Counter[str] = field(default_factory=Counter)

    @property
    def coverage_pct(self) -> float:
        return 100 * self.covered / self.total if self.total else 0.0


def analyze(app: FastAPI, rows: Iterable[tuple[str, str, int]]) -> Report:
    """``rows`` are (method, path, request count)."""
    report = Report()
    for method, path, count in rows:
        report.total += count
        report.top[path] += count
        if is_covered(app, method, path):
            report.covered += count
        else:
            report.uncovered[path] += count
    return report


def render(report: Report, top: int) -> str:
    lines = [
        f"requests: {report.total}",
        f"covered by templates: {report.covered} ({report.coverage_pct:.1f}%)",
        "",
        f"top {top} paths:",
        *(f"  {n:>8}  {p!r}" for p, n in report.top.most_common(top)),
        "",
        f"top {top} uncovered paths (template candidates):",
        *(f"  {n:>8}  {p!r}" for p, n in report.uncovered.most_common(top)),
    ]
    return "\n".join(lines)


async def _fetch(database_url: str, days: int) -> list[tuple[str, str, int]]:
    engine = create_engine(database_url, pool_size=1)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT method, path, count(*) FROM requests "
                    "WHERE ts >= now() - make_interval(days => :days) GROUP BY method, path"
                ),
                {"days": days},
            )
            return [(str(m), str(p), int(c)) for m, p, c in result]
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--target", type=float, default=80.0, help="minimum coverage, percent")
    args = parser.parse_args(argv)

    settings = Settings()
    rows = asyncio.run(_fetch(settings.database_url.get_secret_value(), args.days))
    report = analyze(create_app(settings), rows)
    print(render(report, args.top))
    if report.coverage_pct < args.target:
        print(f"\ncoverage below target {args.target:.0f}%", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
