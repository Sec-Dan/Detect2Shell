"""Fan the (target x check) grid across a thread pool and collect findings."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional

from ..checks.base import Check, CheckContext
from .models import Confidence, Finding, Target, Tier


def run_scan(
    targets: List[Target],
    checks: List[Check],
    ctx: CheckContext,
    concurrency: int = 10,
    progress: Optional[Callable] = None,
) -> List[Finding]:
    jobs = [(target, check) for target in targets for check in checks]
    findings: List[Finding] = []
    if not jobs:
        return findings
    total = len(jobs)
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {pool.submit(check.run, target, ctx): (target, check) for (target, check) in jobs}
        done = 0
        for future in as_completed(futures):
            target, check = futures[future]
            try:
                finding = future.result()
            except Exception as exc:
                finding = check.finding(
                    target, Confidence.ERROR, Tier.PASSIVE, "check crashed",
                    ["{}: {}".format(type(exc).__name__, exc)],
                )
            findings.append(finding)
            done += 1
            if progress:
                progress(done, total, target, check)
    return findings
