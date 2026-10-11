"""Overall banner precedence, the `ack` output and the adapter exit code (04 sec. 6; 02 sec. 3; A-3; A-8).

`ack` is exactly "not-required" only for rows 7 and 8 without the TRUST DEGRADED notice; in every other case it
is "required". The workflow's gate expression selects `p02-no-ack` only for that value, so a missing, empty or
malformed output fails closed.
"""
EXIT_OK = 0
EXIT_ACK_REQUIRED = 10       # fail-on-risk fallback: human acknowledgement required (review job red)
EXIT_INPUT = 20              # rows 2 and 3: suspected credential / input rejected
EXIT_TECHNICAL = 30          # row 1


def _valid_row(row) -> bool:
    return isinstance(row, int) and not isinstance(row, bool) and 1 <= row <= 8


def ack_value(row, trust_degraded) -> str:
    if _valid_row(row) and row in (7, 8) and trust_degraded is False:
        return "not-required"
    return "required"


def exit_code(row, trust_degraded, gate_mode) -> int:
    if not _valid_row(row) or row == 1:
        return EXIT_TECHNICAL
    if row in (2, 3):
        return EXIT_INPUT
    needs_ack = ack_value(row, trust_degraded) == "required"
    if not needs_ack:
        return EXIT_OK
    if gate_mode == "environment":
        return EXIT_OK            # review green; the gate job waits in p02-risk-acknowledgement
    return EXIT_ACK_REQUIRED      # fallback (and any unknown mode): fail closed


def overall_row(package_rows, unreviewed_count: int, run_failure: bool) -> int:
    """Highest-precedence (lowest-numbered) banner among packages and the run-level row-6 condition."""
    if run_failure:
        return 1
    rows = [r for r in package_rows]
    if any(not _valid_row(r) or r == 8 for r in rows):
        return 1
    if unreviewed_count:
        rows.append(6)
    if not rows:
        return 8
    return min(rows)
