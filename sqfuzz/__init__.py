"""sqisign-verify-fuzz — AddressSanitizer verification-robustness fuzz harness.

An independent reproduction of the already-open, team-acknowledged upstream
robustness issue #23 in the SQIsign reference verifier, plus the fuzzing tooling
upstream issue #15 asked for. This is NOT a vulnerability, discovery, 0-day, or
attack; the reference is explicitly not production-ready and not constant-time.

Author: Moe Tabei <tabei@ryun.jp>. MIT-licensed.
"""

__version__ = "0.1.0"
