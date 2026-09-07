"""Account-security-owned abuse-control defaults."""

from types import MappingProxyType


ABUSE_POLICY_DEFAULTS = MappingProxyType(
    {
        "login": MappingProxyType({"window_seconds": 900, "challenge_threshold": 3, "hard_limit": 5, "ip_challenge_threshold": 18, "ip_hard_limit": 60}),
        "recovery_request": MappingProxyType({"window_seconds": 900, "challenge_threshold": 3, "hard_limit": 5, "ip_challenge_threshold": 18, "ip_hard_limit": 60}),
        "recovery_resend": MappingProxyType({"window_seconds": 900, "challenge_threshold": 2, "hard_limit": 3, "ip_challenge_threshold": 12, "ip_hard_limit": 60}),
        "recovery_verify": MappingProxyType({"window_seconds": 900, "challenge_threshold": 2, "hard_limit": 3, "ip_challenge_threshold": 12, "ip_hard_limit": 60}),
        "contact": MappingProxyType({"window_seconds": 600, "challenge_threshold": 3, "hard_limit": 5, "ip_challenge_threshold": 18, "ip_hard_limit": 60}),
        "activation": MappingProxyType({"window_seconds": 900, "challenge_threshold": 3, "hard_limit": 5, "ip_challenge_threshold": 18, "ip_hard_limit": 60}),
        "token_verify": MappingProxyType({"window_seconds": 900, "challenge_threshold": 3, "hard_limit": 5, "ip_challenge_threshold": 18, "ip_hard_limit": 60}),
        "ecounseling_join": MappingProxyType({"window_seconds": 300, "challenge_threshold": 3, "hard_limit": 5, "ip_challenge_threshold": 18, "ip_hard_limit": 60}),
        "student_search": MappingProxyType({"window_seconds": 60, "challenge_threshold": 20, "hard_limit": 40, "ip_challenge_threshold": 120, "ip_hard_limit": 240}),
        "api_admin_write": MappingProxyType({"window_seconds": 900, "challenge_threshold": 20, "hard_limit": 40, "ip_challenge_threshold": 120, "ip_hard_limit": 240}),
        "api_protected_download": MappingProxyType({"window_seconds": 300, "challenge_threshold": 30, "hard_limit": 60, "ip_challenge_threshold": 120, "ip_hard_limit": 240}),
        "api_export": MappingProxyType({"window_seconds": 900, "challenge_threshold": 10, "hard_limit": 20, "ip_challenge_threshold": 60, "ip_hard_limit": 120}),
    }
)
