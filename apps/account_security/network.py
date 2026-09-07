"""Request-network identity helpers used by abuse controls and provider calls.

Module scope:
- ``get_client_ip_from_headers`` resolves forwarded metadata under the
  configured proxy boundary (used only by edge adapters to derive coarse
  classification and hashes).
- ``classify_network_class`` reduces an address to one bounded, coarse class.
  Only the configured ``CAMPUS_NETWORK_CIDRS`` ranges ever produce
  ``campus_network``; a campus is never inferred from an arbitrary address.
"""

from __future__ import annotations

import ipaddress

from django.conf import settings


# Bounded coarse-network classes. These are the ONLY values ever persisted or
# projected for network location — never a raw IP address.
CLASS_CAMPUS = "campus_network"
CLASS_PRIVATE = "private_network"
CLASS_PUBLIC = "public_network"
CLASS_UNKNOWN = "unknown"


def get_client_ip_from_headers(headers) -> str:
    """Return the address under the explicitly configured proxy boundary.

    Local and test settings intentionally use ``REMOTE_ADDR``.  Deployment
    settings must opt into exactly one trusted proxy hop before the rightmost
    forwarded address is accepted.  Header values are never persisted raw;
    callers pass them to the HMAC-based abuse/audit boundaries.
    """

    trusted_hops = int(getattr(settings, "TRUSTED_PROXY_HOPS", 0) or 0)
    headers = headers or {}
    forwarded = [
        value.strip()
        for value in str(headers.get("HTTP_X_FORWARDED_FOR", "") or "").split(",")
        if value.strip()
    ]
    if trusted_hops == 1 and forwarded:
        return forwarded[-1]
    return str(headers.get("REMOTE_ADDR", "") or "")


def _configured_campus_networks() -> list:
    """Return parsed ``CAMPUS_NETWORK_CIDRS`` networks, ignoring invalid entries."""
    networks = []
    for entry in getattr(settings, "CAMPUS_NETWORK_CIDRS", None) or []:
        try:
            networks.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError:
            # Invalid configured ranges never broaden classification.
            continue
    return networks


def classify_network_class(ip: str) -> str:
    """Return one coarse network class for ``ip``.

    - ``campus_network`` : contained in a configured ``CAMPUS_NETWORK_CIDRS`` range.
    - ``private_network`` : RFC-private address not matched by a campus range.
    - ``public_network``   : valid global (public) address.
    - ``unknown``          : loopback / link-local / unspecified / reserved /
      multicast / unparseable / missing values.
    """
    if not ip or not str(ip).strip():
        return CLASS_UNKNOWN
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return CLASS_UNKNOWN

    if (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_reserved
        or address.is_multicast
    ):
        return CLASS_UNKNOWN

    for network in _configured_campus_networks():
        if address in network:
            return CLASS_CAMPUS

    if address.is_private:
        return CLASS_PRIVATE
    if address.is_global:
        return CLASS_PUBLIC
    return CLASS_UNKNOWN
