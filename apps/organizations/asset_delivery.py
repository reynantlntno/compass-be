"""Short-lived signed delivery URLs for approved public brand assets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlencode

from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
from django.utils import timezone

from apps.governance.runtime_config import resolve_runtime_setting


BRAND_ASSET_SIGNING_SALT = "compass.organizations.public-brand-asset.v1"
BRAND_ASSET_CONTENT_PATH = "/api/v1/organizations/public/branding/assets/{asset_id}/content/"
BRAND_ASSET_MIN_TTL_SECONDS = 60
BRAND_ASSET_MAX_TTL_SECONDS = 3600


@dataclass(frozen=True, slots=True)
class PublicBrandAssetDelivery:
    """Safe delivery receipt; it contains no storage coordinates."""

    asset_id: str
    url: str
    expires_at: datetime
    ttl_seconds: int
    content_type: str

    def as_safe_json(self) -> dict[str, object]:
        return {
            "asset_id": self.asset_id,
            "url": self.url,
            "expires_at": self.expires_at.isoformat(),
            "ttl_seconds": self.ttl_seconds,
            "content_type": self.content_type,
            "cache_control": (
                f"public, max-age={self.ttl_seconds}, "
                f"s-maxage={self.ttl_seconds}, must-revalidate"
            ),
        }


def public_brand_asset_ttl_seconds() -> int:
    value = int(
        resolve_runtime_setting(
            "security.protected_storage",
            "PROTECTED_STORAGE_SIGNED_URL_TTL_SECONDS",
        )
        or BRAND_ASSET_MIN_TTL_SECONDS
    )
    return max(BRAND_ASSET_MIN_TTL_SECONDS, min(BRAND_ASSET_MAX_TTL_SECONDS, value))


def _signer() -> TimestampSigner:
    return TimestampSigner(salt=BRAND_ASSET_SIGNING_SALT)


def issue_public_brand_asset_delivery(asset) -> PublicBrandAssetDelivery:
    """Issue a relative, short-lived URL without exposing storage details."""

    ttl_seconds = public_brand_asset_ttl_seconds()
    now = timezone.now()
    token = _signer().sign(str(asset.pk))
    query = urlencode({"token": token})
    url = BRAND_ASSET_CONTENT_PATH.format(asset_id=asset.pk) + f"?{query}"
    return PublicBrandAssetDelivery(
        asset_id=str(asset.pk),
        url=url,
        expires_at=now + timedelta(seconds=ttl_seconds),
        ttl_seconds=ttl_seconds,
        content_type=str(asset.content_type_hint or "").lower(),
    )


def verify_public_brand_asset_delivery(*, asset_id: str, token: str) -> bool:
    """Verify a token at the content boundary without persisting it."""

    if not token:
        return False
    try:
        signed_asset_id = _signer().unsign(token, max_age=public_brand_asset_ttl_seconds())
    except (BadSignature, SignatureExpired, TypeError, ValueError):
        return False
    return str(signed_asset_id) == str(asset_id)
