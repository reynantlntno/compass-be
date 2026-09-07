"""Model-free, secret-free staff account projections."""


def project_staff_account(user, invitation=None):
    if user is None:
        return None
    counselor = getattr(user, "counselor_profile", None)
    gco = getattr(user, "staff_profile", None)
    pending = bool(invitation and invitation.used_at is None and invitation.revoked_at is None)
    return {
        "id": user.pk,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": user.role,
        "is_active": bool(user.is_active),
        "profile_type": user.role if user.role in {"COUNSELOR", "GCO_STAFF"} else None,
        "designation": getattr(gco, "designation", "") if gco else "",
        "license_present": bool(getattr(counselor, "license_number", "")) if counselor else False,
        "employee_number_present": bool(getattr(gco, "employee_number", "")) if gco else False,
        "is_head_guidance": bool(getattr(counselor, "is_head_guidance", False)) if counselor else False,
        "invitation": {
            "state": "pending" if pending else ("used" if invitation and invitation.used_at else "revoked" if invitation else "none"),
            "expires_at": invitation.expires_at.isoformat() if invitation else None,
            "created_at": invitation.created_at.isoformat() if invitation else None,
            "used_at": invitation.used_at.isoformat() if invitation and invitation.used_at else None,
            "revoked_at": invitation.revoked_at.isoformat() if invitation and invitation.revoked_at else None,
        },
    }


def project_head_designation(profile):
    if profile is None:
        return None
    return {
        "user_id": profile.user_id,
        "is_head_guidance": bool(profile.is_head_guidance),
        "designated_at": profile.updated_at.isoformat() if profile.updated_at else None,
    }
