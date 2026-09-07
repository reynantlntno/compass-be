"""Django fields that expose Python values while storing strict encrypted TEXT."""

from django.core import checks
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.expressions import BaseExpression
from django.db.models.lookups import IsNull
from django.db.models.expressions import Col
from django.db.models.signals import pre_save

from apps.security.exceptions import (
    FieldEncryptionMalformedEnvelope,
    FieldEncryptionUnsupportedORMOperation,
)
from apps.security.constants import FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES
from apps.security.field_encryption import decrypt_field_value, encrypt_field_value


def _references_field(expression, field):
    if isinstance(expression, Col):
        return expression.target is field
    if isinstance(expression, str):
        return expression.lstrip("-") == field.name
    getter = getattr(expression, "get_source_expressions", None)
    return bool(getter and any(_references_field(child, field) for child in getter()))


class _EncryptedCol(Col):
    def as_sql(self, compiler, connection):
        query = compiler.query
        target = self.target
        if getattr(query, "distinct", False) or getattr(query, "combinator", None):
            raise FieldEncryptionUnsupportedORMOperation()
        prohibited = list(getattr(query, "order_by", ()))
        group_by = getattr(query, "group_by", None)
        if group_by is True:
            raise FieldEncryptionUnsupportedORMOperation()
        if group_by not in (None, False):
            prohibited += list(group_by)
        prohibited += list(getattr(query, "distinct_fields", ()) or ())
        prohibited += list(getattr(query, "annotations", {}).values())
        meta_ordering = getattr(compiler, "_meta_ordering", None)
        if meta_ordering:
            prohibited += list(meta_ordering)
        if any(_references_field(item, target) for item in prohibited):
            raise FieldEncryptionUnsupportedORMOperation()
        return super().as_sql(compiler, connection)


class _EncryptedFieldBase(models.TextField):
    payload_type = None
    description = "Encrypted confidential value"
    empty_strings_allowed = True

    def __init__(
        self,
        *args,
        max_plaintext_bytes=FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES,
        **kwargs,
    ):
        self.max_plaintext_bytes = max_plaintext_bytes
        super().__init__(*args, **kwargs)

    def contribute_to_class(self, cls, name, private_only=False, **kwargs):
        super().contribute_to_class(cls, name, private_only=private_only, **kwargs)
        self._encryption_context = f"{cls._meta.app_label}.{cls.__name__}.{self.name}"

    def get_col(self, alias, output_field=None):
        if alias == self.model._meta.db_table and (
            output_field is None or output_field is self
        ):
            cached = getattr(self, "_encrypted_col", None)
            if cached is None:
                cached = self._encrypted_col = _EncryptedCol(alias, self, self)
            return cached
        return _EncryptedCol(alias, self, output_field or self)

    @property
    def encryption_context(self):
        missing = False
        try:
            return self._encryption_context
        except AttributeError:
            missing = True
        if missing:
            raise FieldEncryptionMalformedEnvelope()

    def from_db_value(self, value, expression, connection):
        if value is None:
            return None
        return decrypt_field_value(
            value,
            payload_type=self.payload_type,
            context=self.encryption_context,
            max_plaintext_bytes=self.max_plaintext_bytes,
        )

    def to_python(self, value):
        if value is None:
            return None
        return self._coerce_python(value)

    def get_prep_value(self, value):
        if value is None:
            return None
        if isinstance(value, BaseExpression) or hasattr(value, "as_sql"):
            raise FieldEncryptionUnsupportedORMOperation()
        value = self.to_python(value)
        return encrypt_field_value(
            value,
            payload_type=self.payload_type,
            context=self.encryption_context,
            max_plaintext_bytes=self.max_plaintext_bytes,
        )

    def get_db_prep_value(self, value, connection, prepared=False):
        if isinstance(value, BaseExpression) or hasattr(value, "as_sql"):
            raise FieldEncryptionUnsupportedORMOperation()
        return value if prepared else self.get_prep_value(value)

    def get_db_prep_save(self, value, connection):
        if isinstance(value, BaseExpression) or hasattr(value, "as_sql"):
            raise FieldEncryptionUnsupportedORMOperation()
        return self.get_db_prep_value(value, connection, prepared=False)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        if self.max_plaintext_bytes != FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES:
            kwargs["max_plaintext_bytes"] = self.max_plaintext_bytes
        return name, path, args, kwargs

    def value_to_string(self, obj):
        # Django's generic serializer cannot distinguish caller plaintext from
        # fixture envelope text on deserialization. Fail closed instead of
        # risking plaintext fixtures or silent double encryption.
        raise FieldEncryptionUnsupportedORMOperation()

    def get_lookup(self, lookup_name):
        if lookup_name == "isnull":
            return IsNull
        raise FieldEncryptionUnsupportedORMOperation()

    def get_transform(self, name):
        raise FieldEncryptionUnsupportedORMOperation()

    def check(self, **kwargs):
        errors = super().check(**kwargs)
        if self.unique:
            errors.append(checks.Error("Encrypted fields cannot be unique.", obj=self, id="security.E101"))
        if self.db_index:
            errors.append(checks.Error("Encrypted fields cannot be indexed.", obj=self, id="security.E102"))
        if getattr(self, "db_default", models.NOT_PROVIDED) is not models.NOT_PROVIDED:
            errors.append(checks.Error("Encrypted fields cannot use database defaults.", obj=self, id="security.E103"))
        if type(self.max_plaintext_bytes) is not int or not 1 <= self.max_plaintext_bytes <= FIELD_ENCRYPTION_MAX_PLAINTEXT_BYTES:
            errors.append(checks.Error("Encrypted field payload limit is unsafe.", obj=self, id="security.E104"))
        ordering = getattr(self.model._meta, "ordering", ()) or ()
        if any(str(item).lstrip("-") == self.name for item in ordering):
            errors.append(checks.Error("Encrypted fields cannot define model ordering.", obj=self, id="security.E105"))
        if any(self.name in repr(constraint) for constraint in self.model._meta.constraints):
            errors.append(checks.Error("Encrypted fields cannot use content constraints.", obj=self, id="security.E106"))
        return errors

    def validate(self, value, model_instance):
        value = self.to_python(value)
        invalid = False
        try:
            super().validate(value, model_instance)
            encrypt_field_value(
                value,
                payload_type=self.payload_type,
                context=self.encryption_context,
                max_plaintext_bytes=self.max_plaintext_bytes,
            ) if value is not None else None
        except Exception as exc:
            if isinstance(exc, ValidationError):
                raise
            invalid = True
        if invalid:
            raise ValidationError("Confidential value is invalid.", code="invalid")


class EncryptedTextField(_EncryptedFieldBase):
    payload_type = "text"

    def _coerce_python(self, value):
        if not isinstance(value, str):
            raise ValidationError("Enter valid text.", code="invalid")
        return value

    def formfield(self, **kwargs):
        kwargs.setdefault("strip", False)
        return super().formfield(**kwargs)


class EncryptedJSONField(_EncryptedFieldBase):
    payload_type = "json"

    def _coerce_python(self, value):
        return value

    def get_prep_value(self, value):
        # A non-null JSON field uses Python None for encrypted JSON null. A
        # nullable JSON field reserves Python None for database NULL, matching
        # Django's normal nullable-field contract.
        if value is _ENCRYPTED_JSON_NULL or (value is None and not self.null):
            return encrypt_field_value(
                None,
                payload_type=self.payload_type,
                context=self.encryption_context,
                max_plaintext_bytes=self.max_plaintext_bytes,
            )
        return super().get_prep_value(value)

    def validate(self, value, model_instance):
        if value is None and not self.null:
            encrypt_field_value(
                None,
                payload_type=self.payload_type,
                context=self.encryption_context,
                max_plaintext_bytes=self.max_plaintext_bytes,
            )
            return
        return super().validate(value, model_instance)

    def formfield(self, **kwargs):
        return super().formfield(form_class=models.JSONField().formfield().__class__, **kwargs)


def _reject_raw_fixture_save(sender, instance, raw=False, **kwargs):
    if raw and any(
        isinstance(field, _EncryptedFieldBase) for field in sender._meta.concrete_fields
    ):
        raise FieldEncryptionUnsupportedORMOperation()


pre_save.connect(
    _reject_raw_fixture_save,
    dispatch_uid="security.reject_raw_encrypted_fixture_save",
    weak=False,
)


class _EncryptedJSONNull:
    pass


_ENCRYPTED_JSON_NULL = _EncryptedJSONNull()
