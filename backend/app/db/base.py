from typing import TypeVar, Generic, Any
import uuid
from datetime import datetime

T = TypeVar('T')

class Mapped(Generic[T]):
    pass

def mapped_column(*args, **kwargs):
    return None

def relationship(*args, **kwargs):
    return None

class DummyType:
    def __init__(self, *args, **kwargs):
        pass

String = DummyType
Boolean = DummyType
DateTime = DummyType
ForeignKey = DummyType
SAEnum = DummyType
UUID = DummyType
JSONB = DummyType
ARRAY = DummyType
INET = DummyType
Integer = DummyType
Text = DummyType
Float = DummyType

class FieldShim:
    def __init__(self, name):
        self.name = name
    def __eq__(self, other):
        return (self.name, other, "eq")
    def __ne__(self, other):
        return (self.name, other, "ne")
    def __ge__(self, other):
        return (self.name, other, "ge")
    def __le__(self, other):
        return (self.name, other, "le")
    def __gt__(self, other):
        return (self.name, other, "gt")
    def __lt__(self, other):
        return (self.name, other, "lt")
    def desc(self):
        return (self.name, -1)
    def asc(self):
        return (self.name, 1)

class ModelMetaclass(type):
    def __new__(cls, name, bases, attrs):
        annotations = attrs.get("__annotations__", {})
        for field_name in annotations:
            attrs[field_name] = FieldShim(field_name)
        for base in bases:
            for field_name in getattr(base, "__annotations__", {}):
                attrs[field_name] = FieldShim(field_name)
        new_class = super().__new__(cls, name, bases, attrs)
        for attr_name in dir(new_class):
            try:
                attr_val = getattr(new_class, attr_name)
                if isinstance(attr_val, FieldShim):
                    attr_val.model_class = new_class
            except AttributeError:
                pass
        return new_class

class Base(metaclass=ModelMetaclass):
    def _init_defaults(self):
        for field_name in getattr(self.__class__, "__annotations__", {}):
            setattr(self, field_name, None)
        # Specific defaults matching columns
        if hasattr(self, "failed_login_attempts"):
            self.failed_login_attempts = 0
        if hasattr(self, "is_active"):
            self.is_active = True
        if hasattr(self, "is_verified"):
            self.is_verified = False
        if hasattr(self, "is_blocked"):
            self.is_blocked = False
        if hasattr(self, "mfa_enabled"):
            self.mfa_enabled = False
        if hasattr(self, "is_approved"):
            self.is_approved = False
        if hasattr(self, "confirmed"):
            self.confirmed = False
        if hasattr(self, "liveness_passed"):
            self.liveness_passed = False
        if hasattr(self, "match_passed"):
            self.match_passed = False
        if hasattr(self, "role"):
            self.role = "user"
            
        # Enum/status fields
        if hasattr(self, "status"):
            classname = self.__class__.__name__
            if classname == "Credential":
                self.status = "active"
            elif classname in ("ConsentRecord", "DocumentValidation"):
                self.status = "pending"
                
        # String defaults
        if hasattr(self, "schema_version"):
            self.schema_version = "1.0"
        if hasattr(self, "key_algorithm"):
            self.key_algorithm = "Ed25519"
            
        # Dict defaults
        for dict_field in ("did_document", "details", "ocr_extracted_fields", "tamper_indicators", "signals", "metadata_json"):
            if hasattr(self, dict_field):
                setattr(self, dict_field, {})
                
        # Datetime defaults
        now = datetime.utcnow()
        for dt_field in ("created_at", "updated_at", "issued_at", "requested_at"):
            if hasattr(self, dt_field):
                setattr(self, dt_field, now)

    def __init__(self, **kwargs):
        self._init_defaults()
        for k, v in kwargs.items():
            setattr(self, k, v)
        if not hasattr(self, "id") or self.id is None:
            self.id = uuid.uuid4()
        if not hasattr(self, "created_at") or self.created_at is None:
            self.created_at = datetime.utcnow()
        if not hasattr(self, "updated_at") or self.updated_at is None:
            self.updated_at = datetime.utcnow()

    def to_dict(self):
        d = {}
        for k, v in self.__dict__.items():
            if isinstance(v, uuid.UUID):
                d[k] = str(v)
            elif isinstance(v, datetime):
                d[k] = v.isoformat()
            elif isinstance(v, Base):
                pass
            elif k.startswith("_"):
                pass
            else:
                d[k] = v
        d["_id"] = str(self.id)
        d["id"] = str(self.id)
        return d

    @classmethod
    def from_dict(cls, d):
        if not d:
            return None
        obj = cls.__new__(cls)
        obj._init_defaults()
        for k, v in d.items():
            if k == "_id":
                k = "id"
            if k == "id" and isinstance(v, str):
                try:
                    v = uuid.UUID(v)
                except ValueError:
                    pass
            elif k in ("created_at", "updated_at", "locked_until", "verified_at", "expires_at", "uploaded_at", "matched_at", "timestamp", "issued_at", "requested_at") and isinstance(v, str):
                try:
                    v = datetime.fromisoformat(v)
                except ValueError:
                    pass
            
            # Map None values to defaults (only override if database has a non-null value)
            if v is not None:
                setattr(obj, k, v)
        return obj

    def __getattr__(self, name):
        if name == "failed_login_attempts":
            return 0
        if name in ("is_active", "is_verified"):
            return True
        if name in ("is_blocked", "mfa_enabled", "liveness_passed", "match_passed", "is_approved", "confirmed"):
            return False
        if name in ("locked_until", "verified_at", "expires_at", "uploaded_at", "matched_at", "timestamp", "mfa_secret_encrypted", "full_name_encrypted", "organization_domain", "onchain_issuer_id", "signing_public_key_pem", "blockchain_tx_hash", "onchain_credential_hash", "revoked_at", "revocation_reason"):
            return None
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

