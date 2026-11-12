"""Domain exceptions for the local IAM service layer."""

class IAMError(Exception):
    """Base class for expected IAM service failures."""

class InvalidPassword(IAMError, ValueError):
    """A password violates the local password policy."""

class InvalidActivationToken(IAMError):
    """An activation token is unknown, expired, consumed, or unusable."""

class AccountNotEligible(IAMError):
    """The account state does not permit the requested operation."""

class PasswordVerificationFailed(IAMError):
    """The supplied current password could not be verified."""

class AccountNotFound(IAMError):
    """The requested IAM account does not exist."""
