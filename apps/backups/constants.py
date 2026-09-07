"""Immutable backup compatibility boundaries."""

# The supported PostgreSQL client major is part of the tested backup format
# contract, not a deployment-tunable policy value.
POSTGRES_CLIENT_MIN_MAJOR = 16
