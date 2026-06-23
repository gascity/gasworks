"""gasworks — SSO login + getToken for the Gas City credential plane.

`gasworks login` authenticates a user against Keycloak SSO (device-code or browser
loopback, both PKCE) and stores the refresh token + a DPoP key. `gasworks getToken
<product>` discovers the caller's org + mintable scopes and exchanges the session at
the STS for a short-lived EIA (RFC 8693). Everything narrows server-side; the client
never asserts authority it wasn't granted.
"""

__version__ = "0.1.0"
