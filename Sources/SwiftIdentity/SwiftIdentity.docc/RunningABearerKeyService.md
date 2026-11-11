# Running a bearer-key service

Keep a service's API keys in the two files ``FileCredentialStore`` reads, and add, rotate and revoke them while it runs.

## Overview

A service that authenticates callers by a generated key needs four things besides checking the key: a way to *make* one, a way to *replace* one without an outage, a way to *stop* one at once, and a way to *notice* a key that should never be used. ``IdentityDirectory`` and ``ReloadingCredentialStore`` are those, on the files the store already reads.

The files hold digests only. A key is shown once, when it is minted.

### Making and rotating keys

``IdentityDirectory/create(first:using:)`` makes the directory (owner-only) with a first subject and its first key; ``IdentityDirectory/add(_:using:)`` adds another subject. Each returns a ``MintedKey``: hand its `key` to whoever needs it, once, and keep nothing. Neither description of the type prints it. These take the random number generator as a parameter: a service passes `SystemRandomNumberGenerator()` once, at its own entry point, and a test passes a seeded one.

To **rotate**, add a second key to the subject with ``IdentityDirectory/addKey(for:expires:using:)``. Both verify. Give the new key to the client, let the old one expire (or remove it with ``IdentityDirectory/revokeKey(digestPrefix:)``) once nothing presents it. No request fails in between.

### Stopping a key, and catching one that leaked

``IdentityDirectory/revoke(subject:)`` makes every key of a subject refuse. ``IdentityDirectory/setStatus(_:of:)`` with `honeypot` does the same and makes the refusal *reportable*: the caller is told nothing, and the service's audit is told which subject's key was presented. A key known to have leaked, or a decoy planted where a leak would look for it, is a subject with that status.

### Noticing changes while running

Hold the directory with ``ReloadingCredentialStore`` instead of ``FileCredentialStore``. It looks at the files at most once per interval and adopts a change that loads. **A change that does not load is refused, the last good copy keeps serving, and the refusal is reported once.** The interval bounds how long a revoked key can still verify; ``ReloadingCredentialStore/reload()`` looks at once.

### Why changes are checked first

Every change to the files is loaded through ``FileCredentialStore`` in a staging directory before the live files are replaced, and the live files are replaced atomically. A service therefore cannot be left with files its own reader refuses.

## Topics

### Administering

- ``IdentityDirectory``
- ``SubjectSpec``
- ``SubjectListing``
- ``KeyListing``
- ``AdministrationFailure``
- ``BearerKeyMinter``
- ``MintedKey``

### Reloading

- ``ReloadingCredentialStore``

### Files

- ``SecureIdentityFiles``
