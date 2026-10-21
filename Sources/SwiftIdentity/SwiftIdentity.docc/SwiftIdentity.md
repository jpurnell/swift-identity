# ``SwiftIdentity``

Who is asking, and are they still allowed to be here?

## Overview

A name in a record is only worth what the system did to verify it. SwiftIdentity holds
**subjects** — the people and services a system knows — and the **credentials** that prove
them, so that `decisionOwner`, `completed_by`, and "which customer is this" stop being strings
somebody typed.

### Identity, not entitlement

This package answers *who*, and whether they may be here at all. What a subject may **do** — a
tier, a plan, a decision role — stays with the consumer. A family vault's tiers and a commercial
plan are the same shape only by coincidence, and a package that understood both would be
answering to whichever paid more.

### Not every client has a browser

A shared speaker cannot follow a redirect. A calendar client cannot send an `Authorization`
header at all. Those are permanent properties of those clients, not gaps to close later — so a
capability URL, a bearer key, and an OAuth login must resolve to the *same* subject, or identity
is only true on the web.

That is the part OAuth cannot do alone, and the reason this is a package rather than a
convention.

## Topics

### Status

Nothing is implemented yet. The design is under review in
`project/plans/proposals/SubjectsAndCredentials.md`, and this project puts the proposal before
the code — most of all for a package that holds credentials.
