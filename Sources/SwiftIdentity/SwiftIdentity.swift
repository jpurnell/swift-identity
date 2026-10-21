/// Who is asking, and are they still allowed to be here?
///
/// SwiftIdentity holds **subjects** — the people and services a system knows — and the
/// **credentials** that prove them, so that a name in a record is something the system verified
/// rather than something a caller typed.
///
/// ## What it is not
///
/// It is not an OAuth library: SwiftOAuth is that, and should stay spec-shaped. What OAuth does
/// not model is the subject that outlives any one token — and, as deployed here, its
/// `/authorize` flow authenticates the *client* and never the person, so a token records which
/// application asked and never who.
///
/// It is not an entitlement system either. This package answers who, and whether they may be
/// here at all. What a subject may *do* — a tier, a plan, a decision role — belongs to the
/// consumer, because a family vault's tiers and a commercial plan are the same shape only by
/// coincidence.
///
/// ## Why a package rather than a store per service
///
/// The same hole appears in four services at once: a decision log whose owner field is free
/// text, a vault that cannot say who completed a job, a commercial service that cannot revoke
/// one customer without revoking all of them, and a guidelines server that cannot tell
/// organisations apart. Solving it once per service is how each of them gets a slightly
/// different answer.
///
/// And not every client has a browser. A shared speaker cannot follow a redirect; a calendar
/// client cannot send an `Authorization` header at all. A capability URL, a bearer key and an
/// OAuth login have to resolve to the *same* subject, or identity is only true on the web.
///
/// ## Status
///
/// Nothing is implemented yet, deliberately. The design is under review in
/// `project/plans/proposals/SubjectsAndCredentials.md`; this project's workflow puts the
/// proposal before the code, and a package that holds credentials is the last place to skip
/// that step.
public enum SwiftIdentity {}
