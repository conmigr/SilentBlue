"""Defensive playbooks. Each one states the control and the evidence for it."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Playbook:
    """Evidence bar for one control family."""

    playbook_id: str
    control_family: str
    control: str
    holds_when: str
    gap_when: str
    remediation: str

    def render(self) -> str:
        return "\n".join(
            [
                f"Playbook: {self.playbook_id}",
                f"Control: {self.control}",
                f"Holds when: {self.holds_when}",
                f"Gap when: {self.gap_when}",
                f"Repair: {self.remediation}",
            ]
        )


PLAYBOOKS: dict[str, Playbook] = {
    "secrets": Playbook(
        playbook_id="secrets",
        control_family="secrets",
        control="Credentials are loaded at runtime from a secret store or the environment.",
        holds_when=(
            "Secret-shaped values are absent from source, or the assignment is an obvious placeholder, "
            "and credential values are not written to logs."
        ),
        gap_when=(
            "A private key, token, or password literal is stored in a tracked file, "
            "a password is a well-known default, or a credential value is passed to a log call."
        ),
        remediation=(
            "Remove the value from source, rotate the credential, and load it from "
            "an environment variable or a secret manager."
        ),
    ),
    "injection": Playbook(
        playbook_id="injection",
        control_family="injection",
        control=(
            "Queries, commands, and code paths keep their syntax fixed and pass "
            "data through a dedicated parameter or argument channel."
        ),
        holds_when=(
            "SQL and document queries are constants with bound parameters, directory "
            "filters and response headers are constants, templates are fixed files, "
            "process calls use an argument list with the shell left off, external input "
            "is not passed to eval or exec, and markup is built with DOM methods."
        ),
        gap_when=(
            "A query, directory filter, header, shell command, template, or eval/exec "
            "call is built by concatenation, interpolation, or formatting, or a string "
            "is parsed as HTML."
        ),
        remediation=(
            "Keep the command or query text constant. Pass values as bound parameters "
            "or as separate arguments, leave shell execution disabled, and build markup "
            "with DOM methods or a fixed template."
        ),
    ),
    "transport": Playbook(
        playbook_id="transport",
        control_family="transport",
        control="TLS clients verify the server certificate.",
        holds_when="Certificate verification stays at the client default, or a private trust bundle is named.",
        gap_when="A call turns certificate verification off, including rejectUnauthorized set to false.",
        remediation=(
            "Leave certificate verification enabled. Point the client at a private "
            "trust bundle when the service uses an internal certificate authority."
        ),
    ),
    "configuration": Playbook(
        playbook_id="configuration",
        control_family="configuration",
        control="Shared configuration leaves debug mode off and keeps browser protections on.",
        holds_when=(
            "Debug flags are off, the host allow-list is explicit, and security headers "
            "and secure-cookie flags stay enabled."
        ),
        gap_when=(
            "A configuration file turns debug mode on, allows every host, or disables "
            "a security header or a secure-cookie flag."
        ),
        remediation=(
            "Turn debug mode off, name the allowed hosts, and leave the security headers "
            "and secure-cookie flags enabled."
        ),
    ),
    "access-control": Playbook(
        playbook_id="access-control",
        control_family="access-control",
        control=(
            "Callers are limited to the origins, objects, and fields they are allowed to use."
        ),
        holds_when=(
            "The origin allow-list is explicit, session tokens stay out of page script, "
            "CSRF checks stay on, models copy a named field list, and an object loaded "
            "by a request id is compared with the caller."
        ),
        gap_when=(
            "A cross-origin setting allows every origin, a session token is readable by "
            "page script, CSRF protection is disabled, a request body is expanded into "
            "a model, or the excerpt loads an object by a request id and does not compare "
            "the caller with the owner."
        ),
        remediation=(
            "Name the allowed origins, keep CSRF checks on, copy an explicit field list, "
            "and compare the caller with the owner before returning or changing an object."
        ),
    ),
    "cryptography": Playbook(
        playbook_id="cryptography",
        control_family="cryptography",
        control="Passwords use a password hash, and tokens use a cryptographic generator.",
        holds_when=(
            "Passwords are passed to a password hash, tokens use a cryptographic generator, "
            "and ciphers are authenticated modes."
        ),
        gap_when=(
            "A password is passed to MD5 or SHA-1, a token uses a non-cryptographic random "
            "source, or a call selects ECB, DES, RC4, or Blowfish."
        ),
        remediation=(
            "Hash passwords with a password hash. Draw tokens from a cryptographic generator. "
            "Use an authenticated cipher."
        ),
    ),
    "deserialization": Playbook(
        playbook_id="deserialization",
        control_family="deserialization",
        control="Decoders do not construct objects from a stream.",
        holds_when="Structured input is decoded with a safe parser that returns data only.",
        gap_when="A loader can construct objects, including pickle, unsafe YAML, or a native formatter.",
        remediation="Decode data with a parser that does not construct objects from the stream.",
    ),
    "request-routing": Playbook(
        playbook_id="request-routing",
        control_family="request-routing",
        control="Outbound URLs, file paths, and redirect targets are fixed or allow-listed.",
        holds_when=(
            "HTTP clients use URLs from configuration, file paths stay under a fixed root, "
            "and redirect targets are relative paths on an allow-list."
        ),
        gap_when=(
            "An HTTP client, file path, or redirect target is taken from request data."
        ),
        remediation=(
            "Call fixed URLs, join files under a fixed root, and accept only allow-listed "
            "relative redirect targets."
        ),
    ),
    "authentication": Playbook(
        playbook_id="authentication",
        control_family="authentication",
        control="Sessions are verified, marked, and bounded.",
        holds_when=(
            "Token signatures are verified with an explicit algorithm list, session cookies "
            "keep HttpOnly and Secure, and a login excerpt sets an expiry. A login excerpt "
            "that completes on a password also shows a second factor."
        ),
        gap_when=(
            "Verification is disabled, the none algorithm is allowed, a cookie flag is set "
            "false, or the excerpt completes a password login with no expiry and no second "
            "factor in the shown lines."
        ),
        remediation=(
            "Verify the token, set HttpOnly and Secure, set an expiry, and require a second "
            "factor on the login path shown in the excerpt."
        ),
    ),
    "resource-limits": Playbook(
        playbook_id="resource-limits",
        control_family="resource-limits",
        control="Login, signup, password, and upload routes have a request limit.",
        holds_when="A limiter is enabled for the login, signup, password, or upload handler in the excerpt.",
        gap_when=(
            "A limiter is disabled or set to zero, or the excerpt shows one of those handlers "
            "with no limit in the shown lines."
        ),
        remediation="Enable a request limit on login, signup, password, and upload routes.",
    ),
    "logging": Playbook(
        playbook_id="logging",
        control_family="logging",
        control="Authentication and authorization failures are logged without credential values.",
        holds_when="Logging stays enabled, and a shown failure path records the event name.",
        gap_when=(
            "Logging is disabled, or the excerpt shows an authentication or authorization "
            "failure discarded by an empty handler."
        ),
        remediation="Log the event name for authentication and authorization failures. Leave the credential out.",
    ),
    "supply-chain": Playbook(
        playbook_id="supply-chain",
        control_family="supply-chain",
        control="Dependencies and workflows are pinned, fetched over TLS, and narrowly permitted.",
        holds_when=(
            "Versions are exact pins, fetches use TLS and a CA bundle, downloads are not "
            "piped into a shell, and workflow permissions are named."
        ),
        gap_when=(
            "A version is not an exact pin, a dependency uses cleartext HTTP, an install "
            "turns certificate checks off, a named CA bundle is missing, a pinned package "
            "is named by an advisory, a download is piped into a shell, or a workflow uses "
            "pull_request_target or write-all."
        ),
        remediation=(
            "Pin a reviewed version, fetch it over TLS, keep a CA bundle in place, check a "
            "digest before running a download, and name the workflow permissions."
        ),
    ),
}


def playbook_for(family: str) -> Playbook | None:
    return PLAYBOOKS.get(family)
