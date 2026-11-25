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
            "Delete the literal, revoke it at the issuer, and read the replacement from the process "
            "environment or a secret manager. Do not commit the new value."
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
            "Keep the statement, command, filter, and template text constant. "
            "Pass values through the driver's bind API or an argument list with the shell off. "
            "Build markup with DOM methods. Do not compile caller text as code or HTML."
        ),
    ),
    "transport": Playbook(
        playbook_id="transport",
        control_family="transport",
        control="TLS clients verify the server certificate.",
        holds_when="Certificate verification stays at the client default, or a private trust bundle is named.",
        gap_when="A call turns certificate verification off, including rejectUnauthorized set to false.",
        remediation=(
            "Delete verify=False, rejectUnauthorized: false, and InsecureSkipVerify: true. "
            "For a private CA, set the trust store to that bundle and leave hostname checks on."
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
            "Set debug flags false in shared configuration. Replace a host allow-list of * with explicit hosts. "
            "Leave security headers and secure-cookie flags at their safe values."
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
            "Name allowed origins as scheme, host, and port. Keep the CSRF check on for state-changing routes. "
            "Copy a named field list from the body. Compare the caller with the owner before returning or changing an object."
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
            "Hash passwords with bcrypt, scrypt, or Argon2. Draw tokens from a cryptographic generator. "
            "Use an authenticated cipher such as AES-GCM, and remove ECB, DES, RC4, and Blowfish."
        ),
    ),
    "deserialization": Playbook(
        playbook_id="deserialization",
        control_family="deserialization",
        control="Decoders do not construct objects from a stream.",
        holds_when="Structured input is decoded with a safe parser that returns data only.",
        gap_when="A loader can construct objects, including pickle, unsafe YAML, or a native formatter.",
        remediation=(
            "Decode with json.loads, yaml.safe_load, or the equivalent. "
            "Remove pickle.loads and yaml.load without SafeLoader."
        ),
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
            "Read outbound URLs from configuration. Resolve file paths under a fixed root and reject a path that escapes it. "
            "Accept a redirect only when it is a relative path on an allow-list, with no scheme or host."
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
            "Verify the token with an explicit algorithm list and reject alg=none. "
            "Set the session cookie HttpOnly and Secure. Set an expiry. Require a second factor on the password login shown in the excerpt."
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
        remediation=(
            "Set a non-zero request limit on the login, signup, password, and upload handlers. "
            "Remove a limiter exemption and any maximum of zero."
        ),
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
        remediation=(
            "Log a stable event name on authentication and authorization failure. "
            "Leave the logger enabled, and leave the password, token, and authorization header out of the message."
        ),
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
            "Pin an exact version in the lockfile and fetch it over https. "
            "When an advisory names a fixed version, set that version and refresh the lockfile with the tool that wrote it. "
            "Do not guess a version the advisory does not name, and do not pin a lower version as the repair. "
            "Point install config at a CA bundle that exists, or use the system store. "
            "Check a digest before running a download. Name workflow permissions instead of write-all."
        ),
    ),
}


def playbook_for(family: str) -> Playbook | None:
    return PLAYBOOKS.get(family)
