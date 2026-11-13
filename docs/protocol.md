# Protocol

The protocol is experimental. Both endpoints must use the same version.

Agent traffic uses the framing from [RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html): a four-byte big-endian payload length followed by the payload, including its one-byte type. lend accepts payloads from 1 to 262144 bytes and rejects larger lengths before allocation.

The proxy admits identity listings, policy-approved signing and management requests, validly framed OpenSSH session binding requests, and its own extensions. Other operations are refused. Allowed upstream requests use one persistent connection per downstream connection. This preserves connection-scoped state such as [OpenSSH session bindings](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent). lend checks binding framing and leaves cryptographic verification to the upstream agent. It does not claim to verify a request's origin.

## SSH key operations

Type 11 requests an identity list. Type 12 replies are parsed completely and filtered by the `ssh` key policy before being returned. Key fingerprints are SHA256 of the exact public key blob, encoded as unpadded base64 with the `SHA256:` prefix. Certificate blobs are distinct identities.

Type 13 signing requests contain an SSH string key blob, an SSH string payload, and uint32 flags. Flags must be 0, 2, or 4. Trailing data and malformed fields are refused. The proxy checks the fingerprint, signing purpose, namespace, and available signature quota before requesting local approval. Only after approval does it forward the original request unchanged to the original agent. Type 14 replies are structurally checked; a single-byte type 5 failure is passed back without consuming signature quota. Local policy and approval failures also return type 5. A successful upstream signature consumes a quota use before delivery to the downstream client.

The `ssh` purpose recognizes SSH user authentication payloads from [RFC 4252](https://www.rfc-editor.org/rfc/rfc4252.html), including OpenSSH's hostbound variant. The public key inside the payload must equal the signing request's key. The `sshsig` purpose recognizes the signing data format in [PROTOCOL.sshsig](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig), with a nonempty namespace, a supported hash name, and its corresponding digest length. Other payloads are classified as `raw`. Purpose classification does not verify a remote host's identity.

`session-bind@openssh.com` is forwarded on the original connection. The `query` extension is answered locally and advertises only `query`, `session-bind@openssh.com`, and the lend execution extension. Unknown extensions and legacy agent messages return type 5 without reaching the upstream agent.

## Management requests

Management uses the standard agent message formats from RFC 9987. Types 17 and 25 map to `add-key`, 18 to `remove-key`, 19 to `remove-all-keys`, 20 and 26 to `add-provider`, 21 to `remove-provider`, 22 to `lock`, and 23 to `unlock`. Types 25 and 26 include constraints. The `ssh.management` policy is checked separately from signing policy. Every allowed management request receives its configured approval before the original packet is sent on the same upstream connection. Only single-byte success (6) and failure (5) replies are accepted. Local refusal returns type 5.

Key additions parse supported private-key formats and check their correspondence to the public identity used for fingerprint selection. Certificate identities use the certificate blob's fingerprint. Management summaries contain public target metadata, requested lifetime and confirmation, and recognized extension names. Private key values, security-key handles, PINs, and passphrases are never added to the summary. The original packet buffer is cleared after processing.

Supported constraints are lifetime (1), confirmation (2), and recognized extension constraints (255): `sk-provider@openssh.com`, `restrict-destination-v00@openssh.com`, and `associated-certs-v00@openssh.com`. Provider selection also applies to an explicit security-key provider on an add-key request. Destination payloads are framed and forwarded unchanged; their semantics and certificate signatures are validated by the upstream agent. Duplicate or unknown constraints, trailing bytes, invalid public/private correspondence, and malformed secret fields are refused. Secret text fields must be NUL-free; lock passphrases must be nonempty. Public comments and provider identifiers are limited to 4096 UTF-8 bytes. Associated certificate lists are limited to 16 entries.

## Execution handshake

The client sends an extension request:

```text
byte    27 (SSH_AGENTC_EXTENSION)
string  "exec-v1@lend.antoniomika.com"
bytes   UTF-8 JSON: {"args":["executable","argument",...],"reason":"why this is needed","caller":{"source":"cli","host":"agent-vm"}}
```

An SSH `string` has its own four-byte length. The JSON occupies the remainder of the packet. Only `args`, optional `reason`, and optional `caller` are accepted. The request allows at most 256 arguments and 8192 bytes of argument contents, with a nonempty executable and no embedded NUL bytes. A reason must be valid UTF-8 without NUL and at most 2048 bytes. The remote side cannot set a local working directory, environment, or approval requirement. A local policy can require a nonempty reason.

The `caller` object is requester-supplied display metadata. Its `source` must be `cli`, `mcp`, or `client`. Optional fields are `host`, `user`, `uid`, `pid`, `parent_pid`, `executable`, `parent_process`, `directory`, `ssh_connection`, `client_name`, `client_version`, `tool`, and `request_id`. PIDs are nonnegative signed 32-bit values; UID is unsigned 32-bit. All strings must be valid UTF-8 without NUL. Host, user, client name, and request ID are limited to 256 bytes each; client version and tool to 128 bytes each; SSH connection to 512 bytes; executable, parent process, and directory to 4096 bytes each. Unknown fields, including claims of verified identity, are rejected. Missing caller metadata is accepted and displayed as unavailable. These fields have no role in authorization.

The server attaches local peer credentials from its Unix socket and at most eight accepted session-binding host-key hints to the approval summary. Neither can be supplied through the request JSON. Local socket credentials describe the laptop's connected process at connection time. Binding hints are recorded only after an upstream success response, remain local to that connection, and are explicitly unverified by lend.

The server resolves the executable and its symlinks locally, checks the local command policy, obtains the required approval, and replies:

```text
byte    29 (SSH_AGENT_EXTENSION_RESPONSE)
string  "exec-v1@lend.antoniomika.com"
byte    240 (ready)
```

Refusal returns a single-byte `28` (`SSH_AGENT_EXTENSION_FAILURE`), then closes the connection. This includes invalid requests, policy denials, unavailable commands, credential retrieval failures, and denied or expired approval. A plain agent without the extension normally returns `5` (`SSH_AGENT_FAILURE`).

The ready response switches this dedicated connection to the private streaming protocol below. This switch is an lend convention. Regular agent requests cannot be sent on the connection after it switches. SSH carries the byte stream in its agent channel. Each execution uses a new connection.

## Streaming

Streaming uses the same length prefix, with private-use message types:

| Type | Direction | Payload after type |
| --- | --- | --- |
| 241 | Client to agent | Stdin bytes |
| 242 | Client to agent | Empty, closes command stdin |
| 243 | Agent to client | Stdout bytes |
| 244 | Agent to client | Stderr bytes |
| 245 | Agent to client | Four-byte big-endian exit status |
| 246 | Agent to client | UTF-8 execution error |

Each sender emits data chunks of at most 32768 bytes. Readers enforce the overall frame limit. Stdin bytes are valid only before stdin EOF. The server rejects duplicate EOF, data after EOF, and unknown message types. Stdout and stderr each retain their byte order; their relative interleaving is unspecified.

The agent sends exit status after output has drained, then closes the connection. An execution error also ends the session. The client maps protocol and transport failures to exit status 125. Closing the client connection requests cancellation. Approval and execution timeouts are configured locally.

## Local session state

Profiles, credential references, approval leases, queues, history, and local activity IDs are selected on the laptop. The remote execution request schema is unchanged. It cannot set a profile, lease, environment, credential reference, or control action. Policy checks and signature quotas apply before every approval or lease use. Management requests never reuse approval.

`lend ssh` creates an independent local proxy and control socket per SSH process. Its daemon follows the wrapper through a parent lifetime pipe. The wrapper forwards the proxy socket and keeps control local. Leases are available only for these supervised sessions with available desktop lock tracking. They are bounded by exact command scope or key signing scope, duration, use count, device state, and the session's lifetime.

## Local control protocol

The sibling `agent.sock.control` socket uses one bounded JSON request and JSON response per connection, followed by close. It is a private Unix socket and does not speak SSH agent framing. SSH agent extension discovery does not advertise it. Unknown agent extensions continue to be refused.

Requests contain `action` and an optional `id`. Actions are `status`, `history`, `pause`, `resume`, `revoke`, and `clear-leases`. IDs refer to local activity entries or grants; caller-supplied request IDs cannot revoke work. Unknown fields are refused. Requests are limited to 4096 bytes and connections have a five-second deadline.

Responses include local session state, active entries, optional completed history, current grants, and counted signature uses. Errors appear in `error`. Active entries can contain full approval summaries for local inspection. Completed records omit those summaries and only include arguments when local policy opted into argument logging. The CLI bounds control response decoding at 32 MiB. Neither command output nor secret values belong in control responses.
