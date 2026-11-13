---
title: Scope and trust
description: Understand what local approval and SSH forwarding authorize.
---

## Execution and forwarding

This is an initial implementation for macOS and Linux. It supports pipes and binary streams. It does not allocate a PTY, forward terminal input, resize terminals, or support interactive programs such as editors. When the remote caller's stdin is a terminal, the command receives EOF; pipe or redirect input to send it to the laptop.

Forwarding the proxy grants the ability to request local execution, use admitted SSH keys, and request permitted management changes. Local policy checks every request. Commands, signatures, and management require approval unless their rule or default sets `none`. Commands and signatures can also use a valid explicit lease. The upstream agent's restrictions and approval requirements also apply. Approving a shell, interpreter, or command that consumes instructions on stdin can authorize arbitrary local execution. Stdin is streamed after approval and is not reviewed by the prompt.

Requests are labeled with an unverified origin. This version preserves OpenSSH session binding messages for the upstream agent, but does not verify those bindings itself or map them to hostnames. Signing format classification does not prove the remote destination or enforce host allowlists. Anyone able to access the forwarded socket, including an administrator on the remote host, can request execution or relay the socket elsewhere. The local policy and approval prompt govern each request.

Commands run directly as the local user and can access local files, credentials, and environment variables. Their output goes to the requester. Approval is not an execution sandbox. An approved program can access the original agent socket directly if it knows its path, so an arbitrary command grant also grants that program the local user's access. Disconnects and timeouts cancel execution and kill the command's process group. Pipelined requests or a blocked stdin stream can delay disconnect detection until a timeout; descendants that detach from the process group can outlive cancellation.
