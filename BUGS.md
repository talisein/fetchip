# Known bugs

## Without -4 or -6, IPv4 and IPv6 answers share one vote

With neither flag, `ctx.requested_family` is `Any`:

- The HTTP client and the whoami resolvers resolve both families and use whichever endpoint connects first.
- `query_http_public_ip` skips its family check.
- `IPConsensus` counts every answer as a vote, whatever its family.

A whoami service reports the address the query arrived from, so on a dual-stack host some services report the IPv4 address and some the IPv6 one. `whoami.akamai.net` (`A_ONLY`) always reports IPv4. The others depend on which family connected first.

Consequences:

- The answers can end up split evenly between the two addresses once every candidate service has answered. No address reaches a strict majority, and fetchip exits EXIT_FAILURE although every service answered correctly.
- When one address does win, whether it is IPv4 or IPv6 depends on the shuffle.

Not seen on a v4-only host, where every answer is IPv4.

Workaround: pass `-4` or `-6`.

Possible fixes, both undecided:

- Tally each family separately.
- Make `Any` pick one family per run.

Defaulting `Any` to IPv4 was rejected.
