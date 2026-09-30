# fetchip

fetchip is a reliable, non-forking public IP lookup.

It makes one promise: it writes a valid, normalized IP address to stdout, or it exits with an error. It never prints a partial answer, an error page, or anything else a script would have to check for.

```sh
ip=$(fetchip -4) || exit 1
```

## How it works

fetchip asks several public "what is my IP" services and prints an address only when they agree on it. Services are drawn in random order, a few at a time. An address wins once at least two services report it and it holds a strict majority of the answers so far in its family. It also needs a vote from the most trustworthy kind of service in the run: an HTTPS service if there is one, otherwise a DNS service that asks the provider's authoritative server. DNS and plain HTTP can be answered by anything on the path, so their votes count towards the majority but cannot win on their own. `-s HTTP` and `-s DNS_AAAA` have neither kind, and skip this check. IPv4 and IPv6 answers are tallied separately, so without `-4` or `-6` a dual-stack host prints whichever family's address wins first. When the remaining services can no longer produce a winner, fetchip gives up and exits with an error.

It speaks HTTP, HTTPS and DNS itself, in one process, using Boost.Asio and Boost.Beast. It never forks curl, dig or a shell. Host names are looked up through systemd-resolved's Varlink interface rather than getaddrinfo, so the lookups time out and cancel like everything else. Every query has a timeout, and outstanding queries are cancelled as soon as the outcome is settled.

Answers are compared, and printed, in canonical form, so two spellings of the same IPv6 address count as one vote.

## Usage

```
fetchip [-4 | -6] [-s TYPE] [-n NAME] [-i] [-v]
```

| Option | Meaning |
|---|---|
| `-4` | Fetch the public IPv4 address |
| `-6` | Fetch the public IPv6 address |
| `-s`, `--service TYPE` | Only ask services of one type: `HTTP`, `HTTPS`, `DNS`, `DNS_A`, `DNS_AAAA` or `DNS_TXT`. `DNS` selects all three DNS types. `HTTP` implies `-i` |
| `-n`, `--name NAME` | Ask only the named service and print its answer, without consensus |
| `-i`, `--insecure` | Use the plain HTTP endpoints instead of HTTPS |
| `-v`, `--verbose` | Copy log messages to stderr |
| `-h`, `--help` | Show help |

`fetchip --list type` and `fetchip --list name` print the values `-s` and `-n` accept. The bash completion uses them.

## Services

| Name | Types |
|---|---|
| ifconfig.me, icanhazip, ipecho, ident.me, dnsomatic, amazon, akamai, ipinfo, ipify | HTTP, HTTPS |
| opendns, quad9 | DNS_A, DNS_AAAA |
| akamai-dns | DNS_A |
| google, akahelp | DNS_TXT |

DNS services are queried directly at the provider's own server, not through the system resolver. Only the server's own address is looked up through systemd-resolved. akamai-dns, google and akahelp ask the authoritative server for their name, so a reply without the authoritative-answer flag is refused: it means something on the path, such as a router that redirects port 53, answered in the server's place and reported its own address. opendns and quad9 are public resolvers, which never set that flag.

## Logging

fetchip logs to the systemd journal:

```sh
journalctl -t fetchip
```

Debug messages go to the journal only in a debug build (`meson setup --buildtype=debug`, Meson's default). With `-v`, fetchip also writes every message, debug included, to stderr. stdout carries only the address.

## Exit status

`0` with an address on stdout, or `1` with nothing on stdout.

## Building

fetchip needs a C++26 compiler, Meson, libsystemd (257 or later), Boost 1.86 or later and OpenSSL 3. The other dependencies are fetched as Meson wraps.

```sh
meson setup build --buildtype=release
meson compile -C build
meson test -C build
meson install -C build
```

`meson install` also installs the bash completion.
