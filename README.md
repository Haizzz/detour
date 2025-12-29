# Detour

A performance-focused DNS proxy written in Rust.

## Features

- **Single-threaded async** - Uses tokio's current_thread runtime for minimal overhead
- **UDP and TCP support** - Full DNS transport support
- **Response caching** - TTL-aware caching with configurable min/max bounds
- **Ad blocking** - Optional blocklist support for filtering domains
- **Upstream racing** - Queries multiple upstreams in parallel, uses first response
- **Verbose logging** - Optional request logging with timing information

## Building

```bash
cargo build --release
```

## Usage

```bash
# Default: listens on 127.0.0.1:5353, forwards to Cloudflare + Google DNS
./target/release/detour

# With verbose logging
./target/release/detour -v

# Custom port (requires root/admin for port 53)
sudo ./target/release/detour -p 53

# Custom upstream server
./target/release/detour -u 9.9.9.9:53

# Multiple upstreams (races all, uses first response)
./target/release/detour -u 1.1.1.1:53 -u 8.8.8.8:53

# Listen on all interfaces
./target/release/detour -b 0.0.0.0
```

## CLI Options

```
Usage: detour [OPTIONS]

Options:
  -p, --port <PORT>          Local port to listen on [default: 5353]
  -b, --bind <BIND>          Bind address [default: 127.0.0.1]
  -u, --upstream <UPSTREAM>  Upstream DNS servers (host:port), races all and
                             uses first response [default: 1.1.1.1:53 1.0.0.1:53
                             8.8.8.8:53 8.8.4.4:53]
  -v, --verbose              Print verbose logging (domain, blocked status, timing)
  -h, --help                 Print help
```

## Example Output

With `-v` (verbose) flag:

```
Detour DNS proxy
  Listening on 127.0.0.1:5353 (UDP + TCP)
  Upstreams: 1.1.1.1:53, 1.0.0.1:53, 8.8.8.8:53, 8.8.4.4:53
  Blocked domains: 0

[2025-12-29 08:42:59] [UDP] google.com FORWARDED total=9.150ms (from 1.1.1.1:53)
[2025-12-29 08:43:01] [UDP] google.com CACHED total=0.042ms
[2025-12-29 08:43:05] [TCP] example.com FORWARDED total=12.304ms upstream=11.892ms (from 8.8.8.8:53)
[2025-12-29 08:43:10] [UDP] ads.tracker.com BLOCKED total=0.015ms
```

## Installation (Linux/systemd)

Install as a systemd service:

```bash
cargo build --release
sudo ./target/release/detour install
```

This copies the binary to `/usr/local/bin/detour` and enables the service.

```bash
# Check status
systemctl status detour

# View logs
tail -f /var/log/detour.log

# Uninstall
sudo detour uninstall
```

## Testing

Using `dig` (Linux/macOS):

```bash
# UDP query
dig @127.0.0.1 -p 5353 google.com

# TCP query
dig @127.0.0.1 -p 5353 +tcp google.com

# Query specific record type
dig @127.0.0.1 -p 5353 google.com AAAA
```

Using `nslookup` (Windows, after setting system DNS):

```cmd
nslookup google.com 127.0.0.1
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Detour                             │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐                       │
│  │ UDP Transport│  │ TCP Transport│                      │
│  └──────┬──────┘  └──────┬──────┘                       │
│         │                │                              │
│         └───────┬────────┘                              │
│                 ▼                                       │
│         ┌─────────────┐                                 │
│         │   Resolver  │                                 │
│         └──────┬──────┘                                 │
│                │                                        │
│    ┌───────────┼───────────┐                            │
│    ▼           ▼           ▼                            │
│ ┌───────┐ ┌─────────┐ ┌──────────┐                      │
│ │Filter │ │  Cache  │ │ Upstream │                      │
│ └───────┘ └─────────┘ └──────────┘                      │
└─────────────────────────────────────────────────────────┘
```

- **Transports** handle network I/O (UDP/TCP)
- **Resolver** decides: block, return cached, or forward
- **Filter** checks blocklist for ad/tracker domains
- **Cache** stores responses with TTL-based expiration

## Benchmarks

Run benchmarks:

```bash
cargo bench
```
