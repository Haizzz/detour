# detour

Performance focused DNS proxy

A minimal, single-threaded DNS proxy server written in Rust using tokio. Forwards DNS queries to an upstream server (default: Google DNS) over UDP and TCP without caching or filtering.

## Features

- Single-threaded async runtime (tokio current_thread)
- UDP and TCP DNS query support
- Pass-through forwarding (no caching, no blocklists)
- Configurable bind address and upstream server

## Building

```bash
cargo build --release
```

## Running

```bash
# Default: listens on 127.0.0.1:5353, forwards to 8.8.8.8:53
cargo run --release

# Custom port
cargo run --release -- --port 53

# Custom upstream (Cloudflare)
cargo run --release -- --upstream 1.1.1.1:53

# Listen on all interfaces
cargo run --release -- --bind 0.0.0.0 --port 5353
```

## CLI Options

```
Options:
  -p, --port <PORT>          Local port to listen on [default: 5353]
  -b, --bind <BIND>          Bind address [default: 127.0.0.1]
  -u, --upstream <UPSTREAM>  Upstream DNS server (host:port) [default: 8.8.8.8:53]
  -h, --help                 Print help
```

## Testing

Windows nslookup doesn't support custom ports. Use PowerShell instead:

**UDP test:**
```powershell
$query = [byte[]](0x00,0x01,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
  0x06,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01)
$udp = New-Object System.Net.Sockets.UdpClient
$udp.Send($query, $query.Length, "127.0.0.1", 5353)
```

**TCP test:**
```powershell
$query = [byte[]](0x00,0x1c,0x00,0x01,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
  0x06,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01)
$tcp = New-Object System.Net.Sockets.TcpClient
$tcp.Connect("127.0.0.1", 5353)
$stream = $tcp.GetStream()
$stream.Write($query, 0, $query.Length)
$response = New-Object byte[] 512
$n = $stream.Read($response, 0, 512)
Write-Host "Received $n bytes"
$tcp.Close()
```

On Linux/macOS with dig:
```bash
dig @127.0.0.1 -p 5353 google.com        # UDP
dig @127.0.0.1 -p 5353 +tcp google.com   # TCP
```

## License

MIT
