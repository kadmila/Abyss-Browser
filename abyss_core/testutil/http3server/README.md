# HTTP/3 Test Server

A simple HTTP/3 server for testing purposes.

## Features

- Serves files from the current directory
- Runs on port 4433 (https://localhost:4433)
- Uses self-signed certificate (auto-generated)
- Standalone executable

## Build

```bash
go build -o http3server.exe .
```

## Run

```bash
./http3server.exe
```

The server will start on `https://localhost:4433` and serve files from the current directory.

## Usage

Access files via HTTP/3:
- `https://localhost:4433/` - Directory listing
- `https://localhost:4433/test.txt` - Serve test.txt file
- etc.

## Testing with curl

```bash
# Requires curl with HTTP/3 support
curl --http3 -k https://localhost:4433/
```

Note: `-k` flag is needed because the certificate is self-signed.
