# LogAnlyzer

LogAnlyzer is a lightweight **CLI-based log analysis tool** designed to help developers and system administrators detect suspicious activity from web server access logs.

This project focuses on **defensive security**, clarity, and practical usage rather than exploitation.

---

## What Does LogAnlyzer Do?

LogAnlyzer reads server access logs and analyzes request patterns to identify:

- Abnormally high request rates
- Potential brute-force attempts
- Repeated access to sensitive endpoints
- General traffic statistics

The tool works completely offline and does not require external services.

---

## Key Features

- Parse Apache / Nginx access logs
- Count total requests and unique IP addresses
- Detect suspicious IPs using configurable thresholds
- Detect access to sensitive paths like `/login` or `/admin`
- Colored CLI output for readability
- Export reports to JSON or CSV format
- Designed for large log files

---

## Screenshot

Example CLI output:

![LogAnlyzer Demo](assets/1.jpg)

---

## How It Works

1. Reads the log file line by line (memory efficient)
2. Extracts IP address, HTTP method, and request path
3. Aggregates request count per IP
4. Applies detection rules:
   - High request count threshold
   - Sensitive endpoint access
5. Generates a readable security report

---

## How to Run

Basic usage:

```bash
php loganlyzer.php access.log
```

Export analysis result to JSON:

```bash
php loganlyzer.php access.log --json
```

Export analysis result to CSV:

```bash
php loganlyzer.php access.log --csv
```

You can combine flags:

```bash
php loganlyzer.php access.log --json --csv
```

---

## Configuration

Detection rules can be adjusted inside the configuration file:

- Request threshold per IP
- Sensitive endpoint paths

This allows the tool to adapt to different server environments.

---

## Use Cases

- Detect brute-force login attempts
- Identify abusive IP addresses
- Analyze traffic behavior
- Learn defensive log analysis techniques

---

## Requirements

- PHP 7.4 or higher
- CLI environment (Linux, macOS, Termux)

---

## Disclaimer

This tool is intended for **educational and defensive security purposes only**.  
Do not use it for unauthorized monitoring or malicious activity.

---

## License

MIT License
