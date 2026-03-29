# Network Scanner - Docker Container

A web-based network scanner that periodically scans your network with nmap to discover devices, detect their OS, and identify open services.

## Features

- **Periodic Scanning**: Automatically scans the network every hour (configurable)
- **OS Detection**: Identifies operating systems using nmap's OS detection
- **Service Discovery**: Lists open ports and running services
- **Web Interface**: Beautiful, responsive web dashboard to view results
- **Device Classification**: Automatically categorizes devices (Windows PC, Linux, Router, Printer, etc.)
- **MAC Address Lookup**: Attempts to identify device vendors
- **Real-time Updates**: Manual scan trigger and auto-refresh
- **Persistent Storage**: Results are saved to JSON for persistence across container restarts
- **Slack Notifications**: Send scan results to Slack (optional)

## Requirements

- Docker
- Docker Compose (optional, but recommended)
- Network access to the target subnet (must be on the same network)

## Setup

### 1. Build the Container

Using Docker Compose (recommended):
```bash
docker-compose build
```

Or using Docker directly:
```bash
docker build -t network-scanner .
```

### 2. Run the Container

Using Docker Compose:
```bash
docker-compose up -d
```

Or using Docker directly:
```bash
docker run -d \
  --name network-scanner \
  --net host \
  -p 5000:5000 \
  -v $(pwd)/scan_results.json:/app/scan_results.json \
  network-scanner
```

### 3. Access the Web Interface

Open your browser and navigate to:
```
http://localhost:5000
```

## Configuration

### Network to Scan

Edit the `NETWORK` variable in `app.py` (default: `192.168.12.0/24`):

```python
NETWORK = "192.168.12.0/24"
```

Or set via environment variable in docker-compose.yml:

```yaml
environment:
  - NETWORK=192.168.0.0/24
```

### Scan Interval

Edit the `SCAN_INTERVAL` variable in `app.py` (default: 3600 seconds = 1 hour):

```python
SCAN_INTERVAL = 3600  # in seconds
```

Or set via environment variable:

```yaml
environment:
  - SCAN_INTERVAL=1800  # 30 minutes
```

### Slack Notifications (Optional)

To receive scan results via Slack:

1. **Create a Slack Incoming Webhook**:
   - Go to your Slack workspace → Settings → App Management
   - Create a new app or use an existing one
   - Enable "Incoming Webhooks"
   - Add a new webhook and copy the URL

2. **Set the webhook URL** in `app.py`:
   ```python
   SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL', '')
   ```

3. **Or set via environment variable** in docker-compose.yml:
   ```yaml
   environment:
     - SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
   ```

4. **The scanner will post notifications** to your Slack channel after each scan completes.

**Note**: Keep your webhook URL secure. Don't commit it to version control—use environment variables instead.

## Important Notes

### Network Access

The container **must** have network access to the target subnet. Use `--net host` to ensure the container can access your local network.

### Permissions

nmap requires elevated privileges for OS detection. The container runs as root, which is necessary for full functionality. If running on restricted systems, you may need to adjust the Dockerfile or run with `--cap-add=NET_ADMIN`.

### Timing

Initial scan runs immediately on startup, then subsequent scans run at the specified interval.

## API Endpoints

### Get Current Results
```
GET /api/devices
```

Returns JSON with discovered devices and scan metadata.

### Trigger Manual Scan
```
POST /api/scan-now
```

Starts a new scan immediately (if one isn't already running).

## Output

Scan results are automatically saved to `scan_results.json` with the following structure:

```json
{
  "devices": [
    {
      "ip": "192.168.12.100",
      "hostname": "desktop-computer",
      "mac": "00:1A:2B:3C:4D:5E",
      "vendor": "Intel",
      "os": "Microsoft Windows 10 or 11",
      "device_type": "Windows PC",
      "services": [
        {
          "port": 445,
          "protocol": "tcp",
          "service": "microsoft-ds",
          "version": "Windows 10/11 File Sharing"
        }
      ]
    }
  ],
  "last_scan": "2024-01-15T10:30:45.123456",
  "scan_in_progress": false
}
```

## Troubleshooting

### Container exits immediately
Check logs: `docker logs network-scanner`

### No devices found
- Ensure the container is on the same network: `docker run --net host ...`
- Verify the NETWORK variable matches your subnet
- Check that devices are online and responding to pings

### OS detection not working
- Some devices may not respond to OS detection probes
- Firewalls may block nmap probes
- Results improve with devices that respond to common ports (HTTP, SSH, RDP, SMB)

### Slow scans
- Large subnets take longer to scan
- Adjust timeout values in `app.py` if needed
- Consider running on a more powerful host

## Logs

View container logs:
```bash
docker logs -f network-scanner
```

## Stopping the Container

```bash
docker-compose down
```

Or:
```bash
docker stop network-scanner
docker rm network-scanner
```

## License

This project is provided as-is for network administration purposes.
