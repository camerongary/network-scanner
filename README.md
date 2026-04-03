# Network Scanner - Docker Container

A comprehensive web-based network scanner that periodically scans your network with nmap to discover devices, detect their OS, identify open services, and provides historical trends with Slack notifications.

## Features

### Core Scanning
- **Periodic Scanning**: Automatically scans the network every hour (configurable)
- **OS Detection**: Multi-method OS identification:
  - nmap OS fingerprinting (-O flag)
  - Service-based inference (SSH, RDP, RTSP, etc.)
  - MAC OUI database lookup (150+ vendors)
  - Hostname pattern matching
- **Service Discovery**: Lists open ports, running services, and versions
- **Device Classification**: Automatically categorizes devices:
  - Windows (PC, Server)
  - macOS, iOS
  - Linux (Desktop, Server, Embedded)
  - Network devices (Router, Printer, Camera, NAS, Switch)
  - Virtual machines (Hyper-V, VMware, VirtualBox, KVM)

### Dashboard & Visualization
- **Beautiful Web Interface**: Responsive, real-time dashboard
- **Device List**: Sortable device table with filtering by type
- **Expandable Details**: Click to see full device info including services
- **Historical Charts**: 
  - Device count trends over time
  - Device type distribution (doughnut chart)
  - New device tracking
- **Real-time Updates**: Auto-refresh every 30 seconds
- **Manual Scan Trigger**: "Scan Now" button for immediate scans
- **Scan Progress Indicator**: Visual feedback when scan is running

### Data & Notifications
- **Slack Integration**: Automatic notifications with device details
- **New Device Tracking**: Green badges for newly discovered devices
- **Persistent Storage**: JSON-based storage across container restarts
- **Historical Data**: Last 100 scans stored automatically
- **MAC Vendor Lookup**: Identifies device manufacturers

## Requirements

- Docker & Docker Compose
- Network access to target subnet (must be on same network)
- Slack webhook (optional, for notifications)
- Linux host (nmap requires certain capabilities)

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/camerongary/network-scanner.git
cd network-scanner
```

### 2. Configure (Optional)
Edit `docker-compose.yml` to customize:
```yaml
environment:
  - NETWORK=192.168.12.0/24      # Your network subnet
  - SCAN_INTERVAL=3600            # Scan interval in seconds (1 hour)
  - TZ=America/Los_Angeles        # Your timezone
```

Add Slack webhook to `app.py`:
```python
SLACK_WEBHOOK = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

### 3. Deploy
```bash
docker-compose build
docker-compose up -d
```

### 4. Access
Open browser: `http://localhost:5000`

## Configuration

### Network Subnet
Change `NETWORK` in `docker-compose.yml`:
```yaml
environment:
  - NETWORK=192.168.0.0/24
```

### Scan Interval
Change `SCAN_INTERVAL` in seconds (default: 3600 = 1 hour):
```yaml
environment:
  - SCAN_INTERVAL=1800  # 30 minutes
```

### Timezone
Set `TZ` to your timezone (default: America/Los_Angeles):
```yaml
environment:
  - TZ=Europe/London
```

### Slack Notifications
Get a webhook from Slack and add to `app.py`:
```python
SLACK_WEBHOOK = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

```

## API Endpoints

### Get Current Scan Results
```
GET /api/devices
```
Returns: Current devices, last scan time, scan progress status

### Get Historical Data
```
GET /api/history
```
Returns: Last 100 scans with device counts and types

### Trigger Manual Scan
```
POST /api/scan-now
```
Returns: Scan status

## Docker Commands

### View Logs
```bash
docker logs -f network-scanner
```

### Stop Container
```bash
docker-compose down
```

### Rebuild Container
```bash
docker-compose down
docker rmi network-scanner-network-scanner
docker-compose build
docker-compose up -d
```

## Project Structure

```
network-scanner/
├── Dockerfile           # Container definition with nmap
├── docker-compose.yml   # Docker Compose configuration
├── requirements.txt     # Python dependencies
├── app.py              # Main Flask application
├── wsgi.py             # Gunicorn WSGI entry point
├── templates/
│   └── index.html      # Web dashboard (HTML/CSS/JS)
├── scan_data/          # Persistent scan results
│   └── results.json    # Historical scan data
├── README.md           # This file
└── .gitignore          # Git ignore rules
```

## Performance Notes

- **Scan Duration**: 5-15 minutes depending on network size and responsiveness
- **CPU Usage**: Moderate during scans, minimal at rest
- **Memory**: ~200MB base + growth with device count
- **Storage**: ~1KB per scan in JSON format

## Troubleshooting

### Scans Not Completing
- Increase timeout in Dockerfile if network is slow
- Check nmap arguments in app.py
- Verify network connectivity

### Low OS Detection Rate
- Some devices block OS fingerprinting for security
- Check device firewalls
- Verify devices are responsive on common ports

### Timezone Incorrect
- Update `TZ` environment variable in docker-compose.yml
- Restart container: `docker-compose restart`

### Slack Notifications Not Working
- Verify webhook URL is correct
- Check webhook is still valid
- Review logs: `docker logs network-scanner | grep -i slack`

## Development

### Local Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

### Making Changes
1. Edit files locally
2. Test with `docker-compose up`
3. Commit and push to GitHub
4. Pull on server and redeploy

## License

MIT License - Feel free to use and modify for your needs

## Contributing

Pull requests welcome! Areas for improvement:
- Additional OS detection methods
- More detailed service identification
- Custom alert thresholds
- Export to CSV/Excel
- API authentication
- Dark mode UI

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
