# Security Documentation

This document describes the security measures implemented in the NGINX Monitor Stack.

## Security Philosophy

The NGINX Monitor Stack follows a **defense-in-depth** approach:

1. **Minimal exposure** - All services bind to localhost by default
2. **Least privilege** - Services run as non-root users
3. **Secure defaults** - No configuration required to be secure
4. **Transparency** - All scripts are readable and auditable

## Network Security

### Binding to Localhost

All services are configured to bind to `127.0.0.1` (localhost) only:

| Service | Port | Binding |
|---------|------|---------|
| Prometheus | 9090 | 127.0.0.1 |
| Grafana | 3000 | 127.0.0.1 |
| Node Exporter | 9100 | 127.0.0.1 |
| NGINX Exporter | 9113 | 127.0.0.1 |
| NGINX stub_status | 8080 | 127.0.0.1 |

**This means**:
- No monitoring data is accessible from external networks
- No firewall rules are required
- External access requires explicit setup (SSH tunnel or reverse proxy)

### Accessing Remotely

**Option 1: SSH Port Forwarding (Recommended)**

The safest way to access monitoring dashboards:

```bash
ssh -L 3000:127.0.0.1:3000 user@your-server
```

Then access `http://localhost:3000` on your local machine.

**Option 2: Reverse Proxy with Authentication**

If you need persistent remote access, set up a reverse proxy:

```nginx
# Example NGINX configuration
server {
    listen 443 ssl;
    server_name monitor.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Basic authentication
    auth_basic "Monitoring";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Service Security

### Non-Root Execution

All services run as dedicated non-privileged users:

| Service | User |
|---------|------|
| Prometheus | `prometheus` |
| Grafana | `grafana` |
| Node Exporter | `nginx-exporter` |
| NGINX Exporter | `nginx-exporter` |

These users are created as system users with:
- No login shell (`/usr/sbin/nologin`)
- No home directory
- No password

### Systemd Hardening

All services use systemd security features:

```ini
# Applied to all services
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
CapabilityBoundingSet=
```

This prevents:
- Privilege escalation
- Access to sensitive kernel interfaces
- Execution of arbitrary code
- Access to home directories
- Creation of SUID/SGID files

## Data Security

### File Permissions

| Path | Permissions | Owner |
|------|-------------|-------|
| `/opt/nginx-monitor/` | 755 | root |
| `/etc/nginx-monitor/` | 750 | root |
| `/etc/nginx-monitor/secrets/` | 700 | root |
| Config files | 640 | service user |
| Data directories | 700 | service user |

### Secrets Management

Sensitive data (like Grafana admin password) is:
1. Generated using cryptographic randomness (`/dev/urandom`)
2. Stored in `/etc/nginx-monitor/secrets/` with mode `600`
3. Readable only by root

### Grafana Security

Grafana is configured with:
- Randomly generated admin password
- Anonymous access disabled
- User registration disabled
- Organization creation disabled
- Gravatar disabled (privacy)
- Cookie security flags enabled
- Content Security Policy enabled
- X-Content-Type-Options enabled
- X-XSS-Protection enabled

## Download Security

### Checksum Verification

All downloaded binaries are verified using SHA256 checksums:
1. Known checksums are embedded in the installer
2. Downloaded files are verified before installation
3. Mismatched checksums cause immediate failure

### HTTPS Only

All downloads use HTTPS with:
- TLS 1.2 minimum
- Automatic HTTPS upgrade
- No insecure fallback

## NGINX stub_status Security

The stub_status endpoint is configured securely:

```nginx
server {
    listen 127.0.0.1:8080;  # Localhost only

    location /nginx_status {
        stub_status on;
        allow 127.0.0.1;    # Explicit allowlist
        deny all;           # Deny everything else
    }
}
```

**Why this is secure**:
- Bound to localhost only (not accessible externally)
- Explicit IP allowlist
- Separate server block (isolated from your main site)
- Access logging disabled (reduces log noise)

## Audit Logging

Installation and configuration changes are logged to:
```
/var/log/nginx-monitor/audit.log
```

This includes:
- Component installations/uninstallations
- Configuration changes
- User who performed the action
- Timestamp

## What We Don't Collect

The NGINX Monitor Stack:
- Does NOT send data to any external service
- Does NOT collect personally identifiable information
- Does NOT log request bodies or sensitive data
- Does NOT phone home or check for updates automatically

All data stays on your server.

## Security Recommendations

### Regular Updates

Keep your system and monitoring stack updated:

```bash
# Update system packages
sudo apt update && sudo apt upgrade  # Debian/Ubuntu
sudo dnf update                       # RHEL/CentOS

# Update monitoring stack
cd /nginx-monitor
git pull
sudo ./install.sh
```

### Monitor the Monitors

Set up alerts for:
- Prometheus being down
- Node exporter being down
- Unusual resource usage on the monitoring server

### Backup Configuration

Regularly backup:
- `/etc/nginx-monitor/` - Configuration
- `/var/lib/nginx-monitor/grafana/` - Dashboards and settings

### Review Access

Periodically review:
- Who has SSH access to the server
- Grafana user accounts
- Any reverse proxy configurations

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do NOT** open a public GitHub issue
2. Write a private message
3. Include steps to reproduce
4. Allow time for a fix before public disclosure

## Security Checklist

Use this checklist to verify your installation:

- [ ] All services bound to 127.0.0.1 (`ss -tuln | grep LISTEN`)
- [ ] No monitoring ports exposed in firewall
- [ ] Grafana password changed from default
- [ ] SSH access is key-based only
- [ ] Regular system updates enabled
- [ ] Audit log is being written
- [ ] Backups are configured
