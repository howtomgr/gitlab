# GitLab Installation and Configuration Guide



## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Introduction

GitLab is a comprehensive DevOps platform that provides Git repository management, CI/CD pipelines, issue tracking, container registry, and security scanning capabilities. As a Free and Open Source Software (FOSS) solution, GitLab Community Edition offers robust features for teams of all sizes, while GitLab Enterprise Edition provides additional advanced features for enterprise environments.

### FOSS Context
GitLab Community Edition (CE) is released under the MIT License and provides:
- Core Git repository management
- Issue tracking and project management
- Integrated CI/CD with GitLab Runner
- Built-in container registry
- Merge request workflows
- Wiki and documentation
- Security scanning (basic)

GitLab Enterprise Edition (EE) extends CE with premium features including advanced security scanning, compliance management, geo-replication, and enterprise authentication integrations.

### Key Features
- **Repository Management**: Git-based version control with advanced merge request workflows
- **CI/CD Platform**: Integrated continuous integration and deployment with GitLab Runner
- **Container Registry**: Built-in Docker registry with vulnerability scanning
- **Security**: SAST, DAST, dependency scanning, and secret detection
- **Project Management**: Issue tracking, milestones, and agile planning tools
- **Monitoring**: Performance monitoring and error tracking
- **Authentication**: LDAP, SAML, OAuth, and multi-factor authentication support

## 2. Prerequisites

### 10. System Requirements
- **Operating System**: Linux (RHEL/CentOS 8+, Ubuntu 20.04+, Debian 10+, SUSE Linux, Arch Linux), macOS 10.15+, Windows 10/11, or FreeBSD 12+
- **Memory**: 8GB RAM minimum, 16GB+ recommended for production, 32GB+ for large installations
- **CPU**: 4 cores minimum, 8+ recommended for production
- **Storage**: 50GB+ available disk space, SSD strongly recommended for database and Git repositories
- **Network**: Stable internet connection, open ports 80, 443, and 22 (or custom SSH port)

### Required Software Dependencies
- **Package Manager**: apt (Debian/Ubuntu), yum/dnf (RHEL/CentOS/Fedora), pacman (Arch), zypper (openSUSE), pkg (FreeBSD)
- **System Tools**: curl, wget, openssh-server, ca-certificates, tzdata, perl
- **Mail Transfer Agent**: Postfix, Sendmail, or external SMTP service
- **Firewall**: firewalld, ufw, or iptables for security configuration

### Network Requirements
- **Domain Name**: Fully qualified domain name for external access
- **SSL Certificates**: Valid SSL/TLS certificates for production deployment (Let's Encrypt recommended)
- **Firewall Ports**: 
  - 80/tcp (HTTP, redirects to HTTPS)
  - 443/tcp (HTTPS)
  - 22/tcp or custom port (SSH/Git)
  - 2222/tcp (GitLab Shell SSH, if configured)
- **SMTP Server**: For email notifications (password resets, notifications, etc.)

### Optional Components
- **External Database**: PostgreSQL 12+ for high availability setups
- **External Redis**: Redis 6+ for session storage and caching
- **Object Storage**: S3-compatible storage for artifacts, uploads, and backups
- **Load Balancer**: For multi-node GitLab installations
- **Monitoring**: Prometheus, Grafana for advanced monitoring

## 3. Installation

GitLab provides native packages for all major operating systems. The Omnibus package is the recommended installation method as it includes all dependencies and provides automatic updates.

### RHEL/CentOS/Rocky Linux/AlmaLinux

#### RHEL/CentOS 8+ / Rocky Linux / AlmaLinux
```bash
# Update system packages
sudo dnf update -y

# Install required dependencies
sudo dnf install -y curl policycoreutils-python-utils openssh-server perl postfix

# Enable and start required services
sudo systemctl enable --now sshd postfix

# Configure SELinux policies for GitLab
sudo setsebool -P httpd_can_network_connect 1
sudo setsebool -P httpd_can_network_relay 1
sudo setsebool -P httpd_read_user_content 1
sudo setsebool -P httpd_enable_homedirs 1

# Configure firewall rules
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-port=2222/tcp
sudo firewall-cmd --reload

# Add GitLab official repository
curl -fsSL https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.rpm.sh | sudo bash

# Install GitLab Enterprise Edition
sudo EXTERNAL_URL="https://gitlab.example.com" dnf install -y gitlab-ee

# For Community Edition instead:
# sudo EXTERNAL_URL="https://gitlab.example.com" dnf install -y gitlab-ce

# Initial configuration and start services
sudo gitlab-ctl reconfigure

# Check installation status
sudo gitlab-ctl status
```

#### RHEL/CentOS 7 (Legacy)
```bash
# Install dependencies
sudo yum install -y curl policycoreutils-python openssh-server perl postfix

# Configure services
sudo systemctl enable --now sshd postfix
sudo lokkit -s http -s https -s ssh

# Add repository and install
curl -fsSL https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.rpm.sh | sudo bash
sudo EXTERNAL_URL="https://gitlab.example.com" yum install -y gitlab-ee
sudo gitlab-ctl reconfigure
```

### Debian/Ubuntu

#### Ubuntu 20.04+ / Debian 10+
```bash
# Update package repositories
sudo apt-get update

# Install required dependencies
sudo apt-get install -y curl openssh-server ca-certificates tzdata perl postfix gpg

# Configure Postfix for email (choose 'Internet Site' for basic setup)
sudo dpkg-reconfigure postfix

# Configure UFW firewall (if enabled)
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow 2222/tcp

# Add GitLab official repository
curl -fsSL https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.deb.sh | sudo bash

# Install GitLab Enterprise Edition
sudo EXTERNAL_URL="https://gitlab.example.com" apt-get install -y gitlab-ee

# For Community Edition instead:
# sudo EXTERNAL_URL="https://gitlab.example.com" apt-get install -y gitlab-ce

# Initial configuration and start services
sudo gitlab-ctl reconfigure

# Verify installation
sudo gitlab-ctl status
```

### Arch Linux

```bash
# Update system packages
sudo pacman -Syu

# Install required dependencies
sudo pacman -S curl openssh postfix

# Enable and start services
sudo systemctl enable --now sshd postfix

# Install GitLab from AUR (using yay helper)
yay -S gitlab-ee

# Or install GitLab Community Edition
# yay -S gitlab

# Configure GitLab
sudo vim /etc/gitlab/gitlab.rb
# Set: external_url 'https://gitlab.example.com'

# Initial configuration
sudo gitlab-ctl reconfigure

# Enable GitLab service
sudo systemctl enable gitlab-runsvdir
sudo systemctl start gitlab-runsvdir
```

### Alpine Linux

```bash
# Update package index
sudo apk update

# Install required packages
sudo apk add curl openssh postfix

# Enable services
sudo rc-update add sshd default
sudo rc-update add postfix default
sudo rc-service sshd start
sudo rc-service postfix start

# Add GitLab repository key
wget -O /etc/apk/keys/gitlab.rsa.pub https://packages.gitlab.com/gitlab/gitlab-ee/gpgkey/gitlab-gitlab-ee-3D645A26AB9FBD22.rsa.pub

# Add GitLab repository
echo "https://packages.gitlab.com/gitlab/gitlab-ee/alpine/v$(cat /etc/alpine-release | cut -d'.' -f1-2)/main" >> /etc/apk/repositories

# Update and install GitLab
sudo apk update
sudo apk add gitlab-ee

# Configure external URL
echo "external_url 'https://gitlab.example.com'" >> /etc/gitlab/gitlab.rb

# Reconfigure and start
sudo gitlab-ctl reconfigure
```

### openSUSE/SLES

```bash
# Install dependencies (openSUSE)
sudo zypper install -y curl openssh postfix

# For SLES
# sudo zypper install -y curl openssh2 postfix

# Enable services
sudo systemctl enable --now sshd postfix

# Configure firewall
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload

# Add GitLab repository
curl -fsSL https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.rpm.sh | sudo bash

# Install GitLab
sudo EXTERNAL_URL="https://gitlab.example.com" zypper install -y gitlab-ee

# Configure and start
sudo gitlab-ctl reconfigure
```

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install required dependencies
brew install curl git postfix

# Start postfix service
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.postfix.master.plist

# Install GitLab using official installer
curl -LO https://packages.gitlab.com/gitlab/gitlab-ee/packages/el/8/gitlab-ee-latest.x86_64.rpm

# Note: GitLab doesn't provide native macOS packages
# Recommended to use Docker for macOS installations:

# Create GitLab directories
sudo mkdir -p /srv/gitlab/{config,logs,data}

# Set environment variables
export GITLAB_HOME=/srv/gitlab

# Run GitLab container
docker run --detach \
  --hostname gitlab.example.com \
  --publish 443:443 --publish 80:80 --publish 2222:22 \
  --name gitlab \
  --restart unless-stopped \
  --volume $GITLAB_HOME/config:/etc/gitlab \
  --volume $GITLAB_HOME/logs:/var/log/gitlab \
  --volume $GITLAB_HOME/data:/var/opt/gitlab \
  --shm-size 256m \
  --env GITLAB_OMNIBUS_CONFIG="external_url 'https://gitlab.example.com'" \
  gitlab/gitlab-ee:latest
```

### FreeBSD

```bash
# Update ports tree
sudo portsnap fetch extract

# Install required ports
sudo pkg install curl openssh-portable postfix git

# Enable services
sudo sysrc sshd_enable="YES"
sudo sysrc postfix_enable="YES"
sudo service sshd start
sudo service postfix start

# Configure firewall (if pf is enabled)
echo 'pass in on $ext_if proto tcp from any to any port {22, 80, 443, 2222}' >> /etc/pf.conf
sudo pfctl -f /etc/pf.conf

# GitLab doesn't provide official FreeBSD packages
# Install using source compilation or Docker:

# Docker method (install Docker first)
sudo pkg install docker
sudo sysrc docker_enable="YES"
sudo service docker start

# Run GitLab container
sudo docker run --detach \
  --hostname gitlab.example.com \
  --publish 443:443 --publish 80:80 --publish 2222:22 \
  --name gitlab \
  --restart unless-stopped \
  --volume /usr/local/gitlab/config:/etc/gitlab \
  --volume /usr/local/gitlab/logs:/var/log/gitlab \
  --volume /usr/local/gitlab/data:/var/opt/gitlab \
  --shm-size 256m \
  gitlab/gitlab-ee:latest
```

### Windows

GitLab does not provide native Windows packages. Use Docker Desktop or WSL2 with Linux installation.

#### Windows with Docker Desktop
```powershell
# Install Docker Desktop from https://www.docker.com/products/docker-desktop

# Create GitLab directories
mkdir C:\gitlab\config
mkdir C:\gitlab\logs
mkdir C:\gitlab\data

# Run GitLab container
docker run --detach `
  --hostname gitlab.example.com `
  --publish 443:443 --publish 80:80 --publish 2222:22 `
  --name gitlab `
  --restart unless-stopped `
  --volume C:\gitlab\config:/etc/gitlab `
  --volume C:\gitlab\logs:/var/log/gitlab `
  --volume C:\gitlab\data:/var/opt/gitlab `
  --shm-size 256m `
  --env GITLAB_OMNIBUS_CONFIG="external_url 'https://gitlab.example.com'" `
  gitlab/gitlab-ee:latest
```

#### Windows with WSL2
```bash
# Enable WSL2 and install Ubuntu
wsl --install -d Ubuntu

# Switch to WSL2 Ubuntu environment
wsl

# Follow Ubuntu installation instructions above
sudo apt-get update
sudo apt-get install -y curl openssh-server ca-certificates tzdata perl postfix gpg
curl -fsSL https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.deb.sh | sudo bash
sudo EXTERNAL_URL="https://gitlab.example.com" apt-get install -y gitlab-ee
sudo gitlab-ctl reconfigure
```

## 4. Initial Configuration

After installation, GitLab requires initial configuration to set up the root password and basic settings.

### First-time Setup

1. **Access GitLab Web Interface**
   ```bash
   # Wait for GitLab to fully start (may take 2-3 minutes)
   sudo gitlab-ctl status
   
   # Check GitLab is responding
   curl -I http://localhost
   ```

2. **Retrieve Initial Root Password**
   ```bash
   # Get the initial root password
   sudo cat /etc/gitlab/initial_root_password
   ```

3. **Web Interface Setup**
   - Navigate to `https://your-domain.com` or `http://your-server-ip`
   - Login with username: `root` and the password from step 2
   - Set a new secure root password immediately
   - Complete the initial setup wizard

### Basic Configuration File Setup

Edit the main configuration file:
```bash
sudo vim /etc/gitlab/gitlab.rb
```

Essential initial settings:
```ruby
# External URL (replace with your domain)
external_url 'https://gitlab.example.com'

# Email configuration
gitlab_rails['gitlab_email_enabled'] = true
gitlab_rails['gitlab_email_from'] = 'gitlab@example.com'
gitlab_rails['gitlab_email_display_name'] = 'GitLab'

# SMTP configuration (example with Gmail)
gitlab_rails['smtp_enable'] = true
gitlab_rails['smtp_address'] = "smtp.gmail.com"
gitlab_rails['smtp_port'] = 587
gitlab_rails['smtp_user_name'] = "gitlab@example.com"
gitlab_rails['smtp_password'] = "app_password"
gitlab_rails['smtp_domain'] = "gmail.com"
gitlab_rails['smtp_authentication'] = "login"
gitlab_rails['smtp_enable_starttls_auto'] = true
gitlab_rails['smtp_tls'] = false

# Time zone
gitlab_rails['time_zone'] = 'UTC'

# GitLab Shell SSH port (if different from 22)
gitlab_rails['gitlab_shell_ssh_port'] = 2222
```

Apply configuration changes:
```bash
sudo gitlab-ctl reconfigure
sudo gitlab-ctl restart
```

### SSL/TLS Configuration

#### Let's Encrypt (Recommended)
```bash
# Enable Let's Encrypt in gitlab.rb
sudo vim /etc/gitlab/gitlab.rb
```

Add these settings:
```ruby
# Enable Let's Encrypt
letsencrypt['enable'] = true
letsencrypt['contact_emails'] = ['admin@example.com']
letsencrypt['auto_renew'] = true

# Force HTTPS
nginx['redirect_http_to_https'] = true
nginx['ssl_protocols'] = "TLSv1.2 TLSv1.3"
```

Reconfigure to activate SSL:
```bash
sudo gitlab-ctl reconfigure
```

#### Manual SSL Certificate
```bash
# Create SSL directory
sudo mkdir -p /etc/gitlab/ssl

# Copy your certificates (replace with your actual cert files)
sudo cp your-certificate.crt /etc/gitlab/ssl/gitlab.example.com.crt
sudo cp your-private-key.key /etc/gitlab/ssl/gitlab.example.com.key

# Set proper permissions
sudo chmod 600 /etc/gitlab/ssl/gitlab.example.com.key
sudo chmod 644 /etc/gitlab/ssl/gitlab.example.com.crt
```

Configure in gitlab.rb:
```ruby
external_url 'https://gitlab.example.com'
nginx['ssl_certificate'] = "/etc/gitlab/ssl/gitlab.example.com.crt"
nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/gitlab.example.com.key"
```

## 5. Service Management

GitLab uses the `gitlab-ctl` command for service management across all platforms.

### Service Control Commands

```bash
# Check status of all services
sudo gitlab-ctl status

# Start all GitLab services
sudo gitlab-ctl start

# Stop all GitLab services  
sudo gitlab-ctl stop

# Restart all GitLab services
sudo gitlab-ctl restart

# Restart specific service
sudo gitlab-ctl restart nginx
sudo gitlab-ctl restart unicorn
sudo gitlab-ctl restart sidekiq

# Reload configuration without restart
sudo gitlab-ctl reconfigure

# Show service logs
sudo gitlab-ctl tail
sudo gitlab-ctl tail nginx
sudo gitlab-ctl tail unicorn
sudo gitlab-ctl tail postgresql
```

### Service Status Monitoring

```bash
# Detailed service status
sudo gitlab-ctl service-list

# Check specific service
sudo gitlab-ctl status nginx
sudo gitlab-ctl status postgresql
sudo gitlab-ctl status redis

# Monitor service logs in real-time
sudo gitlab-ctl tail -f gitlab-workhorse
sudo gitlab-ctl tail -f sidekiq

# Check GitLab application status
sudo gitlab-rake gitlab:check

# Environment information
sudo gitlab-rake gitlab:env:info
```

### Systemd Integration

On systems with systemd, GitLab services are managed through systemd:

```bash
# Enable GitLab to start at boot
sudo systemctl enable gitlab-runsvdir.service

# Start GitLab services
sudo systemctl start gitlab-runsvdir.service

# Check systemd status
sudo systemctl status gitlab-runsvdir.service

# Stop GitLab services
sudo systemctl stop gitlab-runsvdir.service

# Check GitLab logs through journald
sudo journalctl -u gitlab-runsvdir.service -f
```

### Service Configuration

Individual service configuration in `/etc/gitlab/gitlab.rb`:

```ruby
# Unicorn (web server) settings
unicorn['worker_processes'] = 4
unicorn['worker_memory_limit_min'] = "400m"
unicorn['worker_memory_limit_max'] = "650m"

# Sidekiq (background jobs) settings  
sidekiq['max_concurrency'] = 25
sidekiq['log_format'] = 'json'

# GitLab Workhorse settings
gitlab_workhorse['listen_network'] = "tcp"
gitlab_workhorse['listen_addr'] = "127.0.0.1:8181"

# NGINX settings
nginx['listen_port'] = 80
nginx['listen_https'] = false  # Use with reverse proxy
nginx['client_max_body_size'] = '250m'
```

## 6. Advanced Configuration

### Performance Optimization

Configure GitLab for optimal performance based on your hardware resources:

```ruby
# /etc/gitlab/gitlab.rb - Performance settings

# Unicorn web server optimization
unicorn['worker_processes'] = 8  # Number of CPU cores
unicorn['worker_memory_limit_min'] = "400m"
unicorn['worker_memory_limit_max'] = "650m"
unicorn['worker_timeout'] = 60

# Sidekiq background job optimization
sidekiq['max_concurrency'] = 25
sidekiq['min_concurrency'] = 10
sidekiq['log_format'] = 'json'

# PostgreSQL optimization
postgresql['shared_buffers'] = "2GB"
postgresql['effective_cache_size'] = "8GB"
postgresql['work_mem'] = "16MB"
postgresql['maintenance_work_mem'] = "256MB"
postgresql['max_connections'] = 300
postgresql['checkpoint_completion_target'] = 0.9
postgresql['wal_buffers'] = "16MB"
postgresql['random_page_cost'] = 1.1

# Redis optimization
redis['maxmemory'] = "1gb"
redis['maxmemory_policy'] = "allkeys-lru"
redis['tcp_keepalive'] = 300
redis['tcp_timeout'] = 60

# Gitaly optimization (Git RPC service)
gitaly['ruby_max_rss'] = 300000000  # 300MB
gitaly['concurrency'] = [
  {
    'rpc' => "/gitaly.SmartHTTPService/PostReceivePack",
    'max_per_repo' => 3
  },
  {
    'rpc' => "/gitaly.SSHService/SSHUploadPack",
    'max_per_repo' => 3
  }
]

# File system optimization
git_data_dirs({
  "default" => {
    "path" => "/var/opt/gitlab/git-data"
  }
})

# Logging optimization
logging['svlogd_size'] = 200 * 1024 * 1024  # 200MB
logging['svlogd_num'] = 30
logging['logrotate_frequency'] = "daily"
logging['logrotate_rotate'] = 30
```

### Enterprise Features Configuration

```ruby
# LDAP/Active Directory integration
gitlab_rails['ldap_enabled'] = true
gitlab_rails['ldap_servers'] = {
  'main' => {
    'label' => 'LDAP',
    'host' => 'ldap.example.com',
    'port' => 636,
    'uid' => 'sAMAccountName',
    'bind_dn' => 'CN=gitlab,OU=Service Accounts,DC=example,DC=com',
    'password' => 'ldap_service_password',
    'encryption' => 'ssl',
    'verify_certificates' => true,
    'base' => 'DC=example,DC=com',
    'user_filter' => '',
    'attributes' => {
      'username' => ['uid', 'userid', 'sAMAccountName'],
      'email' => ['mail', 'email', 'userPrincipalName'],
      'name' => 'cn',
      'first_name' => 'givenName',
      'last_name' => 'sn'
    },
    'group_base' => 'OU=Groups,DC=example,DC=com',
    'admin_group' => 'GitLab Administrators'
  }
}

# SAML SSO configuration
gitlab_rails['omniauth_enabled'] = true
gitlab_rails['omniauth_allow_single_sign_on'] = ['saml']
gitlab_rails['omniauth_block_auto_created_users'] = false
gitlab_rails['omniauth_auto_link_saml_user'] = true
gitlab_rails['omniauth_providers'] = [
  {
    name: 'saml',
    args: {
      assertion_consumer_service_url: 'https://gitlab.example.com/users/auth/saml/callback',
      idp_cert_fingerprint: 'SAML_IDP_CERT_FINGERPRINT',
      idp_sso_target_url: 'https://idp.example.com/sso/saml',
      issuer: 'https://gitlab.example.com',
      name_identifier_format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress'
    },
    label: 'Company SSO'
  }
]

# Geo replication (Enterprise Premium)
gitlab_rails['geo_primary_role'] = true
gitlab_rails['geo_node_name'] = 'primary-site'
gitlab_rails['geo_registry_replication_enabled'] = true

# Advanced security features
gitlab_rails['security_auto_fix_enabled'] = true
gitlab_rails['dependency_proxy_enabled'] = true
gitlab_rails['packages_enabled'] = true
```

### Container Registry Configuration

```ruby
# Container Registry setup
registry_external_url 'https://registry.example.com'
gitlab_rails['registry_enabled'] = true
registry['enable'] = true
registry['username'] = "registry"
registry['group'] = "registry"
registry['dir'] = "/var/opt/gitlab/registry"

# Registry storage configuration (S3)
registry['storage'] = {
  's3' => {
    'accesskey' => 'registry_s3_access_key',
    'secretkey' => 'registry_s3_secret_key',
    'bucket' => 'gitlab-registry',
    'region' => 'us-west-2',
    'encrypt' => true
  }
}

# Registry security
registry['auth_token_realm'] = "https://gitlab.example.com/jwt/auth"
registry['auth_token_service'] = "container_registry"
registry['auth_token_issuer'] = "gitlab-issuer"

# Registry health checks
registry['health_storagedriver_enabled'] = true
registry['health_storagedriver_interval'] = '10s'
registry['health_storagedriver_threshold'] = 3

# Container scanning and cleanup
gitlab_rails['container_registry_cleanup_enabled'] = true
gitlab_rails['container_registry_expiration_policy_enabled'] = true
```

### GitLab Pages Configuration

```ruby
# GitLab Pages setup
pages_external_url "https://pages.example.com"
gitlab_pages['enable'] = true
gitlab_pages['access_control'] = true
gitlab_pages['artifacts_server'] = true
gitlab_pages['external_http'] = ['0.0.0.0:8090']
gitlab_pages['external_https'] = ['0.0.0.0:8091']

# Pages SSL configuration
gitlab_pages['cert_file'] = "/etc/gitlab/ssl/pages.crt"
gitlab_pages['key_file'] = "/etc/gitlab/ssl/pages.key"

# Pages storage
gitlab_pages['dir'] = "/var/opt/gitlab/gitlab-pages"
gitlab_pages['log_directory'] = "/var/log/gitlab/gitlab-pages"
```

## 7. Reverse Proxy Setup

### NGINX Reverse Proxy

Configure NGINX as a reverse proxy for GitLab:

```bash
# Install NGINX
# Ubuntu/Debian
sudo apt-get install nginx

# RHEL/CentOS
sudo dnf install nginx

# Configure NGINX for GitLab
sudo tee /etc/nginx/sites-available/gitlab > /dev/null <<EOF
upstream gitlab-workhorse {
  server unix:/var/opt/gitlab/gitlab-workhorse/socket fail_timeout=0;
}

server {
  listen 80;
  server_name gitlab.example.com;
  server_tokens off;
  return 301 https://\$server_name\$request_uri;
}

server {
  listen 443 ssl http2;
  server_name gitlab.example.com;
  server_tokens off;

  # SSL configuration
  ssl_certificate /etc/nginx/ssl/gitlab.crt;
  ssl_certificate_key /etc/nginx/ssl/gitlab.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
  ssl_prefer_server_ciphers off;
  ssl_session_cache shared:SSL:10m;
  ssl_session_tickets off;

  # Security headers
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header X-Content-Type-Options nosniff;
  add_header X-Frame-Options DENY;
  add_header X-XSS-Protection "1; mode=block";
  add_header Referrer-Policy strict-origin-when-cross-origin;

  # GitLab needs backwards compatible ciphers to retain compatibility with Java IDEs
  ssl_ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256";

  client_max_body_size 250m;
  
  location / {
    proxy_cache off;
    proxy_pass http://gitlab-workhorse;
    proxy_pass_header Server;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Forwarded-Ssl on;
    
    proxy_read_timeout 300s;
    proxy_connect_timeout 300s;
    proxy_redirect off;
  }
  
  # Container Registry
  location /v2/ {
    proxy_cache off;
    proxy_pass http://localhost:5000;
    proxy_pass_header Server;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Forwarded-Ssl on;
    
    proxy_read_timeout 900;
  }
}
EOF

# Enable site and restart NGINX
sudo ln -sf /etc/nginx/sites-available/gitlab /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Apache HTTP Server (httpd)

Configure Apache as reverse proxy:

```bash
# Install Apache
# RHEL/CentOS
sudo dnf install httpd mod_ssl

# Enable modules
sudo systemctl enable httpd

# Configure Apache for GitLab
sudo tee /etc/httpd/conf.d/gitlab.conf > /dev/null <<EOF
<VirtualHost *:80>
  ServerName gitlab.example.com
  Redirect permanent / https://gitlab.example.com/
</VirtualHost>

<VirtualHost *:443>
  ServerName gitlab.example.com
  
  # SSL Configuration
  SSLEngine on
  SSLCertificateFile /etc/httpd/ssl/gitlab.crt
  SSLCertificateKeyFile /etc/httpd/ssl/gitlab.key
  SSLProtocol -all +TLSv1.2 +TLSv1.3
  SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
  SSLHonorCipherOrder off
  
  # Security headers
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set X-Content-Type-Options nosniff
  Header always set X-Frame-Options DENY
  Header always set X-XSS-Protection "1; mode=block"
  
  # Proxy configuration
  ProxyPreserveHost On
  ProxyPass /v2/ http://localhost:5000/v2/
  ProxyPassReverse /v2/ http://localhost:5000/v2/
  ProxyPass / http://localhost:8080/
  ProxyPassReverse / http://localhost:8080/
  
  # Set headers
  ProxyPassReverse / http://localhost:8080/
  RequestHeader set X-Forwarded-Proto "https"
  RequestHeader set X-Forwarded-Ssl "on"
</VirtualHost>
EOF

# Start Apache
sudo systemctl start httpd
sudo systemctl enable httpd
```

### HAProxy Load Balancer

Configure HAProxy for high availability:

```bash
# Install HAProxy
sudo apt-get install haproxy  # Ubuntu/Debian
sudo dnf install haproxy      # RHEL/CentOS

# Configure HAProxy
sudo tee /etc/haproxy/haproxy.cfg > /dev/null <<EOF
global
    daemon
    log 127.0.0.1:514 local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy

    # SSL configuration
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    mode http
    log global
    option httplog
    option dontlognull
    option log-health-checks
    option forwardfor except 127.0.0.0/8
    option redispatch
    retries 3
    timeout http-request 10s
    timeout queue 1m
    timeout connect 5s
    timeout client 1m
    timeout server 1m
    timeout http-keep-alive 10s
    timeout check 10s

# GitLab frontend
frontend gitlab_frontend
    bind *:80
    bind *:443 ssl crt /etc/haproxy/certs/gitlab.pem
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    rspadd Strict-Transport-Security:\ max-age=31536000;\ includeSubDomains
    rspadd X-Content-Type-Options:\ nosniff
    rspadd X-Frame-Options:\ DENY
    
    default_backend gitlab_backend

# GitLab backend servers
backend gitlab_backend
    balance roundrobin
    option httpchk GET /users/sign_in
    http-check expect status 200
    
    server gitlab1 192.168.1.10:8080 check
    server gitlab2 192.168.1.11:8080 check backup

# Statistics interface
frontend stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
EOF

# Start HAProxy
sudo systemctl start haproxy
sudo systemctl enable haproxy
```

## 8. Security Configuration

### Security Hardening

Implement comprehensive security measures:

```ruby
# /etc/gitlab/gitlab.rb - Security configuration

# Force HTTPS
nginx['redirect_http_to_https'] = true
nginx['ssl_protocols'] = "TLSv1.2 TLSv1.3"
nginx['ssl_prefer_server_ciphers'] = "off"
nginx['ssl_ciphers'] = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"

# Security headers
nginx['custom_nginx_config'] = "include /etc/nginx/conf.d/security-headers.conf;"

# Rate limiting
gitlab_rails['rate_limit_requests_per_period'] = 300
gitlab_rails['rate_limit_period'] = 60

# Rack Attack configuration for Git over HTTP
gitlab_rails['rack_attack_git_basic_auth'] = {
  'enabled' => true,
  'ip_whitelist' => %w{127.0.0.1 192.168.1.0/24},
  'maxretry' => 10,
  'findtime' => 60,
  'bantime' => 3600
}

# Protected paths
gitlab_rails['rack_attack_protected_paths'] = [
  '/users/password',
  '/users/sign_in',
  '/api/v4/session.json',
  '/api/v4/session',
  '/users/confirmation',
  '/unsubscribes/',
  '/admin/session'
]

# SSH security
gitlab_rails['gitlab_shell_ssh_port'] = 2222
gitlab_shell['auth_file'] = "/var/opt/gitlab/.ssh/authorized_keys"

# Two-factor authentication enforcement
gitlab_rails['require_two_factor_authentication'] = false
gitlab_rails['two_factor_grace_period'] = 8  # 8 hours

# Session settings
gitlab_rails['session_expire_delay'] = 10080  # 1 week
gitlab_rails['session_store_enabled'] = true

# Webhook security
gitlab_rails['webhook_timeout'] = 10
gitlab_rails['webhook_max_redirects'] = 3

# API security
gitlab_rails['api_limit_per_min'] = 300

# Disable features that increase attack surface
gitlab_rails['usage_ping_enabled'] = false
gitlab_rails['sentry_enabled'] = false

# Audit logging (Enterprise)
gitlab_rails['audit_events_enabled'] = true

# Security scanning
gitlab_rails['sast_enabled'] = true
gitlab_rails['dependency_scanning_enabled'] = true
gitlab_rails['container_scanning_enabled'] = true
gitlab_rails['secret_detection_enabled'] = true
```

Create security headers configuration:

```bash
sudo mkdir -p /etc/nginx/conf.d

sudo tee /etc/nginx/conf.d/security-headers.conf > /dev/null <<EOF
# Security headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self';" always;
EOF
```

### Firewall Configuration

#### UFW (Ubuntu/Debian)
```bash
# Enable UFW
sudo ufw enable

# Allow SSH
sudo ufw allow OpenSSH

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow GitLab SSH (if using custom port)
sudo ufw allow 2222/tcp

# Allow specific IP ranges only (optional)
sudo ufw allow from 192.168.1.0/24 to any port 22
sudo ufw allow from 10.0.0.0/8 to any port 22

# Check status
sudo ufw status verbose
```

#### firewalld (RHEL/CentOS)
```bash
# Enable firewalld
sudo systemctl enable --now firewalld

# Add services
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-service=ssh

# Add custom ports
sudo firewall-cmd --permanent --add-port=2222/tcp

# Create custom service for GitLab
sudo tee /etc/firewalld/services/gitlab.xml > /dev/null <<EOF
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>GitLab</short>
  <description>GitLab DevOps Platform</description>
  <port protocol="tcp" port="80"/>
  <port protocol="tcp" port="443"/>
  <port protocol="tcp" port="2222"/>
</service>
EOF

sudo firewall-cmd --permanent --add-service=gitlab
sudo firewall-cmd --reload
```

### Access Control and Authentication

```ruby
# Password policy
gitlab_rails['password_authentication_enabled_for_web'] = true
gitlab_rails['password_authentication_enabled_for_git'] = true

# Sign-up restrictions
gitlab_rails['signup_enabled'] = false
gitlab_rails['signin_enabled'] = true

# Email domain restrictions
gitlab_rails['email_restrictions_enabled'] = true
gitlab_rails['email_restrictions'] = '@example\\.com$|@partner\\.com$'

# IP restrictions (Enterprise)
gitlab_rails['ip_restrictions_enabled'] = true

# OAuth/OIDC providers configuration
gitlab_rails['omniauth_enabled'] = true
gitlab_rails['omniauth_allow_single_sign_on'] = ['google_oauth2', 'github']
gitlab_rails['omniauth_block_auto_created_users'] = true
gitlab_rails['omniauth_auto_sign_in_with_provider'] = 'google_oauth2'
gitlab_rails['omniauth_providers'] = [
  {
    name: 'google_oauth2',
    app_id: 'GOOGLE_OAUTH_CLIENT_ID',
    app_secret: 'GOOGLE_OAUTH_CLIENT_SECRET',
    args: {
      scope: 'email profile',
      domain: 'example.com'
    }
  }
]
```

## 9. Database Setup

GitLab uses PostgreSQL as its default database. For production environments, consider using an external PostgreSQL instance.

### Internal PostgreSQL (Default)

GitLab comes with a built-in PostgreSQL instance configured automatically:

```ruby
# /etc/gitlab/gitlab.rb - PostgreSQL settings

# Enable built-in PostgreSQL
postgresql['enable'] = true

# PostgreSQL performance tuning
postgresql['shared_buffers'] = "2GB"
postgresql['effective_cache_size'] = "8GB" 
postgresql['work_mem'] = "16MB"
postgresql['maintenance_work_mem'] = "256MB"
postgresql['max_connections'] = 300
postgresql['checkpoint_completion_target'] = 0.9
postgresql['wal_buffers'] = "16MB"
postgresql['default_statistics_target'] = 100
postgresql['random_page_cost'] = 1.1  # For SSD storage
postgresql['effective_io_concurrency'] = 200

# Connection settings
postgresql['listen_address'] = '127.0.0.1'
postgresql['port'] = 5432
postgresql['max_worker_processes'] = 8
postgresql['max_parallel_workers_per_gather'] = 4
postgresql['max_parallel_workers'] = 8

# WAL settings for performance
postgresql['wal_level'] = 'replica'
postgresql['max_wal_senders'] = 3
postgresql['checkpoint_segments'] = 32
postgresql['checkpoint_timeout'] = '5min'

# Logging
postgresql['log_statement'] = 'none'
postgresql['log_min_duration_statement'] = 1000  # Log slow queries
postgresql['log_line_prefix'] = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
```

### External PostgreSQL Setup

For high availability and better performance, use an external PostgreSQL server:

```bash
# Install PostgreSQL on separate server
# Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib

# RHEL/CentOS  
sudo dnf install postgresql-server postgresql-contrib

# Initialize database (RHEL/CentOS only)
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql

# Create GitLab database and user
sudo -u postgres createuser --createdb --no-superuser --no-createrole gitlab
sudo -u postgres createdb -O gitlab gitlabhq_production
sudo -u postgres psql -c "ALTER USER gitlab ENCRYPTED PASSWORD 'secure_password';"

# Configure PostgreSQL for GitLab
sudo tee -a /var/lib/pgsql/data/postgresql.conf <<EOF
# GitLab optimizations
shared_buffers = 2GB
effective_cache_size = 8GB
work_mem = 16MB  
maintenance_work_mem = 256MB
max_connections = 300
checkpoint_completion_target = 0.9
wal_buffers = 16MB
random_page_cost = 1.1
effective_io_concurrency = 200

# Connection settings
listen_addresses = '*'
port = 5432
max_worker_processes = 8
max_parallel_workers = 8
max_parallel_workers_per_gather = 4

# Enable extensions
shared_preload_libraries = 'pg_stat_statements'
EOF

# Configure client authentication
sudo tee -a /var/lib/pgsql/data/pg_hba.conf <<EOF
host    gitlabhq_production     gitlab          192.168.1.0/24          md5
host    gitlabhq_production     gitlab          10.0.0.0/8              md5
EOF

sudo systemctl restart postgresql
```

Configure GitLab to use external PostgreSQL:

```ruby
# /etc/gitlab/gitlab.rb - External PostgreSQL

# Disable built-in PostgreSQL
postgresql['enable'] = false

# External PostgreSQL configuration
gitlab_rails['db_adapter'] = 'postgresql'
gitlab_rails['db_encoding'] = 'unicode'
gitlab_rails['db_collation'] = nil
gitlab_rails['db_database'] = 'gitlabhq_production'
gitlab_rails['db_pool'] = 10
gitlab_rails['db_username'] = 'gitlab'
gitlab_rails['db_password'] = 'secure_password'
gitlab_rails['db_host'] = '192.168.1.10'
gitlab_rails['db_port'] = 5432
gitlab_rails['db_socket'] = nil
gitlab_rails['db_sslmode'] = 'prefer'
gitlab_rails['db_sslcert'] = nil
gitlab_rails['db_sslkey'] = nil
gitlab_rails['db_sslrootcert'] = nil
gitlab_rails['db_sslcrl'] = nil
gitlab_rails['db_prepared_statements'] = false
gitlab_rails['db_statements_limit'] = 1000

# Load balancing for read replicas (Enterprise)
gitlab_rails['db_load_balancing'] = {
  'hosts' => ['192.168.1.11', '192.168.1.12'],
  'discover' => {
    'record' => 'postgres-replica.example.com'
  }
}
```

### Database Maintenance

```bash
# Database maintenance commands
sudo gitlab-ctl pgb-console  # Connect to database

# Manual database operations
sudo gitlab-psql -d gitlabhq_production

# Database migrations
sudo gitlab-rake db:migrate

# Check database status
sudo gitlab-rake db:migrate:status

# Create database backup
sudo gitlab-backup create SKIP=uploads,builds,artifacts,lfs,registry,pages

# Restore database from backup  
sudo gitlab-backup restore BACKUP=timestamp_of_backup

# Database cleanup
sudo gitlab-rake gitlab:cleanup:sessions
sudo gitlab-rake gitlab:cleanup:project_uploads
```

## 10. Performance Optimization

### System-Level Optimizations

```bash
# Kernel parameter tuning for GitLab
sudo tee /etc/sysctl.d/90-gitlab.conf <<EOF
# Network optimizations
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 7
net.ipv4.tcp_keepalive_intvl = 30

# Memory management
vm.swappiness = 1
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.vfs_cache_pressure = 50

# File system optimizations
fs.file-max = 2097152
fs.nr_open = 1048576
EOF

sudo sysctl -p /etc/sysctl.d/90-gitlab.conf

# Increase file descriptor limits
sudo tee /etc/security/limits.d/90-gitlab.conf <<EOF
git     soft    nofile          65535
git     hard    nofile          65535
git     soft    nproc           65535  
git     hard    nproc           65535
EOF

# Configure systemd limits
sudo mkdir -p /etc/systemd/system/gitlab-runsvdir.service.d
sudo tee /etc/systemd/system/gitlab-runsvdir.service.d/limits.conf <<EOF
[Service]
LimitNOFILE=65535
LimitNPROC=65535
EOF

sudo systemctl daemon-reload
```

### Application Performance Tuning

```ruby
# /etc/gitlab/gitlab.rb - Performance optimizations

# Unicorn/Puma web server settings
# Use Puma (recommended for GitLab 13.0+)
puma['enable'] = true
puma['worker_processes'] = 4  # Number of CPU cores
puma['min_threads'] = 1
puma['max_threads'] = 16
puma['worker_timeout'] = 60
puma['worker_boot_timeout'] = 60

# Disable Unicorn if using Puma
unicorn['enable'] = false

# Sidekiq background job processing
sidekiq['max_concurrency'] = 25
sidekiq['min_concurrency'] = 10
sidekiq['queue_groups'] = [
  '*',
  'cronjob:1',
  'default:5',
  'pipeline_processing:2'
]

# Gitaly settings for Git operations
gitaly['ruby_max_rss'] = 300000000  # 300MB
gitaly['concurrency'] = [
  {
    'rpc' => "/gitaly.SmartHTTPService/PostReceivePack",
    'max_per_repo' => 3
  },
  {
    'rpc' => "/gitaly.SSHService/SSHUploadPack",
    'max_per_repo' => 3  
  },
  {
    'rpc' => "/gitaly.SSHService/SSHReceivePack",
    'max_per_repo' => 3
  }
]

# GitLab Workhorse settings
gitlab_workhorse['api_limit'] = 1000
gitlab_workhorse['api_queue_limit'] = 200
gitlab_workhorse['api_queue_duration'] = "30s"

# Redis caching optimizations  
redis['maxmemory'] = "1gb"
redis['maxmemory_policy'] = "allkeys-lru"
redis['save'] = '900 1 300 10 60 10000'
redis['tcp_keepalive'] = 300
redis['tcp_timeout'] = 60

# NGINX optimizations
nginx['worker_processes'] = 4
nginx['worker_connections'] = 1024
nginx['keepalive_timeout'] = 65
nginx['gzip'] = "on"
nginx['gzip_comp_level'] = 6
nginx['gzip_types'] = [
  'text/plain',
  'text/css', 
  'application/json',
  'application/javascript',
  'text/xml',
  'application/xml',
  'application/xml+rss',
  'text/javascript'
]

# Prometheus monitoring optimization
prometheus['scrape_interval'] = 15
prometheus['scrape_timeout'] = 10
prometheus['evaluation_interval'] = 15
```

### Storage Optimization

```bash
# Use SSD storage with proper mount options
sudo tee -a /etc/fstab <<EOF
/dev/sdb1 /var/opt/gitlab ext4 defaults,noatime,discard 0 2
EOF

# Optimize Git repository storage
sudo tee /usr/local/bin/gitlab-git-optimize.sh <<'EOF'
#!/bin/bash
# Optimize Git repositories for better performance

REPO_DIR="/var/opt/gitlab/git-data/repositories"
LOG_FILE="/var/log/gitlab/git-optimize.log"

echo "$(date): Starting Git repository optimization" >> $LOG_FILE

find $REPO_DIR -name "*.git" -type d | while read repo; do
    cd "$repo"
    echo "Optimizing: $repo" >> $LOG_FILE
    
    # Garbage collection
    git gc --aggressive --prune=now
    
    # Repack repository
    git repack -ad
    
    # Update server info
    git update-server-info
done

echo "$(date): Git repository optimization completed" >> $LOG_FILE
EOF

sudo chmod +x /usr/local/bin/gitlab-git-optimize.sh

# Schedule weekly Git optimization
echo "0 2 * * 0 root /usr/local/bin/gitlab-git-optimize.sh" | sudo tee -a /etc/crontab
```

### Monitoring Performance

```bash
# Create performance monitoring script
sudo tee /usr/local/bin/gitlab-performance-check.sh <<'EOF'
#!/bin/bash
LOGFILE="/var/log/gitlab-performance.log"

echo "$(date): Performance Check Started" >> $LOGFILE

# CPU and Memory usage
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%" >> $LOGFILE
echo "Memory Usage: $(free | grep Mem | awk '{printf "%.2f", $3/$2 * 100.0}')%" >> $LOGFILE

# Database connections
DB_CONNECTIONS=$(sudo gitlab-psql -t -c "SELECT count(*) FROM pg_stat_activity;")
echo "Database Connections: $DB_CONNECTIONS" >> $LOGFILE

# Redis memory usage
REDIS_MEMORY=$(redis-cli info memory | grep used_memory_human | cut -d: -f2)
echo "Redis Memory: $REDIS_MEMORY" >> $LOGFILE

# Disk usage
DISK_USAGE=$(df /var/opt/gitlab | awk 'NR==2 {print $5}')
echo "Disk Usage: $DISK_USAGE" >> $LOGFILE

# Active processes
PROCESSES=$(sudo gitlab-ctl status | grep -c "run:")
echo "Active GitLab Processes: $PROCESSES" >> $LOGFILE

echo "$(date): Performance Check Completed" >> $LOGFILE
echo "---" >> $LOGFILE
EOF

sudo chmod +x /usr/local/bin/gitlab-performance-check.sh

# Schedule performance checks every 15 minutes
echo "*/15 * * * * root /usr/local/bin/gitlab-performance-check.sh" | sudo tee -a /etc/crontab
```

## 11. Monitoring

GitLab includes built-in monitoring capabilities with Prometheus and Grafana.

### Built-in Monitoring Stack

Enable GitLab's integrated monitoring:

```ruby
# /etc/gitlab/gitlab.rb - Monitoring configuration

# Enable Prometheus monitoring
prometheus_monitoring['enable'] = true
prometheus['enable'] = true
prometheus['listen_address'] = 'localhost:9090'
prometheus['scrape_interval'] = 15
prometheus['scrape_timeout'] = 10
prometheus['evaluation_interval'] = 15

# Prometheus exporters
node_exporter['enable'] = true
node_exporter['listen_address'] = 'localhost:9100'

redis_exporter['enable'] = true
redis_exporter['listen_address'] = 'localhost:9121'

postgres_exporter['enable'] = true
postgres_exporter['listen_address'] = 'localhost:9187'

gitlab_exporter['enable'] = true
gitlab_exporter['listen_address'] = 'localhost:9168'

# Grafana configuration
grafana['enable'] = true
grafana['admin_password'] = 'secure_grafana_password'
grafana['disable_login_form'] = false
grafana['allow_user_sign_up'] = false
grafana['secret_key'] = 'generate_secure_secret_key'

# Alert Manager
alertmanager['enable'] = true
alertmanager['admin_email'] = 'alerts@example.com'
alertmanager['flags'] = {
  'storage.path' => '/var/opt/gitlab/alertmanager/data',
  'config.file' => '/var/opt/gitlab/alertmanager/alertmanager.yml'
}
```

### External Monitoring Integration

Configure external monitoring systems:

```bash
# Prometheus configuration for external setup
sudo tee /etc/prometheus/prometheus.yml <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    monitor: 'gitlab-monitor'

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['localhost:9093']

rule_files:
  - "gitlab-rules.yml"

scrape_configs:
  - job_name: 'gitlab-workhorse'
    static_configs:
      - targets: ['gitlab.example.com:9229']
    metrics_path: '/metrics'
    scrape_interval: 15s

  - job_name: 'gitlab-unicorn'
    static_configs:
      - targets: ['gitlab.example.com:8080']
    metrics_path: '/-/metrics'
    scrape_interval: 15s

  - job_name: 'gitlab-sidekiq'
    static_configs:
      - targets: ['gitlab.example.com:8082']
    metrics_path: '/metrics'
    scrape_interval: 15s

  - job_name: 'gitlab-gitaly'
    static_configs:
      - targets: ['gitlab.example.com:9236']
    metrics_path: '/metrics'
    scrape_interval: 15s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['gitlab.example.com:9100']
    metrics_path: '/metrics'
    scrape_interval: 15s

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['gitlab.example.com:9187']
    metrics_path: '/metrics'
    scrape_interval: 15s

  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['gitlab.example.com:9121']
    metrics_path: '/metrics'
    scrape_interval: 15s
EOF

# Create GitLab-specific alerting rules
sudo tee /etc/prometheus/gitlab-rules.yml <<EOF
groups:
  - name: gitlab
    rules:
      - alert: GitLabDown
        expr: up{job=~"gitlab.*"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "GitLab service {{ \$labels.job }} is down"
          description: "GitLab service {{ \$labels.job }} has been down for more than 5 minutes."

      - alert: GitLabHighCPU
        expr: 100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage on GitLab server"
          description: "CPU usage is above 80% for more than 10 minutes."

      - alert: GitLabHighMemory
        expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 85
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage on GitLab server"
          description: "Memory usage is above 85% for more than 10 minutes."

      - alert: GitLabDiskSpaceLow
        expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100 < 15
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Low disk space on GitLab server"
          description: "Disk space is below 15% on {{ \$labels.mountpoint }}."

      - alert: GitLabPostgreSQLDown
        expr: up{job="postgres-exporter"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "PostgreSQL is down"
          description: "GitLab PostgreSQL database has been down for more than 5 minutes."

      - alert: GitLabRedisDown
        expr: up{job="redis-exporter"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Redis is down"
          description: "GitLab Redis cache has been down for more than 5 minutes."
EOF
```

### Log Management

Configure centralized logging:

```bash
# Install and configure Elasticsearch, Logstash, Kibana (ELK Stack)
# Or use external services like Splunk, DataDog, etc.

# Configure GitLab log forwarding
sudo tee /etc/rsyslog.d/49-gitlab.conf <<EOF
# Forward GitLab logs to centralized logging
*.* @@logserver.example.com:514

# Local GitLab log files
if \$programname startswith 'gitlab' then /var/log/gitlab-centralized.log
& stop
EOF

sudo systemctl restart rsyslog

# Create log monitoring script
sudo tee /usr/local/bin/gitlab-log-monitor.sh <<'EOF'
#!/bin/bash
ALERT_EMAIL="admin@example.com"
LOG_DIR="/var/log/gitlab"

# Monitor for critical errors
find $LOG_DIR -name "*.log" -type f -mmin -5 | while read logfile; do
    if grep -i "error\|exception\|fatal" "$logfile" | grep "$(date +'%Y-%m-%d %H:%M')" > /tmp/gitlab-errors.tmp; then
        if [ -s /tmp/gitlab-errors.tmp ]; then
            echo "Critical errors found in GitLab logs:" | mail -s "GitLab Error Alert" $ALERT_EMAIL < /tmp/gitlab-errors.tmp
        fi
    fi
done

# Monitor disk space for log directory
USAGE=$(df $LOG_DIR | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $USAGE -gt 80 ]; then
    echo "Log directory usage is at ${USAGE}%. Consider log rotation." | mail -s "GitLab Log Disk Usage Warning" $ALERT_EMAIL
fi
EOF

sudo chmod +x /usr/local/bin/gitlab-log-monitor.sh

# Schedule log monitoring every 5 minutes
echo "*/5 * * * * root /usr/local/bin/gitlab-log-monitor.sh" | sudo tee -a /etc/crontab
```

### Health Monitoring

```bash
# Create comprehensive health monitoring
sudo tee /usr/local/bin/gitlab-health-monitor.sh <<'EOF'
#!/bin/bash
HEALTH_LOG="/var/log/gitlab-health.log"
EMAIL="admin@example.com"
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

check_service() {
    local service=$1
    if sudo gitlab-ctl status $service | grep -q "run:"; then
        echo "$(date): ✓ $service is running" >> $HEALTH_LOG
        return 0
    else
        echo "$(date): ✗ $service is DOWN" >> $HEALTH_LOG
        alert_service_down $service
        return 1
    fi
}

alert_service_down() {
    local service=$1
    echo "ALERT: GitLab service $service is down" | mail -s "GitLab Service Alert" $EMAIL
    
    # Send Slack notification
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"🚨 GitLab Alert: Service $service is down on $(hostname)\"}" \
        $WEBHOOK_URL
}

# Check all critical services
echo "$(date): Starting health check" >> $HEALTH_LOG

services=("nginx" "postgresql" "redis" "unicorn" "sidekiq" "gitaly")
failed_services=0

for service in "${services[@]}"; do
    if ! check_service $service; then
        ((failed_services++))
    fi
done

# Check application health
if sudo gitlab-rake gitlab:check >/dev/null 2>&1; then
    echo "$(date): ✓ GitLab application health check passed" >> $HEALTH_LOG
else
    echo "$(date): ✗ GitLab application health check FAILED" >> $HEALTH_LOG
    echo "GitLab application health check failed" | mail -s "GitLab Application Health Alert" $EMAIL
    ((failed_services++))
fi

# Check backup status
LAST_BACKUP=$(ls -t /var/opt/gitlab/backups/*_gitlab_backup.tar 2>/dev/null | head -1)
if [ -n "$LAST_BACKUP" ]; then
    BACKUP_AGE=$(( ($(date +%s) - $(stat -c %Y "$LAST_BACKUP")) / 3600 ))
    if [ $BACKUP_AGE -gt 48 ]; then
        echo "$(date): ⚠ Last backup is ${BACKUP_AGE} hours old" >> $HEALTH_LOG
        echo "GitLab backup is ${BACKUP_AGE} hours old" | mail -s "GitLab Backup Warning" $EMAIL
    else
        echo "$(date): ✓ Recent backup available (${BACKUP_AGE} hours old)" >> $HEALTH_LOG
    fi
else
    echo "$(date): ✗ No backup files found" >> $HEALTH_LOG
    echo "No GitLab backup files found" | mail -s "GitLab Backup Alert" $EMAIL
fi

echo "$(date): Health check completed. Failed services: $failed_services" >> $HEALTH_LOG
EOF

sudo chmod +x /usr/local/bin/gitlab-health-monitor.sh

# Schedule health checks every 10 minutes
echo "*/10 * * * * root /usr/local/bin/gitlab-health-monitor.sh" | sudo tee -a /etc/crontab
```

## 12. Backup and Restore

### Automated Backup Strategy

```bash
# Create comprehensive backup script
sudo tee /usr/local/bin/gitlab-backup-complete.sh <<'EOF'
#!/bin/bash
BACKUP_DIR="/backup/gitlab"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30
EMAIL="admin@example.com"

# Create backup directories
mkdir -p ${BACKUP_DIR}/{omnibus,secrets,ssl,registry,uploads}

echo "$(date): Starting GitLab backup process..."

# Create GitLab application backup
echo "Creating GitLab application backup..."
if gitlab-backup create STRATEGY=copy SKIP=uploads,builds,artifacts,lfs,registry,pages; then
    echo "✓ GitLab application backup completed"
else
    echo "✗ GitLab application backup failed"
    echo "GitLab application backup failed on $(hostname)" | mail -s "GitLab Backup Failure" $EMAIL
    exit 1
fi

# Backup configuration files
echo "Backing up configuration files..."
tar -czf ${BACKUP_DIR}/omnibus/gitlab-config-${DATE}.tar.gz \
    /etc/gitlab/gitlab.rb \
    /etc/gitlab/gitlab-secrets.json \
    /etc/gitlab/trusted-certs/ 2>/dev/null

# Backup SSL certificates
echo "Backing up SSL certificates..."
if [ -d /etc/gitlab/ssl ]; then
    tar -czf ${BACKUP_DIR}/ssl/gitlab-ssl-${DATE}.tar.gz /etc/gitlab/ssl/
fi

if [ -d /etc/letsencrypt ]; then
    tar -czf ${BACKUP_DIR}/ssl/letsencrypt-${DATE}.tar.gz /etc/letsencrypt/
fi

# Backup secrets
echo "Backing up secrets..."
if [ -d /etc/gitlab/secrets ]; then
    tar -czf ${BACKUP_DIR}/secrets/gitlab-secrets-${DATE}.tar.gz /etc/gitlab/secrets/
fi

# Backup container registry (if using local storage)
if [ -d /var/opt/gitlab/gitlab-rails/shared/registry ]; then
    echo "Backing up container registry..."
    tar -czf ${BACKUP_DIR}/registry/registry-${DATE}.tar.gz /var/opt/gitlab/gitlab-rails/shared/registry/
fi

# Upload to cloud storage (multiple providers)
echo "Uploading backups to cloud storage..."

# AWS S3
if command -v aws >/dev/null 2>&1; then
    aws s3 sync ${BACKUP_DIR}/ s3://gitlab-backups-primary/${DATE}/
fi

# Azure Blob Storage
if command -v az >/dev/null 2>&1; then
    az storage blob upload-batch --source ${BACKUP_DIR} --destination gitlab-backups --destination-path ${DATE}
fi

# Google Cloud Storage
if command -v gsutil >/dev/null 2>&1; then
    gsutil -m cp -r ${BACKUP_DIR}/* gs://gitlab-backups-gcs/${DATE}/
fi

# Verify backup integrity
echo "Verifying backup integrity..."
LATEST_BACKUP=$(ls -t /var/opt/gitlab/backups/*_gitlab_backup.tar | head -1)
if [ -n "$LATEST_BACKUP" ]; then
    if tar -tf "$LATEST_BACKUP" >/dev/null 2>&1; then
        echo "✓ Backup integrity verified"
    else
        echo "✗ Backup integrity check failed"
        echo "GitLab backup integrity check failed" | mail -s "GitLab Backup Integrity Alert" $EMAIL
    fi
fi

# Cleanup old backups
echo "Cleaning up old backups..."
find /var/opt/gitlab/backups/ -name "*_gitlab_backup.tar" -mtime +${RETENTION_DAYS} -delete
find ${BACKUP_DIR} -name "gitlab-*" -type f -mtime +${RETENTION_DAYS} -delete

# Send success notification
echo "GitLab backup completed successfully on $(date)" | mail -s "GitLab Backup Success" $EMAIL

echo "$(date): GitLab backup process completed successfully"
EOF

sudo chmod +x /usr/local/bin/gitlab-backup-complete.sh

# Schedule daily backups at 2 AM
echo "0 2 * * * root /usr/local/bin/gitlab-backup-complete.sh" | sudo tee -a /etc/crontab
```

### Disaster Recovery Procedures

```bash
# Create disaster recovery script
sudo tee /usr/local/bin/gitlab-disaster-recovery.sh <<'EOF'
#!/bin/bash
BACKUP_FILE="${1}"
CONFIG_BACKUP="${2}"

if [ -z "$BACKUP_FILE" ] || [ -z "$CONFIG_BACKUP" ]; then
    echo "Usage: $0 <backup_file> <config_backup>"
    echo "Available backups:"
    ls -la /var/opt/gitlab/backups/*_gitlab_backup.tar 2>/dev/null || echo "No local backups found"
    exit 1
fi

echo "$(date): Starting GitLab disaster recovery process..."

# Pre-recovery checks
echo "Performing pre-recovery checks..."
if ! command -v gitlab-ctl >/dev/null 2>&1; then
    echo "GitLab not installed. Please install GitLab first."
    exit 1
fi

# Stop GitLab services
echo "Stopping GitLab services..."
gitlab-ctl stop unicorn
gitlab-ctl stop puma  
gitlab-ctl stop sidekiq
gitlab-ctl stop workhorse
gitlab-ctl stop gitaly

# Backup current installation (if any)
if [ -d /var/opt/gitlab/git-data ]; then
    echo "Backing up current installation..."
    mv /var/opt/gitlab /var/opt/gitlab.backup.$(date +%s)
    mkdir -p /var/opt/gitlab
fi

# Restore configuration
echo "Restoring configuration files..."
if [ -f "$CONFIG_BACKUP" ]; then
    cd /
    tar -xzf "$CONFIG_BACKUP"
else
    echo "Configuration backup not found: $CONFIG_BACKUP"
    exit 1
fi

# Reconfigure GitLab with restored configuration
echo "Reconfiguring GitLab..."
gitlab-ctl reconfigure

# Restore GitLab backup
echo "Restoring GitLab backup..."
BACKUP_NAME=$(basename "$BACKUP_FILE" _gitlab_backup.tar)
if gitlab-backup restore BACKUP="$BACKUP_NAME" force=yes; then
    echo "✓ GitLab backup restored successfully"
else
    echo "✗ GitLab backup restoration failed"
    exit 1
fi

# Start GitLab services
echo "Starting GitLab services..."
gitlab-ctl start

# Wait for services to start
echo "Waiting for services to start..."
sleep 30

# Verify installation
echo "Verifying GitLab installation..."
if gitlab-rake gitlab:check SANITIZE=true; then
    echo "✓ GitLab installation verified successfully"
else
    echo "⚠ GitLab verification completed with warnings"
fi

# Run database migrations (if needed)
echo "Running database migrations..."
gitlab-rake db:migrate

echo "$(date): GitLab disaster recovery completed"
echo "Please verify the installation manually and check all services"
EOF

sudo chmod +x /usr/local/bin/gitlab-disaster-recovery.sh
```

### Point-in-Time Recovery

```ruby
# /etc/gitlab/gitlab.rb - Configure for point-in-time recovery

# Enable WAL archiving for PostgreSQL
postgresql['archive_mode'] = "on"
postgresql['archive_command'] = 'cp %p /var/opt/gitlab/postgresql/archive/%f'
postgresql['max_wal_senders'] = 3
postgresql['wal_keep_segments'] = 32
postgresql['checkpoint_segments'] = 32

# Configure continuous archiving
postgresql['archive_timeout'] = '60s'
postgresql['checkpoint_completion_target'] = 0.9

# Backup retention
gitlab_rails['backup_keep_time'] = 2592000  # 30 days
gitlab_rails['backup_archive_permissions'] = 0644
```

## 13. Troubleshooting

### Common Issues and Solutions

```bash
# GitLab service diagnostics
sudo tee /usr/local/bin/gitlab-diagnose.sh <<'EOF'
#!/bin/bash
echo "=== GitLab Diagnostic Report ==="
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "GitLab Version: $(gitlab-rake gitlab:env:info | grep "GitLab information" -A 5)"
echo

echo "=== Service Status ==="
sudo gitlab-ctl status
echo

echo "=== Memory Usage ==="
free -h
echo

echo "=== Disk Usage ==="
df -h | grep -E "(gitlab|Filesystem)"
echo

echo "=== GitLab Processes ==="
ps aux | grep -E "(gitlab|unicorn|sidekiq|workhorse|gitaly)" | grep -v grep
echo

echo "=== Database Connectivity ==="
if sudo gitlab-psql -c "SELECT version();" >/dev/null 2>&1; then
    echo "✓ PostgreSQL connection OK"
    sudo gitlab-psql -c "SELECT count(*) as active_connections FROM pg_stat_activity;"
else
    echo "✗ PostgreSQL connection FAILED"
fi
echo

echo "=== Redis Connectivity ==="
if redis-cli ping >/dev/null 2>&1; then
    echo "✓ Redis connection OK"
    redis-cli info memory | grep used_memory_human
else
    echo "✗ Redis connection FAILED"
fi
echo

echo "=== Recent Errors ==="
echo "Last 10 errors from GitLab logs:"
find /var/log/gitlab -name "*.log" -type f -exec grep -l "ERROR\|FATAL" {} \; | head -5 | while read log; do
    echo "--- $log ---"
    tail -5 "$log" | grep -E "ERROR|FATAL" | tail -2
done
echo

echo "=== Network Connectivity ==="
echo "Testing external connectivity:"
if curl -Is https://gitlab.com >/dev/null 2>&1; then
    echo "✓ External connectivity OK"
else
    echo "✗ External connectivity FAILED"
fi

echo "Testing internal services:"
netstat -tlnp | grep -E "(80|443|22|5432|6379)"
echo

echo "=== SSL Certificate Status ==="
if [ -f /etc/gitlab/ssl/gitlab.example.com.crt ]; then
    echo "SSL certificate expires:"
    openssl x509 -in /etc/gitlab/ssl/gitlab.example.com.crt -noout -dates
else
    echo "No SSL certificate found"
fi
EOF

sudo chmod +x /usr/local/bin/gitlab-diagnose.sh
```

### Specific Problem Resolution

#### High Memory Usage
```bash
# Reduce memory consumption
sudo tee -a /etc/gitlab/gitlab.rb <<EOF
# Memory optimization for smaller systems
unicorn['worker_processes'] = 2
sidekiq['max_concurrency'] = 10
postgresql['shared_buffers'] = "256MB"
postgresql['effective_cache_size'] = "1GB"
EOF

sudo gitlab-ctl reconfigure
sudo gitlab-ctl restart
```

#### Database Issues
```bash
# Database troubleshooting commands
sudo gitlab-ctl status postgresql
sudo gitlab-psql -d gitlabhq_production

# Check database connections
sudo gitlab-psql -c "SELECT count(*) FROM pg_stat_activity;"

# Check for locks
sudo gitlab-psql -c "SELECT * FROM pg_locks WHERE NOT granted;"

# Vacuum and analyze database
sudo gitlab-psql -c "VACUUM ANALYZE;"

# Check database size
sudo gitlab-psql -c "SELECT pg_database_size('gitlabhq_production');"
```

#### Performance Issues
```bash
# Check system resources
top -p $(pgrep -d',' -f gitlab)
iostat -x 1 5
free -h

# Check GitLab worker status
sudo gitlab-ctl status | grep -E "(unicorn|sidekiq)"

# Check background job queue
sudo gitlab-rails runner "puts Sidekiq::Queue.new.size"

# Restart specific services
sudo gitlab-ctl restart sidekiq
sudo gitlab-ctl restart unicorn
```

#### SSL/TLS Issues
```bash
# Test SSL configuration
openssl s_client -connect gitlab.example.com:443 -servername gitlab.example.com

# Check certificate chain
openssl s_client -connect gitlab.example.com:443 -showcerts

# Verify certificate
openssl x509 -in /etc/gitlab/ssl/gitlab.example.com.crt -text -noout

# Test cipher suites
nmap --script ssl-enum-ciphers -p 443 gitlab.example.com
```

#### Repository Issues
```bash
# Check repository integrity
sudo gitlab-rake gitlab:check:repos

# Recreate authorized_keys file
sudo gitlab-rake gitlab:shell:setup

# Check GitLab Shell
sudo gitlab-rake gitlab:gitlab_shell:check

# Fix repository permissions
sudo gitlab-ctl reconfigure
```

## 14. Integration Examples

### CI/CD Pipeline Integration

```yaml
# .gitlab-ci.yml - Comprehensive CI/CD pipeline
stages:
  - security
  - test
  - build
  - deploy
  - monitor

variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: "/certs"
  SECURE_LOG_LEVEL: info

# Security scanning stage
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml

# Custom security scans
security:custom-audit:
  stage: security
  image: alpine:latest
  before_script:
    - apk add --no-cache curl jq
  script:
    - echo "Running custom security audit..."
    - |
      # Check for hardcoded secrets
      if grep -r -E "(password|secret|key|token).*=.*['\"][a-zA-Z0-9]{8,}['\"]" .; then
        echo "Potential hardcoded secrets found!"
        exit 1
      fi
    - echo "Security audit passed"
  rules:
    - if: '$CI_COMMIT_BRANCH'

# Testing stage
test:unit:
  stage: test
  image: node:18-alpine
  script:
    - npm ci
    - npm run test:unit
  coverage: '/Coverage: \d+\.\d+%/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml

test:integration:
  stage: test
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker-compose -f docker-compose.test.yml up --build --exit-code-from app
  artifacts:
    reports:
      junit: test-results.xml

# Build stage
build:docker:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker tag $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA $CI_REGISTRY_IMAGE:latest
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - docker push $CI_REGISTRY_IMAGE:latest
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'

# Deployment stages
deploy:staging:
  stage: deploy
  image: alpine/kubectl:latest
  script:
    - kubectl config use-context staging
    - kubectl set image deployment/app app=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - kubectl rollout status deployment/app
  environment:
    name: staging
    url: https://staging.example.com
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'

deploy:production:
  stage: deploy
  image: alpine/kubectl:latest
  script:
    - kubectl config use-context production
    - kubectl set image deployment/app app=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - kubectl rollout status deployment/app
  environment:
    name: production
    url: https://app.example.com
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: manual

# Monitoring stage
monitor:deployment:
  stage: monitor
  image: curlimages/curl:latest
  script:
    - sleep 60  # Wait for deployment
    - |
      if curl -f https://app.example.com/health; then
        echo "Deployment health check passed"
      else
        echo "Deployment health check failed"
        exit 1
      fi
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
```

### External Service Integrations

#### Slack Integration
```bash
# Configure Slack notifications
curl -X POST "https://gitlab.example.com/api/v4/projects/1/services/slack" \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  --data-urlencode "webhook=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK" \
  --data-urlencode "channel=#gitlab" \
  --data-urlencode "push_events=true" \
  --data-urlencode "issues_events=true" \
  --data-urlencode "merge_requests_events=true" \
  --data-urlencode "pipeline_events=true"
```

#### Jira Integration
```bash
# Configure Jira integration
curl -X PUT "https://gitlab.example.com/api/v4/projects/1/services/jira" \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  --data-urlencode "url=https://yourcompany.atlassian.net" \
  --data-urlencode "username=gitlab@company.com" \
  --data-urlencode "password=jira_api_token" \
  --data-urlencode "project_key=PROJ"
```

#### Kubernetes Integration
```ruby
# /etc/gitlab/gitlab.rb - Kubernetes integration
gitlab_rails['kubernetes_enabled'] = true
gitlab_rails['kubernetes_namespace'] = 'gitlab'

# Enable GitLab Agent for Kubernetes
gitlab_rails['gitlab_kas_enabled'] = true
gitlab_kas['enable'] = true
gitlab_kas['listen_address'] = '0.0.0.0:8150'
gitlab_kas['listen_websocket'] = '0.0.0.0:8151'
```

## 15. Maintenance

### Regular Maintenance Tasks

```bash
# Create maintenance script
sudo tee /usr/local/bin/gitlab-maintenance.sh <<'EOF'
#!/bin/bash
MAINTENANCE_LOG="/var/log/gitlab-maintenance.log"

echo "$(date): Starting GitLab maintenance" >> $MAINTENANCE_LOG

# Update GitLab to latest version
echo "Checking for GitLab updates..." >> $MAINTENANCE_LOG
if command -v apt-get >/dev/null; then
    apt-get update && apt-get upgrade gitlab-ee
elif command -v yum >/dev/null; then
    yum update gitlab-ee
elif command -v dnf >/dev/null; then
    dnf update gitlab-ee
fi

# Clean up old log files
echo "Cleaning up old log files..." >> $MAINTENANCE_LOG
find /var/log/gitlab -name "*.log.*" -mtime +30 -delete

# Clean up old backups
echo "Cleaning up old backups..." >> $MAINTENANCE_LOG
find /var/opt/gitlab/backups -name "*_gitlab_backup.tar" -mtime +7 -delete

# Database maintenance
echo "Performing database maintenance..." >> $MAINTENANCE_LOG
sudo gitlab-rake gitlab:cleanup:sessions
sudo gitlab-rake gitlab:cleanup:project_uploads
sudo gitlab-psql -c "VACUUM ANALYZE;"

# Git repository optimization
echo "Optimizing Git repositories..." >> $MAINTENANCE_LOG
sudo gitlab-rake gitlab:cleanup:repos

# Container registry cleanup
echo "Cleaning up container registry..." >> $MAINTENANCE_LOG
sudo gitlab-ctl registry-garbage-collect

# Check system health
echo "Checking system health..." >> $MAINTENANCE_LOG
sudo gitlab-rake gitlab:check SANITIZE=true >> $MAINTENANCE_LOG

echo "$(date): GitLab maintenance completed" >> $MAINTENANCE_LOG
EOF

sudo chmod +x /usr/local/bin/gitlab-maintenance.sh

# Schedule monthly maintenance on first Sunday at 3 AM
echo "0 3 1-7 * 0 root /usr/local/bin/gitlab-maintenance.sh" | sudo tee -a /etc/crontab
```

### Update Procedures

```bash
# Create update script
sudo tee /usr/local/bin/gitlab-update.sh <<'EOF'
#!/bin/bash
CURRENT_VERSION=$(gitlab-rake gitlab:env:info | grep "GitLab information" | head -1)
BACKUP_DIR="/backup/pre-update"
EMAIL="admin@example.com"

echo "Current GitLab version: $CURRENT_VERSION"
echo "Creating pre-update backup..."

# Create backup before update
mkdir -p $BACKUP_DIR
gitlab-backup create BACKUP=$BACKUP_DIR

# Update GitLab
if command -v apt-get >/dev/null; then
    apt-get update
    apt-get install gitlab-ee
elif command -v dnf >/dev/null; then
    dnf update gitlab-ee
fi

# Reconfigure after update
gitlab-ctl reconfigure

# Check installation
if gitlab-rake gitlab:check SANITIZE=true; then
    echo "GitLab update successful" | mail -s "GitLab Update Success" $EMAIL
else
    echo "GitLab update completed with warnings" | mail -s "GitLab Update Warning" $EMAIL
fi

NEW_VERSION=$(gitlab-rake gitlab:env:info | grep "GitLab information" | head -1)
echo "Updated GitLab version: $NEW_VERSION"
EOF

sudo chmod +x /usr/local/bin/gitlab-update.sh
```

## 16. Additional Resources

### Documentation Links
- **Official GitLab Documentation**: https://docs.gitlab.com/
- **GitLab Administration Guide**: https://docs.gitlab.com/ee/administration/
- **GitLab Security Documentation**: https://docs.gitlab.com/ee/security/
- **GitLab CI/CD Documentation**: https://docs.gitlab.com/ee/ci/
- **GitLab API Documentation**: https://docs.gitlab.com/ee/api/
- **GitLab Runner Documentation**: https://docs.gitlab.com/runner/
- **GitLab Container Registry**: https://docs.gitlab.com/ee/user/packages/container_registry/
- **GitLab Pages Documentation**: https://docs.gitlab.com/ee/user/project/pages/
- **GitLab Geo Documentation**: https://docs.gitlab.com/ee/administration/geo/
- **GitLab Kubernetes Integration**: https://docs.gitlab.com/ee/user/clusters/agent/

### Community Resources
- **GitLab Community Forum**: https://forum.gitlab.com/
- **GitLab Community Discord**: https://discord.com/invite/gitlab
- **GitLab Reddit Community**: https://www.reddit.com/r/gitlab/
- **GitLab Stack Overflow**: https://stackoverflow.com/questions/tagged/gitlab

### Training and Certification
- **GitLab Learn**: https://about.gitlab.com/learn/
- **GitLab University**: https://university.gitlab.com/
- **GitLab Certified Associate**: https://about.gitlab.com/services/education/gitlab-certified-associate/
- **GitLab Professional Services**: https://about.gitlab.com/services/

### Tools and Utilities
- **GitLab CLI (glab)**: https://gitlab.com/gitlab-org/cli
- **GitLab Terraform Provider**: https://registry.terraform.io/providers/gitlabhq/gitlab/
- **GitLab Ansible Collection**: https://galaxy.ansible.com/gitlab/gitlab
- **GitLab Helm Chart**: https://docs.gitlab.com/charts/
- **GitLab Docker Images**: https://hub.docker.com/u/gitlab

### Security Resources
- **GitLab Security Team**: https://about.gitlab.com/security/
- **GitLab Bug Bounty Program**: https://about.gitlab.com/security/disclosure/
- **GitLab Security Advisories**: https://about.gitlab.com/security/advisories/
- **GitLab Compliance**: https://about.gitlab.com/compliance/

### Performance and Scaling
- **GitLab Reference Architectures**: https://docs.gitlab.com/ee/administration/reference_architectures/
- **GitLab Performance Monitoring**: https://docs.gitlab.com/ee/administration/monitoring/performance/
- **GitLab Scaling and High Availability**: https://docs.gitlab.com/ee/administration/high_availability/

---

**Note:** This guide covers native OS installations of GitLab across multiple platforms with enterprise-grade security, monitoring, and maintenance procedures. For specific enterprise features, consider GitLab Enterprise Edition. This guide is part of the [HowToMgr](https://howtomgr.github.io) collection.
