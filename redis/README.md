# Redis Production Setup - Meta Ads Intelligence Platform

This directory contains a comprehensive, production-ready Redis setup with high availability, security, and monitoring for the Meta Ads Intelligence Platform.

## 🏗️ Architecture Overview

### Multi-Database Architecture
- **DB 0**: Session storage (authentication, JWT tokens)
- **DB 1**: User preferences and settings
- **DB 2**: Real-time cache (API responses, Meta Graph data)
- **DB 3**: Rate limiting and security tracking
- **DB 4**: Background job queues
- **DB 5**: Analytics and temporary data

### High Availability Setup
- **1 Master + 2 Replicas** for data redundancy
- **3 Sentinel instances** for automatic failover
- **Automatic promotion** of replicas during master failure
- **Client-side discovery** through Sentinel

## 📁 Directory Structure

```
redis/
├── redis.conf              # Main Redis configuration
├── redis-replica.conf      # Replica-specific configuration
├── sentinel.conf           # Sentinel configuration
├── users.acl              # User access control lists
├── monitoring/
│   ├── redis-monitoring.yml     # Monitoring services
│   └── prometheus-rules.yml     # Alerting rules
└── scripts/
    ├── health-check.sh          # Health monitoring
    ├── failover.sh              # Failover management
    └── backup.sh                # Backup automation
```

## 🚀 Quick Start

### 1. Prerequisites

```bash
# Install Docker and Docker Compose
sudo apt-get update
sudo apt-get install docker.io docker-compose

# Install Redis CLI tools
sudo apt-get install redis-tools

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration
```

### 2. Generate TLS Certificates

```bash
# Create TLS directory
mkdir -p redis/tls

# Generate CA certificate
openssl genrsa -out redis/tls/ca.key 4096
openssl req -new -x509 -days 3650 -key redis/tls/ca.key -out redis/tls/ca.crt

# Generate Redis server certificate
openssl genrsa -out redis/tls/redis.key 2048
openssl req -new -key redis/tls/redis.key -out redis/tls/redis.csr
openssl x509 -req -days 365 -in redis/tls/redis.csr -CA redis/tls/ca.crt -CAkey redis/tls/ca.key -CAcreateserial -out redis/tls/redis.crt

# Generate DH parameters
openssl dhparam -out redis/tls/redis.dh 2048

# Set proper permissions
chmod 600 redis/tls/*.key
chmod 644 redis/tls/*.crt
```

### 3. Configure Environment Variables

```bash
# Required environment variables
export REDIS_PASSWORD="YourSecurePassword2024!"
export REDIS_USERNAME="meta-ads-app"
export SENTINEL_PASSWORD="SentinelSecurePassword2024!"

# Optional configuration
export REDIS_TLS_ENABLED="true"
export BACKUP_S3_BUCKET="your-backup-bucket"
export SLACK_WEBHOOK="https://hooks.slack.com/..."
```

### 4. Deploy Redis Cluster

```bash
# Start the Redis cluster
docker-compose -f docker-compose.redis.yml up -d

# Verify deployment
docker-compose -f docker-compose.redis.yml ps

# Check logs
docker-compose -f docker-compose.redis.yml logs redis-master
```

### 5. Initialize Application Connection

```typescript
import { redisManager, RedisDatabase } from '@/lib/redis-manager'

// Initialize Redis connections
await redisManager.initialize()

// Use specific database connections
const sessionStore = redisManager.getSessionStore()
const cacheStore = redisManager.getCacheStore()
```

## 🔧 Configuration

### Security Configuration

#### Authentication
- **Multi-user ACL system** with role-based access
- **Strong password policies** with rotation requirements
- **TLS encryption** for all connections
- **IP whitelisting** and network isolation

#### User Roles
```bash
# Application users
meta-ads-app         # Full application access
session-manager      # Session DB only
cache-manager        # Cache DB only
rate-limiter         # Rate limiting DB only
job-manager          # Job queue DB only
analytics-reader     # Analytics DB read-only

# Administrative users
redis-admin          # Emergency full access
monitoring           # Metrics collection
backup-service       # Backup operations
```

### Performance Configuration

#### Memory Management
- **2GB memory limit** with LRU eviction
- **Lazy freeing** for better performance
- **Active defragmentation** enabled
- **Memory usage tracking** and alerts

#### Connection Management
- **10,000 max connections** with timeout
- **Connection pooling** in application
- **Keep-alive** configuration
- **Connection monitoring** and alerting

### Database Configuration

#### TTL Defaults
- **Sessions**: 30 days
- **User Preferences**: 1 year
- **API Cache**: 1 hour
- **Rate Limiting**: 1 hour
- **Job Queue**: 7 days
- **Analytics**: 24 hours

## 📊 Monitoring & Alerting

### Metrics Collection
- **Redis Exporter** for Prometheus integration
- **Sentinel monitoring** for failover events
- **Database-specific metrics** for each use case
- **Performance tracking** and capacity planning

### Alert Rules
- **Instance availability** (critical)
- **Memory usage** (warning at 85%, critical at 95%)
- **Replication lag** (warning at 1000 bytes)
- **Connection limits** (warning at 80%)
- **Sentinel quorum** (critical if <2 sentinels)

### Dashboards
- **Redis Overview** - cluster health and performance
- **Database Metrics** - per-database statistics
- **Sentinel Status** - failover monitoring
- **Security Events** - authentication and access logs

## 🔄 High Availability

### Automatic Failover
```bash
# Sentinels monitor master and replicas
# Automatic promotion when master fails
# Client reconnection through Sentinel discovery
# Application restart for fresh connections
```

### Manual Failover
```bash
# Force failover
./redis/scripts/failover.sh failover

# Check status
./redis/scripts/failover.sh status

# Start monitoring
./redis/scripts/failover.sh monitor
```

### Recovery Procedures
```bash
# Automated recovery
./redis/scripts/failover.sh recover

# Health checks
./redis/scripts/health-check.sh

# Application restart
./redis/scripts/failover.sh restart-app
```

## 💾 Backup & Recovery

### Automated Backups
```bash
# Full backup (RDB + AOF + logical)
./redis/scripts/backup.sh backup

# Scheduled backups (cron)
0 */6 * * * /path/to/backup.sh backup
```

### Backup Types
- **RDB snapshots** - point-in-time binary backups
- **AOF backups** - append-only file backups
- **Logical backups** - JSON export of all databases
- **S3 upload** with encryption and compression
- **Retention policy** (30 days default)

### Recovery
```bash
# List available backups
./redis/scripts/backup.sh list

# Download from S3
./redis/scripts/backup.sh download <s3-key> <local-file>

# Restore (manual process with service stop)
```

## 🔍 Troubleshooting

### Common Issues

#### Connection Refused
```bash
# Check Redis status
docker-compose -f docker-compose.redis.yml ps

# Check logs
docker logs meta-ads-redis-master

# Test connectivity
redis-cli -h localhost -p 6379 ping
```

#### Memory Issues
```bash
# Check memory usage
redis-cli info memory

# Check slow queries
redis-cli slowlog get 10

# Monitor memory in real-time
watch -n 1 'redis-cli info memory | grep used_memory_human'
```

#### Replication Issues
```bash
# Check replication status
redis-cli info replication

# Check Sentinel status
redis-cli -p 26379 sentinel masters

# Force failover if needed
./redis/scripts/failover.sh failover
```

### Health Checks
```bash
# Full health check
./redis/scripts/health-check.sh

# Master only
./redis/scripts/health-check.sh master-only

# Sentinels only
./redis/scripts/health-check.sh sentinels-only
```

## 🔐 Security Best Practices

### Password Management
- **Generate strong passwords** (>20 characters)
- **Rotate passwords** every 90 days
- **Use environment variables** for secrets
- **Never commit passwords** to version control

### Network Security
- **Bind to specific interfaces** (never 0.0.0.0)
- **Use TLS** for all connections
- **IP whitelisting** at firewall level
- **VPN access** for administration

### Access Control
- **Principle of least privilege** for users
- **Disable dangerous commands** in production
- **Monitor ACL logs** for violations
- **Regular security audits**

### Monitoring Security
- **Failed authentication attempts**
- **Unusual command patterns**
- **Configuration changes**
- **Network connections**

## 📚 Integration Examples

### Session Management
```typescript
// Store user session
await redisManager.saveSession(sessionId, {
  userId: user.id,
  expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000
}, 30 * 24 * 60 * 60)

// Get session
const session = await redisManager.getSession(sessionId)
```

### API Caching
```typescript
// Cache API response
await redisManager.cacheApiResponse('campaigns', { accountId }, data, 3600)

// Get cached response
const cached = await redisManager.getCachedApiResponse('campaigns', { accountId })
```

### Rate Limiting
```typescript
// Check rate limit
const { count, remaining, resetTime } = await redisManager.incrementWithExpiry(
  `rate:${userId}`, 3600, 100
)
```

### Job Queue
```typescript
// Enqueue job
const jobId = await redisManager.enqueueJob('sync-campaigns', { accountId })

// Dequeue job
const job = await redisManager.dequeueJob('sync-campaigns')
```

## 🚨 Production Checklist

### Before Deployment
- [ ] TLS certificates generated and installed
- [ ] Strong passwords configured
- [ ] Network security implemented
- [ ] Monitoring and alerting configured
- [ ] Backup procedures tested
- [ ] Failover procedures tested
- [ ] Application integration tested

### After Deployment
- [ ] Health checks passing
- [ ] Monitoring dashboards accessible
- [ ] Backup automation verified
- [ ] Security monitoring active
- [ ] Performance baselines established
- [ ] Documentation updated
- [ ] Team training completed

## 📞 Support

### Monitoring Dashboards
- **Grafana**: http://localhost:3001 (admin/RedisAdmin2024!)
- **Redis Insight**: http://localhost:8001 (development only)
- **Prometheus**: http://localhost:9090

### Log Files
- **Redis**: `/var/log/redis/redis-server.log`
- **Sentinel**: `/var/log/redis/sentinel.log`
- **Health Checks**: `/var/log/redis/health-check.log`
- **Backups**: `/var/log/redis/backup.log`
- **Failover**: `/var/log/redis/failover.log`

### Emergency Contacts
- **Slack**: #redis-alerts channel
- **Email**: ops@meta-ads.com
- **On-call**: Use failover.sh monitor for automatic handling

---

**⚠️ Important**: Always test configuration changes in a staging environment before applying to production. This Redis setup is designed for high availability and data safety, but proper operational procedures are essential.