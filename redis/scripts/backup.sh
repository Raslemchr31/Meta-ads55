#!/bin/bash

# Meta Ads Intelligence Platform - Redis Backup Script
# Automated backup and recovery for Redis data

set -euo pipefail

# =======================
# CONFIGURATION
# =======================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/redis/backup.log"
BACKUP_DIR="/backups"
REDIS_DATA_DIR="/var/lib/redis"

# Redis configuration
REDIS_PASSWORD="${REDIS_PASSWORD:-MetaAds2024!SecureRedis#Production$}"
REDIS_USERNAME="${REDIS_USERNAME:-meta-ads-app}"
REDIS_HOST="${REDIS_MASTER_HOST:-redis-master}"
REDIS_PORT="${REDIS_MASTER_PORT:-6379}"

# AWS S3 configuration
S3_BUCKET="${REDIS_BACKUP_S3_BUCKET:-meta-ads-redis-backups}"
AWS_REGION="${AWS_REGION:-us-east-1}"

# Backup configuration
BACKUP_RETENTION_DAYS=30
BACKUP_COMPRESSION_LEVEL=6
BACKUP_PREFIX="meta-ads-redis"
ENCRYPT_BACKUPS="${ENCRYPT_BACKUPS:-true}"
BACKUP_ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"

# Notification configuration
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
ALERT_WEBHOOK="${REDIS_ALERT_WEBHOOK:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =======================
# UTILITY FUNCTIONS
# =======================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "$@"
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_warn() {
    log "WARN" "$@"
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    log "ERROR" "$@"
    echo -e "${RED}[ERROR]${NC} $*"
}

log_success() {
    log "SUCCESS" "$@"
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

# Send notification
send_notification() {
    local status="$1"
    local title="$2"
    local message="$3"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Send to Slack if configured
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        local color="good"
        [[ "$status" == "warning" ]] && color="warning"
        [[ "$status" == "error" ]] && color="danger"

        local slack_payload=$(cat <<EOF
{
    "username": "Redis Backup Bot",
    "icon_emoji": ":floppy_disk:",
    "attachments": [
        {
            "color": "$color",
            "title": "$title",
            "text": "$message",
            "fields": [
                {
                    "title": "Service",
                    "value": "Redis Backup",
                    "short": true
                },
                {
                    "title": "Environment",
                    "value": "${ENVIRONMENT:-production}",
                    "short": true
                }
            ],
            "footer": "Meta Ads Intelligence Platform",
            "ts": $(date +%s)
        }
    ]
}
EOF
)
        curl -s -X POST "$SLACK_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$slack_payload" || log_warn "Failed to send Slack notification"
    fi

    # Send to webhook if configured
    if [[ -n "$ALERT_WEBHOOK" ]]; then
        local payload=$(cat <<EOF
{
    "timestamp": "$timestamp",
    "service": "redis-backup",
    "status": "$status",
    "title": "$title",
    "message": "$message",
    "environment": "${ENVIRONMENT:-production}"
}
EOF
)
        curl -s -X POST "$ALERT_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$payload" || log_warn "Failed to send webhook notification"
    fi
}

# Execute Redis command
redis_cmd() {
    local cmd="$1"
    local timeout="${2:-30}"

    timeout "$timeout" redis-cli \
        -h "$REDIS_HOST" \
        -p "$REDIS_PORT" \
        --user "$REDIS_USERNAME" \
        -a "$REDIS_PASSWORD" \
        --no-auth-warning \
        $cmd 2>/dev/null
}

# Check if Redis is available
check_redis_connection() {
    if redis_cmd "ping" 5 >/dev/null; then
        return 0
    else
        return 1
    fi
}

# Get backup filename with timestamp
get_backup_filename() {
    local backup_type="$1"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    echo "${BACKUP_PREFIX}_${backup_type}_${timestamp}"
}

# Encrypt file if encryption is enabled
encrypt_file() {
    local input_file="$1"
    local output_file="$2"

    if [[ "$ENCRYPT_BACKUPS" == "true" ]] && [[ -n "$BACKUP_ENCRYPTION_KEY" ]]; then
        log_info "Encrypting backup file"
        openssl enc -aes-256-cbc -salt -in "$input_file" -out "$output_file" -k "$BACKUP_ENCRYPTION_KEY"
        rm "$input_file"
        return 0
    else
        mv "$input_file" "$output_file"
        return 0
    fi
}

# Decrypt file if encryption is enabled
decrypt_file() {
    local input_file="$1"
    local output_file="$2"

    if [[ "$ENCRYPT_BACKUPS" == "true" ]] && [[ -n "$BACKUP_ENCRYPTION_KEY" ]]; then
        log_info "Decrypting backup file"
        openssl enc -aes-256-cbc -d -in "$input_file" -out "$output_file" -k "$BACKUP_ENCRYPTION_KEY"
        return 0
    else
        cp "$input_file" "$output_file"
        return 0
    fi
}

# =======================
# BACKUP FUNCTIONS
# =======================

# Create RDB backup
create_rdb_backup() {
    log_info "Creating RDB backup"

    if ! check_redis_connection; then
        log_error "Cannot connect to Redis at $REDIS_HOST:$REDIS_PORT"
        return 1
    fi

    # Trigger background save
    log_info "Triggering Redis background save (BGSAVE)"
    if ! redis_cmd "bgsave"; then
        log_error "Failed to trigger background save"
        return 1
    fi

    # Wait for background save to complete
    log_info "Waiting for background save to complete"
    local max_wait=300  # 5 minutes
    local wait_time=0

    while [[ $wait_time -lt $max_wait ]]; do
        local last_save=$(redis_cmd "lastsave")
        sleep 5
        local current_save=$(redis_cmd "lastsave")

        if [[ "$current_save" != "$last_save" ]]; then
            log_success "Background save completed"
            break
        fi

        wait_time=$((wait_time + 5))
        log_info "Background save in progress... (${wait_time}s)"
    done

    if [[ $wait_time -ge $max_wait ]]; then
        log_error "Background save timeout"
        return 1
    fi

    # Create backup file
    local backup_filename=$(get_backup_filename "rdb")
    local source_file="$REDIS_DATA_DIR/dump.rdb"
    local temp_file="$BACKUP_DIR/${backup_filename}.rdb"
    local final_file="$BACKUP_DIR/${backup_filename}.rdb"

    if [[ ! -f "$source_file" ]]; then
        log_error "RDB file not found at $source_file"
        return 1
    fi

    # Copy and compress
    log_info "Copying and compressing RDB file"
    gzip -c -$BACKUP_COMPRESSION_LEVEL "$source_file" > "${temp_file}.gz"

    # Encrypt if enabled
    if ! encrypt_file "${temp_file}.gz" "${final_file}.gz.enc"; then
        log_error "Failed to encrypt backup file"
        return 1
    fi

    # Calculate checksums
    local checksum=$(sha256sum "${final_file}.gz.enc" | cut -d' ' -f1)
    echo "$checksum" > "${final_file}.sha256"

    # Get file size
    local file_size=$(stat -f%z "${final_file}.gz.enc" 2>/dev/null || stat -c%s "${final_file}.gz.enc")
    local file_size_mb=$((file_size / 1024 / 1024))

    log_success "RDB backup created: ${backup_filename}.gz.enc (${file_size_mb}MB)"
    echo "${final_file}.gz.enc"
}

# Create AOF backup
create_aof_backup() {
    log_info "Creating AOF backup"

    if ! check_redis_connection; then
        log_error "Cannot connect to Redis at $REDIS_HOST:$REDIS_PORT"
        return 1
    fi

    # Check if AOF is enabled
    local aof_enabled=$(redis_cmd "config get appendonly" | tail -1)
    if [[ "$aof_enabled" != "yes" ]]; then
        log_warn "AOF is not enabled, skipping AOF backup"
        return 0
    fi

    # Trigger AOF rewrite
    log_info "Triggering AOF rewrite (BGREWRITEAOF)"
    if ! redis_cmd "bgrewriteaof"; then
        log_error "Failed to trigger AOF rewrite"
        return 1
    fi

    # Wait for AOF rewrite to complete
    log_info "Waiting for AOF rewrite to complete"
    local max_wait=600  # 10 minutes
    local wait_time=0

    while [[ $wait_time -lt $max_wait ]]; do
        local aof_rewrite=$(redis_cmd "info persistence" | grep "aof_rewrite_in_progress:1" || true)
        if [[ -z "$aof_rewrite" ]]; then
            log_success "AOF rewrite completed"
            break
        fi

        wait_time=$((wait_time + 10))
        log_info "AOF rewrite in progress... (${wait_time}s)"
        sleep 10
    done

    if [[ $wait_time -ge $max_wait ]]; then
        log_error "AOF rewrite timeout"
        return 1
    fi

    # Create backup file
    local backup_filename=$(get_backup_filename "aof")
    local source_file="$REDIS_DATA_DIR/appendonly.aof"
    local temp_file="$BACKUP_DIR/${backup_filename}.aof"
    local final_file="$BACKUP_DIR/${backup_filename}.aof"

    if [[ ! -f "$source_file" ]]; then
        log_error "AOF file not found at $source_file"
        return 1
    fi

    # Copy and compress
    log_info "Copying and compressing AOF file"
    gzip -c -$BACKUP_COMPRESSION_LEVEL "$source_file" > "${temp_file}.gz"

    # Encrypt if enabled
    if ! encrypt_file "${temp_file}.gz" "${final_file}.gz.enc"; then
        log_error "Failed to encrypt backup file"
        return 1
    fi

    # Calculate checksums
    local checksum=$(sha256sum "${final_file}.gz.enc" | cut -d' ' -f1)
    echo "$checksum" > "${final_file}.sha256"

    # Get file size
    local file_size=$(stat -f%z "${final_file}.gz.enc" 2>/dev/null || stat -c%s "${final_file}.gz.enc")
    local file_size_mb=$((file_size / 1024 / 1024))

    log_success "AOF backup created: ${backup_filename}.gz.enc (${file_size_mb}MB)"
    echo "${final_file}.gz.enc"
}

# Create logical backup (database dump)
create_logical_backup() {
    log_info "Creating logical backup (database dump)"

    if ! check_redis_connection; then
        log_error "Cannot connect to Redis at $REDIS_HOST:$REDIS_PORT"
        return 1
    fi

    local backup_filename=$(get_backup_filename "logical")
    local temp_file="$BACKUP_DIR/${backup_filename}.json"
    local final_file="$BACKUP_DIR/${backup_filename}.json"

    # Create JSON dump with database structure
    log_info "Dumping database structure and data"

    cat > "$temp_file" <<EOF
{
  "meta": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "redis_version": "$(redis_cmd "info server" | grep "redis_version:" | cut -d: -f2 | tr -d '\r')",
    "databases": {
EOF

    # Dump each database
    for db in {0..5}; do
        local db_info=$(redis_cmd "eval \"redis.call('select', $db); local keys = redis.call('keys', '*'); local result = {}; for i=1,#keys do local key = keys[i]; local type = redis.call('type', key).ok; local ttl = redis.call('ttl', key); result[key] = {type=type, ttl=ttl}; if type == 'string' then result[key].value = redis.call('get', key); elseif type == 'hash' then result[key].value = redis.call('hgetall', key); elseif type == 'list' then result[key].value = redis.call('lrange', key, 0, -1); elseif type == 'set' then result[key].value = redis.call('smembers', key); elseif type == 'zset' then result[key].value = redis.call('zrange', key, 0, -1, 'withscores'); end end return cjson.encode(result)\" 0")

        echo "      \"$db\": $db_info" >> "$temp_file"
        [[ $db -lt 5 ]] && echo "," >> "$temp_file"
    done

    cat >> "$temp_file" <<EOF
    }
  }
}
EOF

    # Compress
    log_info "Compressing logical backup"
    gzip -$BACKUP_COMPRESSION_LEVEL "$temp_file"

    # Encrypt if enabled
    if ! encrypt_file "${temp_file}.gz" "${final_file}.gz.enc"; then
        log_error "Failed to encrypt backup file"
        return 1
    fi

    # Calculate checksums
    local checksum=$(sha256sum "${final_file}.gz.enc" | cut -d' ' -f1)
    echo "$checksum" > "${final_file}.sha256"

    # Get file size
    local file_size=$(stat -f%z "${final_file}.gz.enc" 2>/dev/null || stat -c%s "${final_file}.gz.enc")
    local file_size_mb=$((file_size / 1024 / 1024))

    log_success "Logical backup created: ${backup_filename}.gz.enc (${file_size_mb}MB)"
    echo "${final_file}.gz.enc"
}

# Upload backup to S3
upload_to_s3() {
    local backup_file="$1"
    local backup_type="$2"

    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi

    local filename=$(basename "$backup_file")
    local s3_key="backups/$(date '+%Y')/$(date '+%m')/$(date '+%d')/$filename"

    log_info "Uploading backup to S3: s3://$S3_BUCKET/$s3_key"

    # Upload file
    if aws s3 cp "$backup_file" "s3://$S3_BUCKET/$s3_key" --region "$AWS_REGION"; then
        log_success "Backup uploaded to S3 successfully"

        # Upload checksum file
        local checksum_file="${backup_file}.sha256"
        if [[ -f "$checksum_file" ]]; then
            aws s3 cp "$checksum_file" "s3://$S3_BUCKET/${s3_key}.sha256" --region "$AWS_REGION"
        fi

        # Set lifecycle policy for automatic cleanup
        aws s3api put-object-tagging \
            --bucket "$S3_BUCKET" \
            --key "$s3_key" \
            --tagging "TagSet=[{Key=backup-type,Value=$backup_type},{Key=retention-days,Value=$BACKUP_RETENTION_DAYS}]" \
            --region "$AWS_REGION" || log_warn "Failed to set S3 object tags"

        return 0
    else
        log_error "Failed to upload backup to S3"
        return 1
    fi
}

# Clean old local backups
cleanup_old_backups() {
    log_info "Cleaning up old local backups (older than $BACKUP_RETENTION_DAYS days)"

    find "$BACKUP_DIR" -name "${BACKUP_PREFIX}_*" -type f -mtime +$BACKUP_RETENTION_DAYS -delete
    find "$BACKUP_DIR" -name "${BACKUP_PREFIX}_*.sha256" -type f -mtime +$BACKUP_RETENTION_DAYS -delete

    log_success "Old backup cleanup completed"
}

# Full backup procedure
perform_full_backup() {
    log_info "Starting full Redis backup procedure"
    local start_time=$(date +%s)
    local backup_files=()
    local failed_backups=()

    # Create backup directory
    mkdir -p "$BACKUP_DIR"

    # Create RDB backup
    if backup_file=$(create_rdb_backup); then
        backup_files+=("$backup_file:rdb")
    else
        failed_backups+=("rdb")
    fi

    # Create AOF backup
    if backup_file=$(create_aof_backup); then
        [[ -n "$backup_file" ]] && backup_files+=("$backup_file:aof")
    else
        failed_backups+=("aof")
    fi

    # Create logical backup
    if backup_file=$(create_logical_backup); then
        backup_files+=("$backup_file:logical")
    else
        failed_backups+=("logical")
    fi

    # Upload to S3
    local uploaded_files=0
    for backup_entry in "${backup_files[@]}"; do
        local backup_file=$(echo "$backup_entry" | cut -d: -f1)
        local backup_type=$(echo "$backup_entry" | cut -d: -f2)

        if upload_to_s3 "$backup_file" "$backup_type"; then
            ((uploaded_files++))
        fi
    done

    # Cleanup old backups
    cleanup_old_backups

    # Calculate statistics
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local total_size=0

    for backup_entry in "${backup_files[@]}"; do
        local backup_file=$(echo "$backup_entry" | cut -d: -f1)
        if [[ -f "$backup_file" ]]; then
            local file_size=$(stat -f%z "$backup_file" 2>/dev/null || stat -c%s "$backup_file")
            total_size=$((total_size + file_size))
        fi
    done

    local total_size_mb=$((total_size / 1024 / 1024))

    # Generate summary
    local summary="Backup completed in ${duration}s"
    summary+="\nFiles created: ${#backup_files[@]}"
    summary+="\nFiles uploaded: $uploaded_files"
    summary+="\nTotal size: ${total_size_mb}MB"

    if [[ ${#failed_backups[@]} -eq 0 ]]; then
        log_success "Full backup completed successfully"
        log_success "$summary"
        send_notification "success" "Redis Backup Completed" "$summary"
    else
        log_error "Backup completed with failures: ${failed_backups[*]}"
        send_notification "warning" "Redis Backup Completed with Failures" "Failed backups: ${failed_backups[*]}\n$summary"
    fi

    return ${#failed_backups[@]}
}

# =======================
# RESTORE FUNCTIONS
# =======================

# List available backups
list_backups() {
    local backup_type="${1:-all}"

    log_info "Listing available backups"

    echo -e "\n${BLUE}=== Local Backups ===${NC}"
    if [[ "$backup_type" == "all" || "$backup_type" == "rdb" ]]; then
        echo "RDB Backups:"
        find "$BACKUP_DIR" -name "${BACKUP_PREFIX}_rdb_*" -type f | sort -r | head -10
    fi

    if [[ "$backup_type" == "all" || "$backup_type" == "aof" ]]; then
        echo -e "\nAOF Backups:"
        find "$BACKUP_DIR" -name "${BACKUP_PREFIX}_aof_*" -type f | sort -r | head -10
    fi

    if [[ "$backup_type" == "all" || "$backup_type" == "logical" ]]; then
        echo -e "\nLogical Backups:"
        find "$BACKUP_DIR" -name "${BACKUP_PREFIX}_logical_*" -type f | sort -r | head -10
    fi

    echo -e "\n${BLUE}=== S3 Backups ===${NC}"
    aws s3 ls "s3://$S3_BUCKET/backups/" --recursive --region "$AWS_REGION" | grep "$BACKUP_PREFIX" | tail -20
}

# Download backup from S3
download_backup() {
    local s3_key="$1"
    local local_file="$2"

    log_info "Downloading backup from S3: $s3_key"

    if aws s3 cp "s3://$S3_BUCKET/$s3_key" "$local_file" --region "$AWS_REGION"; then
        log_success "Backup downloaded successfully"

        # Download and verify checksum if available
        local checksum_file="${local_file}.sha256"
        if aws s3 cp "s3://$S3_BUCKET/${s3_key}.sha256" "$checksum_file" --region "$AWS_REGION" 2>/dev/null; then
            local expected_checksum=$(cat "$checksum_file")
            local actual_checksum=$(sha256sum "$local_file" | cut -d' ' -f1)

            if [[ "$expected_checksum" == "$actual_checksum" ]]; then
                log_success "Checksum verification passed"
            else
                log_error "Checksum verification failed!"
                return 1
            fi
        else
            log_warn "Checksum file not found, skipping verification"
        fi

        return 0
    else
        log_error "Failed to download backup from S3"
        return 1
    fi
}

# =======================
# MAIN FUNCTION
# =======================

main() {
    case "${1:-help}" in
        "backup")
            perform_full_backup
            ;;
        "rdb")
            create_rdb_backup
            ;;
        "aof")
            create_aof_backup
            ;;
        "logical")
            create_logical_backup
            ;;
        "list")
            list_backups "${2:-all}"
            ;;
        "cleanup")
            cleanup_old_backups
            ;;
        "download")
            if [[ $# -lt 3 ]]; then
                log_error "Usage: $0 download <s3-key> <local-file>"
                exit 1
            fi
            download_backup "$2" "$3"
            ;;
        "help"|*)
            echo "Meta Ads Intelligence Platform - Redis Backup Management"
            echo "Usage: $0 [command] [options]"
            echo ""
            echo "Commands:"
            echo "  backup          - Perform full backup (RDB + AOF + logical)"
            echo "  rdb             - Create RDB backup only"
            echo "  aof             - Create AOF backup only"
            echo "  logical         - Create logical backup only"
            echo "  list [type]     - List available backups (rdb|aof|logical|all)"
            echo "  cleanup         - Clean up old local backups"
            echo "  download <key> <file> - Download backup from S3"
            echo "  help            - Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  REDIS_PASSWORD           - Redis authentication password"
            echo "  REDIS_BACKUP_S3_BUCKET   - S3 bucket for backups"
            echo "  ENCRYPT_BACKUPS          - Enable backup encryption (true/false)"
            echo "  BACKUP_ENCRYPTION_KEY    - Encryption key for backups"
            echo "  SLACK_WEBHOOK           - Slack webhook for notifications"
            ;;
    esac
}

# =======================
# SCRIPT EXECUTION
# =======================

# Create necessary directories
mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

# Execute main function
main "$@"