#!/bin/bash

# Meta Ads Intelligence Platform - Redis Health Check Script
# Comprehensive health monitoring for Redis cluster with Sentinel

set -euo pipefail

# =======================
# CONFIGURATION
# =======================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/redis/health-check.log"
ALERT_WEBHOOK="${REDIS_ALERT_WEBHOOK:-}"
REDIS_PASSWORD="${REDIS_PASSWORD:-MetaAds2024!SecureRedis#Production$}"
REDIS_USERNAME="${REDIS_USERNAME:-meta-ads-app}"

# Redis instances
REDIS_MASTER_HOST="${REDIS_MASTER_HOST:-redis-master}"
REDIS_MASTER_PORT="${REDIS_MASTER_PORT:-6379}"
REDIS_REPLICA_1_HOST="${REDIS_REPLICA_1_HOST:-redis-replica-1}"
REDIS_REPLICA_1_PORT="${REDIS_REPLICA_1_PORT:-6381}"
REDIS_REPLICA_2_HOST="${REDIS_REPLICA_2_HOST:-redis-replica-2}"
REDIS_REPLICA_2_PORT="${REDIS_REPLICA_2_PORT:-6383}"

# Sentinel instances
SENTINEL_1_HOST="${SENTINEL_1_HOST:-redis-sentinel-1}"
SENTINEL_1_PORT="${SENTINEL_1_PORT:-26379}"
SENTINEL_2_HOST="${SENTINEL_2_HOST:-redis-sentinel-2}"
SENTINEL_2_PORT="${SENTINEL_2_PORT:-26380}"
SENTINEL_3_HOST="${SENTINEL_3_HOST:-redis-sentinel-3}"
SENTINEL_3_PORT="${SENTINEL_3_PORT:-26381}"

# Health check thresholds
MEMORY_WARNING_THRESHOLD=85
MEMORY_CRITICAL_THRESHOLD=95
CONNECTION_WARNING_THRESHOLD=80
REPLICATION_LAG_THRESHOLD=1000
RESPONSE_TIME_THRESHOLD=1000  # milliseconds

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

# Send alert to webhook if configured
send_alert() {
    local severity="$1"
    local message="$2"
    local instance="${3:-unknown}"

    if [[ -n "$ALERT_WEBHOOK" ]]; then
        local payload=$(cat <<EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "service": "redis",
    "instance": "$instance",
    "severity": "$severity",
    "message": "$message",
    "environment": "${ENVIRONMENT:-production}"
}
EOF
)

        curl -s -X POST "$ALERT_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$payload" || log_warn "Failed to send alert webhook"
    fi
}

# Execute Redis command with authentication
redis_cmd() {
    local host="$1"
    local port="$2"
    local cmd="$3"
    local timeout="${4:-5}"

    timeout "$timeout" redis-cli \
        -h "$host" \
        -p "$port" \
        --user "$REDIS_USERNAME" \
        -a "$REDIS_PASSWORD" \
        --no-auth-warning \
        $cmd 2>/dev/null
}

# Execute Sentinel command
sentinel_cmd() {
    local host="$1"
    local port="$2"
    local cmd="$3"
    local timeout="${4:-5}"

    timeout "$timeout" redis-cli \
        -h "$host" \
        -p "$port" \
        $cmd 2>/dev/null
}

# =======================
# HEALTH CHECK FUNCTIONS
# =======================

check_redis_connectivity() {
    local host="$1"
    local port="$2"
    local instance_name="$3"

    log_info "Checking connectivity for $instance_name ($host:$port)"

    local start_time=$(date +%s%3N)
    if redis_cmd "$host" "$port" "ping"; then
        local end_time=$(date +%s%3N)
        local response_time=$((end_time - start_time))

        if [[ $response_time -gt $RESPONSE_TIME_THRESHOLD ]]; then
            log_warn "$instance_name response time: ${response_time}ms (threshold: ${RESPONSE_TIME_THRESHOLD}ms)"
        else
            log_success "$instance_name connectivity OK (${response_time}ms)"
        fi
        return 0
    else
        log_error "$instance_name connectivity FAILED"
        send_alert "critical" "$instance_name is not responding to ping" "$instance_name"
        return 1
    fi
}

check_redis_memory() {
    local host="$1"
    local port="$2"
    local instance_name="$3"

    log_info "Checking memory usage for $instance_name"

    local memory_info=$(redis_cmd "$host" "$port" "info memory")
    if [[ -z "$memory_info" ]]; then
        log_error "Failed to get memory info from $instance_name"
        return 1
    fi

    local used_memory=$(echo "$memory_info" | grep "^used_memory:" | cut -d: -f2 | tr -d '\r')
    local max_memory=$(echo "$memory_info" | grep "^maxmemory:" | cut -d: -f2 | tr -d '\r')

    if [[ "$max_memory" == "0" ]]; then
        log_warn "$instance_name has no memory limit set"
        return 0
    fi

    local memory_usage_percent=$((used_memory * 100 / max_memory))

    if [[ $memory_usage_percent -gt $MEMORY_CRITICAL_THRESHOLD ]]; then
        log_error "$instance_name memory usage CRITICAL: ${memory_usage_percent}%"
        send_alert "critical" "$instance_name memory usage is ${memory_usage_percent}%" "$instance_name"
        return 1
    elif [[ $memory_usage_percent -gt $MEMORY_WARNING_THRESHOLD ]]; then
        log_warn "$instance_name memory usage WARNING: ${memory_usage_percent}%"
        send_alert "warning" "$instance_name memory usage is ${memory_usage_percent}%" "$instance_name"
    else
        log_success "$instance_name memory usage OK: ${memory_usage_percent}%"
    fi

    return 0
}

check_redis_connections() {
    local host="$1"
    local port="$2"
    local instance_name="$3"

    log_info "Checking connections for $instance_name"

    local info=$(redis_cmd "$host" "$port" "info clients")
    if [[ -z "$info" ]]; then
        log_error "Failed to get client info from $instance_name"
        return 1
    fi

    local connected_clients=$(echo "$info" | grep "^connected_clients:" | cut -d: -f2 | tr -d '\r')
    local max_clients=$(redis_cmd "$host" "$port" "config get maxclients" | tail -1)

    if [[ -n "$max_clients" && "$max_clients" != "0" ]]; then
        local connection_usage_percent=$((connected_clients * 100 / max_clients))

        if [[ $connection_usage_percent -gt $CONNECTION_WARNING_THRESHOLD ]]; then
            log_warn "$instance_name connection usage: ${connection_usage_percent}% (${connected_clients}/${max_clients})"
            send_alert "warning" "$instance_name connection usage is ${connection_usage_percent}%" "$instance_name"
        else
            log_success "$instance_name connections OK: ${connection_usage_percent}% (${connected_clients}/${max_clients})"
        fi
    else
        log_success "$instance_name connections: $connected_clients (no limit)"
    fi

    return 0
}

check_redis_replication() {
    local host="$1"
    local port="$2"
    local instance_name="$3"

    log_info "Checking replication for $instance_name"

    local replication_info=$(redis_cmd "$host" "$port" "info replication")
    if [[ -z "$replication_info" ]]; then
        log_error "Failed to get replication info from $instance_name"
        return 1
    fi

    local role=$(echo "$replication_info" | grep "^role:" | cut -d: -f2 | tr -d '\r')

    if [[ "$role" == "master" ]]; then
        local connected_slaves=$(echo "$replication_info" | grep "^connected_slaves:" | cut -d: -f2 | tr -d '\r')
        log_success "$instance_name is master with $connected_slaves replicas"

        # Check individual replica lag
        local replica_count=0
        while IFS= read -r line; do
            if [[ "$line" =~ ^slave[0-9]+: ]]; then
                ((replica_count++))
                local lag=$(echo "$line" | grep -o "lag=[0-9]*" | cut -d= -f2)
                if [[ -n "$lag" && $lag -gt $REPLICATION_LAG_THRESHOLD ]]; then
                    log_warn "Replica $replica_count lag: ${lag} seconds"
                    send_alert "warning" "Replica $replica_count has high lag: ${lag}s" "$instance_name"
                fi
            fi
        done <<< "$replication_info"

    elif [[ "$role" == "slave" ]]; then
        local master_link_status=$(echo "$replication_info" | grep "^master_link_status:" | cut -d: -f2 | tr -d '\r')
        local master_last_io_seconds=$(echo "$replication_info" | grep "^master_last_io_seconds_ago:" | cut -d: -f2 | tr -d '\r')

        if [[ "$master_link_status" == "up" ]]; then
            log_success "$instance_name replication link UP (last IO: ${master_last_io_seconds}s ago)"
        else
            log_error "$instance_name replication link DOWN"
            send_alert "critical" "$instance_name replication link is down" "$instance_name"
            return 1
        fi
    fi

    return 0
}

check_redis_persistence() {
    local host="$1"
    local port="$2"
    local instance_name="$3"

    log_info "Checking persistence for $instance_name"

    local persistence_info=$(redis_cmd "$host" "$port" "info persistence")
    if [[ -z "$persistence_info" ]]; then
        log_error "Failed to get persistence info from $instance_name"
        return 1
    fi

    # Check RDB
    local rdb_last_save=$(echo "$persistence_info" | grep "^rdb_last_save_time:" | cut -d: -f2 | tr -d '\r')
    local current_time=$(date +%s)
    local rdb_age=$((current_time - rdb_last_save))

    if [[ $rdb_age -gt 7200 ]]; then  # 2 hours
        log_warn "$instance_name RDB last save: $(date -d @$rdb_last_save) (${rdb_age}s ago)"
    else
        log_success "$instance_name RDB last save: $(date -d @$rdb_last_save)"
    fi

    # Check AOF if enabled
    local aof_enabled=$(echo "$persistence_info" | grep "^aof_enabled:" | cut -d: -f2 | tr -d '\r')
    if [[ "$aof_enabled" == "1" ]]; then
        local aof_last_rewrite=$(echo "$persistence_info" | grep "^aof_last_rewrite_time_sec:" | cut -d: -f2 | tr -d '\r')
        if [[ "$aof_last_rewrite" == "-1" ]]; then
            log_success "$instance_name AOF enabled (no rewrite yet)"
        else
            log_success "$instance_name AOF last rewrite: ${aof_last_rewrite}s"
        fi
    fi

    return 0
}

check_redis_databases() {
    local host="$1"
    local port="$2"
    local instance_name="$3"

    log_info "Checking databases for $instance_name"

    local keyspace_info=$(redis_cmd "$host" "$port" "info keyspace")
    if [[ -z "$keyspace_info" ]]; then
        log_warn "No keyspace info available from $instance_name"
        return 0
    fi

    # Check each database
    for db in {0..5}; do
        local db_info=$(echo "$keyspace_info" | grep "^db${db}:")
        if [[ -n "$db_info" ]]; then
            local keys=$(echo "$db_info" | grep -o "keys=[0-9]*" | cut -d= -f2)
            local expires=$(echo "$db_info" | grep -o "expires=[0-9]*" | cut -d= -f2)
            log_success "$instance_name DB$db: $keys keys, $expires with TTL"
        fi
    done

    return 0
}

check_sentinel() {
    local host="$1"
    local port="$2"
    local sentinel_name="$3"

    log_info "Checking Sentinel $sentinel_name ($host:$port)"

    # Check if Sentinel is responding
    if ! sentinel_cmd "$host" "$port" "ping" >/dev/null; then
        log_error "Sentinel $sentinel_name is not responding"
        send_alert "critical" "Sentinel $sentinel_name is not responding" "$sentinel_name"
        return 1
    fi

    # Check master information
    local master_info=$(sentinel_cmd "$host" "$port" "sentinel masters")
    if [[ -z "$master_info" ]]; then
        log_error "Failed to get master info from Sentinel $sentinel_name"
        return 1
    fi

    # Check if master is reachable
    local master_status=$(sentinel_cmd "$host" "$port" "sentinel master meta-ads-master" | grep -A1 "flags" | tail -1)
    if [[ "$master_status" == "master" ]]; then
        log_success "Sentinel $sentinel_name: master status OK"
    else
        log_warn "Sentinel $sentinel_name: master status: $master_status"
    fi

    # Check number of sentinels
    local sentinel_count=$(sentinel_cmd "$host" "$port" "sentinel sentinels meta-ads-master" | grep -c "name" || echo "0")
    if [[ $sentinel_count -lt 2 ]]; then
        log_warn "Sentinel $sentinel_name sees only $sentinel_count other sentinels"
        send_alert "warning" "Sentinel quorum at risk: only $sentinel_count sentinels" "$sentinel_name"
    else
        log_success "Sentinel $sentinel_name: $sentinel_count sentinels in quorum"
    fi

    return 0
}

# =======================
# MAIN HEALTH CHECK
# =======================

main() {
    log_info "Starting Redis health check - $(date)"

    local overall_status=0
    local failed_checks=()

    echo "================================================="
    echo "Meta Ads Intelligence Platform - Redis Health Check"
    echo "================================================="

    # Check Redis instances
    echo -e "\n${BLUE}=== Redis Master Health Check ===${NC}"
    if ! check_redis_connectivity "$REDIS_MASTER_HOST" "$REDIS_MASTER_PORT" "redis-master"; then
        failed_checks+=("redis-master-connectivity")
        overall_status=1
    else
        check_redis_memory "$REDIS_MASTER_HOST" "$REDIS_MASTER_PORT" "redis-master" || failed_checks+=("redis-master-memory")
        check_redis_connections "$REDIS_MASTER_HOST" "$REDIS_MASTER_PORT" "redis-master" || failed_checks+=("redis-master-connections")
        check_redis_replication "$REDIS_MASTER_HOST" "$REDIS_MASTER_PORT" "redis-master" || failed_checks+=("redis-master-replication")
        check_redis_persistence "$REDIS_MASTER_HOST" "$REDIS_MASTER_PORT" "redis-master" || failed_checks+=("redis-master-persistence")
        check_redis_databases "$REDIS_MASTER_HOST" "$REDIS_MASTER_PORT" "redis-master" || failed_checks+=("redis-master-databases")
    fi

    echo -e "\n${BLUE}=== Redis Replica 1 Health Check ===${NC}"
    if ! check_redis_connectivity "$REDIS_REPLICA_1_HOST" "$REDIS_REPLICA_1_PORT" "redis-replica-1"; then
        failed_checks+=("redis-replica-1-connectivity")
        overall_status=1
    else
        check_redis_memory "$REDIS_REPLICA_1_HOST" "$REDIS_REPLICA_1_PORT" "redis-replica-1" || failed_checks+=("redis-replica-1-memory")
        check_redis_connections "$REDIS_REPLICA_1_HOST" "$REDIS_REPLICA_1_PORT" "redis-replica-1" || failed_checks+=("redis-replica-1-connections")
        check_redis_replication "$REDIS_REPLICA_1_HOST" "$REDIS_REPLICA_1_PORT" "redis-replica-1" || failed_checks+=("redis-replica-1-replication")
    fi

    echo -e "\n${BLUE}=== Redis Replica 2 Health Check ===${NC}"
    if ! check_redis_connectivity "$REDIS_REPLICA_2_HOST" "$REDIS_REPLICA_2_PORT" "redis-replica-2"; then
        failed_checks+=("redis-replica-2-connectivity")
        overall_status=1
    else
        check_redis_memory "$REDIS_REPLICA_2_HOST" "$REDIS_REPLICA_2_PORT" "redis-replica-2" || failed_checks+=("redis-replica-2-memory")
        check_redis_connections "$REDIS_REPLICA_2_HOST" "$REDIS_REPLICA_2_PORT" "redis-replica-2" || failed_checks+=("redis-replica-2-connections")
        check_redis_replication "$REDIS_REPLICA_2_HOST" "$REDIS_REPLICA_2_PORT" "redis-replica-2" || failed_checks+=("redis-replica-2-replication")
    fi

    # Check Sentinels
    echo -e "\n${BLUE}=== Redis Sentinel Health Check ===${NC}"
    check_sentinel "$SENTINEL_1_HOST" "$SENTINEL_1_PORT" "sentinel-1" || failed_checks+=("sentinel-1")
    check_sentinel "$SENTINEL_2_HOST" "$SENTINEL_2_PORT" "sentinel-2" || failed_checks+=("sentinel-2")
    check_sentinel "$SENTINEL_3_HOST" "$SENTINEL_3_PORT" "sentinel-3" || failed_checks+=("sentinel-3")

    # Summary
    echo -e "\n${BLUE}=== Health Check Summary ===${NC}"

    if [[ ${#failed_checks[@]} -eq 0 ]]; then
        log_success "All Redis health checks PASSED"
        echo -e "${GREEN}✓ All systems healthy${NC}"
    else
        log_error "Health check FAILED. Failed checks: ${failed_checks[*]}"
        echo -e "${RED}✗ Failed checks: ${failed_checks[*]}${NC}"
        overall_status=1
    fi

    log_info "Redis health check completed - $(date)"

    # Return appropriate exit code
    exit $overall_status
}

# =======================
# SCRIPT EXECUTION
# =======================

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Handle script arguments
case "${1:-check}" in
    "check")
        main
        ;;
    "master-only")
        log_info "Checking Redis master only"
        check_redis_connectivity "$REDIS_MASTER_HOST" "$REDIS_MASTER_PORT" "redis-master"
        ;;
    "sentinels-only")
        log_info "Checking Redis sentinels only"
        check_sentinel "$SENTINEL_1_HOST" "$SENTINEL_1_PORT" "sentinel-1"
        check_sentinel "$SENTINEL_2_HOST" "$SENTINEL_2_PORT" "sentinel-2"
        check_sentinel "$SENTINEL_3_HOST" "$SENTINEL_3_PORT" "sentinel-3"
        ;;
    "help")
        echo "Usage: $0 [check|master-only|sentinels-only|help]"
        echo "  check         - Full health check (default)"
        echo "  master-only   - Check only master instance"
        echo "  sentinels-only - Check only sentinel instances"
        echo "  help          - Show this help message"
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac