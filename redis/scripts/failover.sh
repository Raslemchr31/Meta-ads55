#!/bin/bash

# Meta Ads Intelligence Platform - Redis Failover Management Script
# Automated failover handling and recovery procedures

set -euo pipefail

# =======================
# CONFIGURATION
# =======================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/redis/failover.log"
ALERT_WEBHOOK="${REDIS_ALERT_WEBHOOK:-}"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"

# Redis configuration
REDIS_PASSWORD="${REDIS_PASSWORD:-MetaAds2024!SecureRedis#Production$}"
REDIS_USERNAME="${REDIS_USERNAME:-meta-ads-app}"
SENTINEL_PASSWORD="${SENTINEL_PASSWORD:-SentinelSecure2024!Guard#}"

# Sentinel instances
SENTINEL_1_HOST="${SENTINEL_1_HOST:-redis-sentinel-1}"
SENTINEL_1_PORT="${SENTINEL_1_PORT:-26379}"
SENTINEL_2_HOST="${SENTINEL_2_HOST:-redis-sentinel-2}"
SENTINEL_2_PORT="${SENTINEL_2_PORT:-26380}"
SENTINEL_3_HOST="${SENTINEL_3_HOST:-redis-sentinel-3}"
SENTINEL_3_PORT="${SENTINEL_3_PORT:-26381}"

MASTER_NAME="${REDIS_MASTER_NAME:-meta-ads-master}"

# Application configuration
APP_NAME="meta-ads-intelligence-platform"
NAMESPACE="${KUBERNETES_NAMESPACE:-default}"
APP_RESTART_COMMAND="${APP_RESTART_COMMAND:-docker-compose restart meta-ads-app}"

# Timing configuration
FAILOVER_TIMEOUT=180  # 3 minutes
RECOVERY_CHECK_INTERVAL=30  # 30 seconds
MAX_RECOVERY_ATTEMPTS=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

log_critical() {
    log "CRITICAL" "$@"
    echo -e "${RED}[CRITICAL]${NC} $*"
}

# Send notification to multiple channels
send_notification() {
    local severity="$1"
    local title="$2"
    local message="$3"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Send to webhook if configured
    if [[ -n "$ALERT_WEBHOOK" ]]; then
        local payload=$(cat <<EOF
{
    "timestamp": "$timestamp",
    "service": "redis",
    "severity": "$severity",
    "title": "$title",
    "message": "$message",
    "environment": "${ENVIRONMENT:-production}",
    "app": "$APP_NAME"
}
EOF
)
        curl -s -X POST "$ALERT_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$payload" || log_warn "Failed to send webhook notification"
    fi

    # Send to Slack if configured
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        local color="good"
        [[ "$severity" == "warning" ]] && color="warning"
        [[ "$severity" == "critical" ]] && color="danger"

        local slack_payload=$(cat <<EOF
{
    "username": "Redis Failover Bot",
    "icon_emoji": ":warning:",
    "attachments": [
        {
            "color": "$color",
            "title": "$title",
            "text": "$message",
            "fields": [
                {
                    "title": "Service",
                    "value": "Redis",
                    "short": true
                },
                {
                    "title": "Environment",
                    "value": "${ENVIRONMENT:-production}",
                    "short": true
                },
                {
                    "title": "Timestamp",
                    "value": "$timestamp",
                    "short": false
                }
            ]
        }
    ]
}
EOF
)
        curl -s -X POST "$SLACK_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$slack_payload" || log_warn "Failed to send Slack notification"
    fi
}

# Execute Sentinel command
sentinel_cmd() {
    local host="$1"
    local port="$2"
    local cmd="$3"
    local timeout="${4:-10}"

    timeout "$timeout" redis-cli \
        -h "$host" \
        -p "$port" \
        -a "$SENTINEL_PASSWORD" \
        --no-auth-warning \
        $cmd 2>/dev/null
}

# Execute Redis command
redis_cmd() {
    local host="$1"
    local port="$2"
    local cmd="$3"
    local timeout="${4:-10}"

    timeout "$timeout" redis-cli \
        -h "$host" \
        -p "$port" \
        --user "$REDIS_USERNAME" \
        -a "$REDIS_PASSWORD" \
        --no-auth-warning \
        $cmd 2>/dev/null
}

# Get current master information from Sentinel
get_master_info() {
    local sentinel_host="$1"
    local sentinel_port="$2"

    sentinel_cmd "$sentinel_host" "$sentinel_port" "sentinel master $MASTER_NAME" | \
    awk 'BEGIN{RS="\n"; FS=""}
         /^name$/{getline; name=$0}
         /^ip$/{getline; ip=$0}
         /^port$/{getline; port=$0}
         /^flags$/{getline; flags=$0}
         END{print ip":"port":"flags":"name}'
}

# Check if Sentinel can reach master
check_sentinel_master() {
    local sentinel_host="$1"
    local sentinel_port="$2"

    local master_info=$(get_master_info "$sentinel_host" "$sentinel_port")
    if [[ -n "$master_info" ]]; then
        echo "$master_info"
        return 0
    else
        return 1
    fi
}

# Get all available Sentinels
get_available_sentinels() {
    local available_sentinels=()

    for sentinel in "$SENTINEL_1_HOST:$SENTINEL_1_PORT" "$SENTINEL_2_HOST:$SENTINEL_2_PORT" "$SENTINEL_3_HOST:$SENTINEL_3_PORT"; do
        local host=$(echo "$sentinel" | cut -d: -f1)
        local port=$(echo "$sentinel" | cut -d: -f2)

        if sentinel_cmd "$host" "$port" "ping" >/dev/null 2>&1; then
            available_sentinels+=("$sentinel")
        fi
    done

    echo "${available_sentinels[@]}"
}

# =======================
# FAILOVER FUNCTIONS
# =======================

# Force manual failover
force_failover() {
    log_critical "Initiating manual Redis failover for master: $MASTER_NAME"

    local available_sentinels=($(get_available_sentinels))
    if [[ ${#available_sentinels[@]} -eq 0 ]]; then
        log_error "No available Sentinels found! Cannot initiate failover."
        send_notification "critical" "Redis Failover Failed" "No available Sentinels found to initiate failover"
        return 1
    fi

    log_info "Available Sentinels: ${available_sentinels[*]}"

    # Use the first available Sentinel to initiate failover
    local primary_sentinel="${available_sentinels[0]}"
    local host=$(echo "$primary_sentinel" | cut -d: -f1)
    local port=$(echo "$primary_sentinel" | cut -d: -f2)

    log_info "Initiating failover using Sentinel $host:$port"

    # Get current master info before failover
    local old_master_info=$(get_master_info "$host" "$port")
    local old_master_ip=$(echo "$old_master_info" | cut -d: -f1)
    local old_master_port=$(echo "$old_master_info" | cut -d: -f2)

    log_info "Current master: $old_master_ip:$old_master_port"

    # Initiate failover
    if sentinel_cmd "$host" "$port" "sentinel failover $MASTER_NAME"; then
        log_success "Failover command sent successfully"
        send_notification "warning" "Redis Failover Initiated" "Manual failover initiated for master $old_master_ip:$old_master_port"
    else
        log_error "Failed to send failover command"
        send_notification "critical" "Redis Failover Command Failed" "Failed to send failover command to Sentinel"
        return 1
    fi

    # Wait for failover to complete
    log_info "Waiting for failover to complete (timeout: ${FAILOVER_TIMEOUT}s)"

    local attempt=0
    local max_attempts=$((FAILOVER_TIMEOUT / 5))

    while [[ $attempt -lt $max_attempts ]]; do
        sleep 5
        ((attempt++))

        # Check if we have a new master
        local new_master_info=$(get_master_info "$host" "$port")
        if [[ -n "$new_master_info" ]]; then
            local new_master_ip=$(echo "$new_master_info" | cut -d: -f1)
            local new_master_port=$(echo "$new_master_info" | cut -d: -f2)

            if [[ "$new_master_ip:$new_master_port" != "$old_master_ip:$old_master_port" ]]; then
                log_success "Failover completed! New master: $new_master_ip:$new_master_port"
                send_notification "info" "Redis Failover Completed" "New master is now $new_master_ip:$new_master_port"

                # Verify new master is working
                if redis_cmd "$new_master_ip" "$new_master_port" "ping" >/dev/null; then
                    log_success "New master is responding to ping"
                    return 0
                else
                    log_error "New master is not responding"
                    return 1
                fi
            fi
        fi

        log_info "Failover in progress... (attempt $attempt/$max_attempts)"
    done

    log_error "Failover timeout reached! Failover may have failed."
    send_notification "critical" "Redis Failover Timeout" "Failover did not complete within $FAILOVER_TIMEOUT seconds"
    return 1
}

# Check failover status
check_failover_status() {
    log_info "Checking Redis cluster failover status"

    local available_sentinels=($(get_available_sentinels))
    if [[ ${#available_sentinels[@]} -eq 0 ]]; then
        log_error "No available Sentinels found!"
        return 1
    fi

    echo -e "\n${PURPLE}=== Sentinel Status ===${NC}"

    for sentinel in "${available_sentinels[@]}"; do
        local host=$(echo "$sentinel" | cut -d: -f1)
        local port=$(echo "$sentinel" | cut -d: -f2)

        echo -e "\n${BLUE}Sentinel $host:$port${NC}"

        # Get master info
        local master_info=$(get_master_info "$host" "$port")
        if [[ -n "$master_info" ]]; then
            local master_ip=$(echo "$master_info" | cut -d: -f1)
            local master_port=$(echo "$master_info" | cut -d: -f2)
            local master_flags=$(echo "$master_info" | cut -d: -f3)

            echo "  Master: $master_ip:$master_port (flags: $master_flags)"

            # Test master connectivity
            if redis_cmd "$master_ip" "$master_port" "ping" >/dev/null; then
                echo -e "  Master Status: ${GREEN}ONLINE${NC}"
            else
                echo -e "  Master Status: ${RED}OFFLINE${NC}"
            fi

            # Get replica info
            local replicas=$(sentinel_cmd "$host" "$port" "sentinel slaves $MASTER_NAME" | grep -c "name" || echo "0")
            echo "  Replicas: $replicas"

            # Get other sentinels
            local other_sentinels=$(sentinel_cmd "$host" "$port" "sentinel sentinels $MASTER_NAME" | grep -c "name" || echo "0")
            echo "  Other Sentinels: $other_sentinels"
        else
            echo -e "  Status: ${RED}Cannot get master info${NC}"
        fi
    done

    echo -e "\n${PURPLE}=== Database Status ===${NC}"

    # Check database integrity across all instances
    local master_info=$(get_master_info "${available_sentinels[0]%:*}" "${available_sentinels[0]#*:}")
    if [[ -n "$master_info" ]]; then
        local master_ip=$(echo "$master_info" | cut -d: -f1)
        local master_port=$(echo "$master_info" | cut -d: -f2)

        for db in {0..5}; do
            local db_name=""
            case $db in
                0) db_name="Sessions" ;;
                1) db_name="User Preferences" ;;
                2) db_name="API Cache" ;;
                3) db_name="Rate Limiting" ;;
                4) db_name="Job Queue" ;;
                5) db_name="Analytics" ;;
            esac

            local key_count=$(redis_cmd "$master_ip" "$master_port" "eval \"return redis.call('dbsize')\" 0" 2>/dev/null || echo "0")
            echo "  DB$db ($db_name): $key_count keys"
        done
    fi

    return 0
}

# Restart application to reconnect to new master
restart_application() {
    log_info "Restarting application to reconnect to new Redis master"

    # Execute the restart command
    if eval "$APP_RESTART_COMMAND"; then
        log_success "Application restart command executed successfully"

        # Wait for application to be healthy
        sleep 30

        # Check if application can connect to Redis
        local health_check_url="${APP_HEALTH_CHECK_URL:-http://localhost:3000/api/health}"
        if curl -s "$health_check_url" | grep -q "healthy"; then
            log_success "Application is healthy and connected to Redis"
            send_notification "info" "Application Restarted" "Application successfully reconnected to new Redis master"
            return 0
        else
            log_error "Application health check failed after restart"
            send_notification "warning" "Application Health Check Failed" "Application restarted but health check is failing"
            return 1
        fi
    else
        log_error "Failed to restart application"
        send_notification "critical" "Application Restart Failed" "Failed to restart application after Redis failover"
        return 1
    fi
}

# Automated recovery procedure
auto_recovery() {
    log_info "Starting automated Redis recovery procedure"

    local recovery_attempts=0
    local recovery_successful=false

    while [[ $recovery_attempts -lt $MAX_RECOVERY_ATTEMPTS ]] && [[ "$recovery_successful" == "false" ]]; do
        ((recovery_attempts++))
        log_info "Recovery attempt $recovery_attempts/$MAX_RECOVERY_ATTEMPTS"

        # Check current cluster status
        local available_sentinels=($(get_available_sentinels))
        if [[ ${#available_sentinels[@]} -lt 2 ]]; then
            log_error "Insufficient Sentinels available (${#available_sentinels[@]}/3). Cannot proceed with recovery."
            send_notification "critical" "Redis Recovery Failed" "Insufficient Sentinels available for recovery"
            break
        fi

        # Get current master status
        local primary_sentinel="${available_sentinels[0]}"
        local host=$(echo "$primary_sentinel" | cut -d: -f1)
        local port=$(echo "$primary_sentinel" | cut -d: -f2)

        local master_info=$(get_master_info "$host" "$port")
        if [[ -n "$master_info" ]]; then
            local master_ip=$(echo "$master_info" | cut -d: -f1)
            local master_port=$(echo "$master_info" | cut -d: -f2)

            # Test master connectivity
            if redis_cmd "$master_ip" "$master_port" "ping" >/dev/null; then
                log_success "Redis master is responsive at $master_ip:$master_port"

                # Restart application to ensure fresh connections
                if restart_application; then
                    recovery_successful=true
                    log_success "Automated recovery completed successfully"
                    send_notification "info" "Redis Recovery Successful" "Automated recovery completed after $recovery_attempts attempts"
                    break
                fi
            else
                log_warn "Current master $master_ip:$master_port is not responsive. Initiating failover."

                # Force failover to a healthy replica
                if force_failover; then
                    log_success "Failover completed. Continuing recovery..."
                    # Continue to next iteration to verify new master
                else
                    log_error "Failover failed during recovery attempt $recovery_attempts"
                fi
            fi
        else
            log_error "Cannot get master information from Sentinel"
        fi

        if [[ "$recovery_successful" == "false" ]]; then
            log_info "Recovery attempt $recovery_attempts failed. Waiting ${RECOVERY_CHECK_INTERVAL}s before next attempt..."
            sleep $RECOVERY_CHECK_INTERVAL
        fi
    done

    if [[ "$recovery_successful" == "false" ]]; then
        log_critical "Automated recovery failed after $MAX_RECOVERY_ATTEMPTS attempts"
        send_notification "critical" "Redis Recovery Failed" "Automated recovery failed after $MAX_RECOVERY_ATTEMPTS attempts. Manual intervention required."
        return 1
    fi

    return 0
}

# =======================
# MONITORING FUNCTIONS
# =======================

# Continuous monitoring mode
start_monitoring() {
    log_info "Starting continuous Redis failover monitoring"

    local last_master_ip=""
    local last_master_port=""
    local failover_detected=false

    while true; do
        local available_sentinels=($(get_available_sentinels))

        if [[ ${#available_sentinels[@]} -eq 0 ]]; then
            log_error "No Sentinels available! Critical failure."
            send_notification "critical" "All Redis Sentinels Down" "No Redis Sentinels are responding"
            sleep 60
            continue
        fi

        # Get current master info
        local primary_sentinel="${available_sentinels[0]}"
        local host=$(echo "$primary_sentinel" | cut -d: -f1)
        local port=$(echo "$primary_sentinel" | cut -d: -f2)

        local master_info=$(get_master_info "$host" "$port")
        if [[ -n "$master_info" ]]; then
            local current_master_ip=$(echo "$master_info" | cut -d: -f1)
            local current_master_port=$(echo "$master_info" | cut -d: -f2)

            # Detect failover
            if [[ -n "$last_master_ip" ]] && [[ "$current_master_ip:$current_master_port" != "$last_master_ip:$last_master_port" ]]; then
                log_critical "FAILOVER DETECTED! Master changed from $last_master_ip:$last_master_port to $current_master_ip:$current_master_port"
                send_notification "critical" "Redis Failover Detected" "Master changed from $last_master_ip:$last_master_port to $current_master_ip:$current_master_port"

                failover_detected=true

                # Start automated recovery
                if auto_recovery; then
                    log_success "Automated recovery completed successfully"
                else
                    log_error "Automated recovery failed. Manual intervention may be required."
                fi

                failover_detected=false
            fi

            last_master_ip="$current_master_ip"
            last_master_port="$current_master_port"

            # Test master health
            if ! redis_cmd "$current_master_ip" "$current_master_port" "ping" >/dev/null; then
                log_error "Current master $current_master_ip:$current_master_port is not responding"
                send_notification "warning" "Redis Master Unresponsive" "Master $current_master_ip:$current_master_port is not responding to ping"
            fi
        else
            log_error "Cannot get master information from any Sentinel"
        fi

        sleep 30  # Check every 30 seconds
    done
}

# =======================
# MAIN FUNCTION
# =======================

main() {
    case "${1:-help}" in
        "status")
            check_failover_status
            ;;
        "failover")
            force_failover
            ;;
        "recover")
            auto_recovery
            ;;
        "restart-app")
            restart_application
            ;;
        "monitor")
            start_monitoring
            ;;
        "help"|*)
            echo "Meta Ads Intelligence Platform - Redis Failover Management"
            echo "Usage: $0 [command]"
            echo ""
            echo "Commands:"
            echo "  status      - Check current failover status and cluster health"
            echo "  failover    - Force manual failover to promote replica to master"
            echo "  recover     - Run automated recovery procedure"
            echo "  restart-app - Restart application to reconnect to Redis"
            echo "  monitor     - Start continuous monitoring for automatic failover handling"
            echo "  help        - Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  REDIS_PASSWORD           - Redis authentication password"
            echo "  SENTINEL_PASSWORD        - Sentinel authentication password"
            echo "  REDIS_ALERT_WEBHOOK      - Webhook URL for alerts"
            echo "  SLACK_WEBHOOK           - Slack webhook URL for notifications"
            echo "  APP_RESTART_COMMAND     - Command to restart application"
            echo "  APP_HEALTH_CHECK_URL    - Application health check URL"
            ;;
    esac
}

# =======================
# SCRIPT EXECUTION
# =======================

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Set up signal handlers for graceful shutdown
trap 'log_info "Failover script interrupted"; exit 130' INT TERM

# Execute main function with all arguments
main "$@"