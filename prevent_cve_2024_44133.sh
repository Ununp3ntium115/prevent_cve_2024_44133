#!/bin/bash

# =============================================================================
# Enhanced System-wide Remediation Script for CVE-2024-44133 Indicators
# =============================================================================
# This script performs system-wide checks and remediations to mitigate the
# effects of CVE-2024-44133. It includes enhanced logging, dynamic user
# detection, SIP awareness, and other improvements to make it future-proof
# and adaptable to new threats.
# =============================================================================

# Exit immediately if a command exits with a non-zero status, and treat unset variables as an error.
set -euo pipefail

# Variables
LOG_FILE="/var/log/cve_2024_44133_remediation.log"
SIP_ENABLED=$(csrutil status | grep -q 'enabled' && echo "yes" || echo "no")

# Configuration Parameters
ADMIN_EMAIL="admin@company.com"
ALLOWED_CPC_VALUE="0x3"
MEDIA_VALIDATION_VALUE="NO"
SUPPORTED_AUDIO_FORMAT_VALUES=("ac3IsDecodable:YES" "ec3IsDecodable:YES" "atmosIsDecodable:NO" "ac3CanPassthrough:NO" "ec3CanPassthrough:NO" "atmosCanPassthrough:NO")

# Function to log actions
log_action() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to notify users
notify_user() {
    local message="$1"
    osascript -e "display notification \"$message\" with title \"Security Alert\"" 2>/dev/null || true
}

# Function to check for suspicious processes
check_processes() {
    log_action "Checking for suspicious processes..."
    # Use regex to match process names
    if pgrep -f "/private/tmp/p" > /dev/null; then
        log_action "Suspicious process '/private/tmp/p' detected. Killing it..."
        pkill -f "/private/tmp/p"
        notify_user "Suspicious process '/private/tmp/p' was detected and terminated."
    fi
    # Add more patterns as needed
}

# Function to secure Safari and MediaToolbox configurations
secure_media_configs() {
    local user_home=$1
    local media_config_file="$user_home/Library/Preferences/com.apple.MediaToolbox.plist"
    local safari_dir="$user_home/Library/Safari"

    log_action "Securing Safari and MediaToolbox configurations for user at $user_home..."

    if [ -d "$safari_dir" ]; then
        chmod -R 600 "$safari_dir"  # Restrict access to Safari configuration files
        chflags -R uchg "$safari_dir"  # Lock the directory against changes
        log_action "Safari configuration secured for $user_home."
    fi

    if [ -f "$media_config_file" ]; then
        chmod 600 "$media_config_file"  # Restrict access to MediaToolbox config file
        chflags uchg "$media_config_file"  # Lock file to prevent unauthorized modifications
        log_action "MediaToolbox configuration secured for $user_home."
    else
        log_action "No MediaToolbox configuration found for $user_home. Skipping."
    fi
}

# Function to check and enforce media filter settings
monitor_media_filters() {
    log_action "Checking and enforcing secure media and streaming filter settings..."

    # Function to check and fix a configuration key
    check_and_fix_config() {
        local domain="$1"
        local key="$2"
        local expected_value="$3"

        local current_value
        current_value=$(/usr/bin/defaults read "$domain" "$key" 2>/dev/null || echo "undefined")

        if [[ "$current_value" != "$expected_value" ]]; then
            log_action "Warning: $key in $domain is '$current_value'. Resetting to '$expected_value'..."
            /usr/bin/defaults write "$domain" "$key" "$expected_value"
            log_action "$key in $domain reset to '$expected_value'."
        fi
    }

    # Check and fix configurations
    check_and_fix_config "com.apple.MediaToolbox" "AllowedCPC" "$ALLOWED_CPC_VALUE"
    check_and_fix_config "com.apple.MediaToolbox" "MediaValidation" "$MEDIA_VALIDATION_VALUE"

    # Handle SupportedAudioFormat separately due to its array structure
    local current_values
    current_values=$(/usr/bin/defaults read com.apple.MediaToolbox SupportedAudioFormat 2>/dev/null || echo "undefined")
    local expected_values="${SUPPORTED_AUDIO_FORMAT_VALUES[*]}"

    if [[ "$current_values" != *"$expected_values"* ]]; then
        log_action "Warning: SupportedAudioFormat has been modified. Resetting to defaults..."
        /usr/bin/defaults write com.apple.MediaToolbox SupportedAudioFormat -array "${SUPPORTED_AUDIO_FORMAT_VALUES[@]}"
        log_action "SupportedAudioFormat reset to secure values."
    fi
}

# Function to detect and log DSCL command misuse
monitor_dscl_usage() {
    log_action "Checking for recent DSCL commands that could indicate TCC bypass attempts..."
    if ! dscl_logs=$(log show --predicate 'eventMessage contains "dscl"' --info --last 24h 2>/dev/null); then
        log_action "Error: Failed to retrieve DSCL logs."
    else
        if [[ $dscl_logs == *"dscl"* ]]; then
            log_action "Warning: DSCL command detected. Inspect the following log entries for potential TCC bypass attempts:"
            echo "$dscl_logs" >> "$LOG_FILE"
            notify_user "Suspicious DSCL command activity detected. Review logs for potential TCC bypass."
        fi
    fi
}

# Function to check and remove suspicious files in /tmp
check_tmp_files() {
    log_action "Checking for unexpected files in /tmp..."
    # Use find with extended regex patterns compatible with BSD find
    find -E /tmp -type f -regex "/tmp/(GmaNi[0-9a-zA-Z]+|unknown_.*\.sh)" | while read -r file; do
        log_action "Warning: Suspicious file $file detected. Deleting it..."
        rm -f "$file"
        notify_user "Suspicious file $file detected and removed from /tmp."
    done
}

# Function to set restrictive permissions on key system binaries
secure_system_binaries() {
    log_action "Setting restrictive permissions on system binaries and directories..."
    /bin/chmod 755 /usr/bin/id
    /bin/chmod 755 /usr/bin/sw_vers
    if [[ "$SIP_ENABLED" == "no" ]]; then
        /bin/chmod 755 /usr/bin/osascript
        log_action "osascript permissions modified."
    else
        log_action "Skipping osascript modification due to SIP restrictions."
    fi
}

# Function to detect base64 decoding or unauthorized scripting attempts
monitor_adload_patterns() {
    log_action "Monitoring system logs for base64 decoding and scripting abuse patterns..."
    /usr/bin/log show --predicate '(eventMessage contains "base64") || (eventMessage contains "osascript")' --info --last 24h > /tmp/adload_patterns.log
    if [[ -s /tmp/adload_patterns.log ]]; then
        log_action "Warning: Potential Adload behavior detected. Review the log at /tmp/adload_patterns.log for suspicious patterns."
        notify_user "Suspicious Adload behavior detected. See /tmp/adload_patterns.log for details."
    fi
}

# Function to send alert notifications if any remediation actions were taken
send_alert() {
    if [[ -f /tmp/adload_patterns.log && -s /tmp/adload_patterns.log ]]; then
        echo "Alert: Adload patterns detected and logged." | /usr/bin/mail -s "Alert: Adload Pattern Detected" "$ADMIN_EMAIL"
        log_action "Alert email sent to $ADMIN_EMAIL."
    fi
}

# Main function to loop over each user and apply checks
main() {
    log_action "Starting enhanced system-wide remediation for CVE-2024-44133 indicators..."

    # Get list of all non-system user home directories
    for user_home in /Users/*; do
        username=$(basename "$user_home")
        if id -u "$username" &>/dev/null && [[ "$username" != "Shared" ]]; then
            log_action "Scanning for user: $username"
            secure_media_configs "$user_home"
        fi
    done

    # Perform system-wide checks
    monitor_media_filters
    check_processes
    monitor_dscl_usage
    check_tmp_files
    secure_system_binaries
    monitor_adload_patterns
    send_alert

    log_action "Enhanced system-wide scan and remediation complete."
}

# Run the main function
main
