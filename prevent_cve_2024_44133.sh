#!/bin/bash

echo "Starting enhanced system-wide remediation for CVE-2024-44133 indicators..."

# Function to check for suspicious processes
check_processes() {
    echo "Checking for suspicious processes..."
    suspicious_processes=( "/private/tmp/p" )
    for process in "${suspicious_processes[@]}"; do
        if pgrep -f "$process" > /dev/null; then
            echo "Warning: Suspicious process $process detected. Killing it..."
            pkill -f "$process"
        fi
    done
}

# Function to secure Safari and other media configurations against modification
secure_media_configs() {
    user_home=$1
    media_config_dir="$user_home/Library/Preferences/com.apple.MediaToolbox.plist"
    safari_dir="$user_home/Library/Safari"
    echo "Securing Safari and MediaToolbox configurations for user at $user_home..."

    if [ -d "$safari_dir" ]; then
        chmod -R 600 "$safari_dir"  # Restrict access to Safari configuration files
        chflags uchg "$safari_dir"  # Lock the directory against changes
        echo "Safari configuration secured for $user_home."
    fi

    if [ -f "$media_config_dir" ]; then
        chmod 600 "$media_config_dir"  # Restrict access to MediaToolbox config file
        chflags uchg "$media_config_dir"  # Lock file to prevent unauthorized modifications
        echo "MediaToolbox configuration secured for $user_home."
    else
        echo "No MediaToolbox configuration found for $user_home. Skipping."
    fi
}

# Function to check media and streaming filter settings
monitor_media_filters() {
    echo "Checking and enforcing secure media and streaming filter settings..."
    media_filter_values=("AllowedCPC" "MediaValidation" "SupportedAudioFormat")

    # For each filter, enforce expected values or log any unauthorized changes
    for filter in "${media_filter_values[@]}"; do
        filter_output=$(defaults read com.apple.MediaToolbox "$filter" 2>/dev/null)

        case $filter in
            "AllowedCPC")
                # Expected setting for AllowedCPC
                expected_value="0x3"
                if [[ "$filter_output" != "$expected_value" ]]; then
                    echo "Warning: AllowedCPC filter has been modified. Resetting to default..."
                    defaults write com.apple.MediaToolbox "$filter" "$expected_value"
                fi
                ;;
            "MediaValidation")
                # Expected setting for MediaValidation (no unknown codecs allowed)
                expected_value="NO"
                if [[ "$filter_output" != "$expected_value" ]]; then
                    echo "Warning: MediaValidation filter has been modified. Resetting to default..."
                    defaults write com.apple.MediaToolbox "$filter" "$expected_value"
                fi
                ;;
            "SupportedAudioFormat")
                # Expected setting to disallow passthrough for unsupported formats
                expected_values=("ac3IsDecodable:YES" "ec3IsDecodable:YES" "atmosIsDecodable:NO" "ac3CanPassthrough:NO" "ec3CanPassthrough:NO" "atmosCanPassthrough:NO")
                for value in "${expected_values[@]}"; do
                    if [[ "$filter_output" != *"$value"* ]]; then
                        echo "Warning: SupportedAudioFormat filter has been modified. Resetting to defaults..."
                        defaults write com.apple.MediaToolbox "$filter" -array "${expected_values[@]}"
                        break
                    fi
                done
                ;;
        esac
    done
}

# Function to detect and log DSCL command misuse
monitor_dscl_usage() {
    echo "Checking for recent DSCL commands that could indicate TCC bypass attempts..."
    dscl_logs=$(log show --predicate 'eventMessage contains "dscl"' --info --last 24h)
    if [[ $dscl_logs == *"dscl"* ]]; then
        echo "Warning: DSCL command detected. Inspect the following log entries for potential TCC bypass attempts:"
        echo "$dscl_logs"
    fi
}

# Function to remove suspicious files in /tmp and set alerts for Adload behavior
check_tmp_files() {
    echo "Checking for unexpected files in /tmp..."
    if [ -f "/tmp/GmaNi4v50ekNZSI" ]; then
        echo "Warning: Unexpected file detected in /tmp. Deleting it..."
        rm -f "/tmp/GmaNi4v50ekNZSI"
    fi
}

# Set restrictive permissions on key system binaries (system-wide)
secure_system_binaries() {
    echo "Setting restrictive permissions on system binaries and directories..."
    chmod 755 /usr/bin/id
    chmod 755 /usr/bin/sw_vers
    echo "Skipping osascript modification due to SIP restrictions."
}

# Function to detect base64 decoding or unauthorized scripting attempts by Adload-like patterns
monitor_adload_patterns() {
    echo "Monitoring system logs for base64 decoding and scripting abuse patterns..."
    log show --predicate '(eventMessage contains "base64") || (eventMessage contains "osascript")' --info --last 24h > /tmp/adload_patterns.log
    if [[ -s /tmp/adload_patterns.log ]]; then
        echo "Warning: Potential Adload behavior detected. Review the log at /tmp/adload_patterns.log for suspicious patterns."
    fi
}

# Main function to loop over each user and apply checks
main() {
    # Get list of all home directories in /Users (excluding system accounts)
    for user_home in /Users/*; do
        if [ -d "$user_home" ] && [ "$user_home" != "/Users/Shared" ]; then
            echo "Scanning for user: $(basename "$user_home")"
            secure_media_configs "$user_home"
        fi
    done
    
    # Check media filters, processes, DSCL usage, /tmp files, and Adload patterns system-wide
    monitor_media_filters
    check_processes
    monitor_dscl_usage
    check_tmp_files
    secure_system_binaries
    monitor_adload_patterns

    echo "Enhanced system-wide scan and remediation complete."
}

# Run the main function
main
