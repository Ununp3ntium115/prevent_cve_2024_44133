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

# Function to secure Safari critical files against modification
secure_safari_files() {
    user_home=$1
    safari_dir="$user_home/Library/Safari"
    echo "Securing Safari critical files for user at $user_home..."

    if [ -d "$safari_dir" ]; then
        # Files of interest
        critical_files=("PerSitePreferences.db" "UserMediaPermissions.plist")
        for file in "${critical_files[@]}"; do
            file_path="$safari_dir/$file"
            if [ -f "$file_path" ]; then
                chmod 600 "$file_path"  # Restrict access to the file
                chflags uchg "$file_path"  # Lock the file against changes
                echo "Secured $file_path."
            else
                echo "$file_path not found for $user_home. Skipping."
            fi
        done
    else
        echo "No Safari configuration found for $user_home. Skipping."
    fi
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

# Function to monitor and reset Chrome preferences for each user
monitor_chrome_prefs() {
    user_home=$1
    chrome_prefs="$user_home/Library/Application Support/Google/Chrome/Default/Preferences"
    echo "Monitoring Chrome preferences for user at $user_home..."
    if [ -f "$chrome_prefs" ]; then
        if grep -q "Unexpected" "$chrome_prefs"; then
            echo "Warning: Unauthorized changes detected in Chrome preferences at $chrome_prefs. Restoring permissions..."
            chmod 644 "$chrome_prefs"
        fi
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
            secure_safari_files "$user_home"
            monitor_chrome_prefs "$user_home"
        fi
    done
    
    # Check for processes, DSCL usage, /tmp files, and Adload patterns system-wide
    check_processes
    monitor_dscl_usage
    check_tmp_files
    secure_system_binaries
    monitor_adload_patterns

    echo "Enhanced system-wide scan and remediation complete."
}

# Run the main function
main
