#!/bin/bash

echo "Starting system-wide scan and remediation for CVE-2024-44133 indicators..."

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

# Function to check and reset Chrome preferences for each user
check_chrome_prefs() {
    user_home=$1
    chrome_prefs="$user_home/Library/Application Support/Google/Chrome/Default/Preferences"
    echo "Checking Chrome preferences for user at $user_home..."
    if [ -f "$chrome_prefs" ]; then
        if grep -q "Unexpected" "$chrome_prefs"; then
            echo "Warning: Unauthorized changes detected in Chrome preferences at $chrome_prefs. Restoring permissions..."
            chmod 644 "$chrome_prefs"
        fi
    fi
}

# Function to set permissions and remove suspicious directories
secure_directories() {
    user_home=$1
    vulnerable_dir="$user_home/Library/Application Support/.17066225541972342347"
    echo "Setting permissions for vulnerable directories for user at $user_home..."
    if [ -d "$vulnerable_dir" ]; then
        chmod -R 700 "$vulnerable_dir"
    else
        echo "Directory $vulnerable_dir not found for user at $user_home. Skipping."
    fi
}

# Function to remove suspicious services
remove_suspicious_services() {
    user_home=$1
    suspicious_services=("com.BasicIndex.service")
    echo "Checking for suspicious services for user at $user_home..."
    for service in "${suspicious_services[@]}"; do
        service_path="$user_home/Library/Application Support/.17066225541972342347/Services/$service"
        if [ -f "$service_path" ]; then
            echo "Warning: Suspicious service $service detected at $service_path. Deleting..."
            rm -rf "$service_path"
        else
            echo "Service $service not found for user at $user_home. Skipping."
        fi
    done
}

# Function to check for unexpected files in /tmp
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

# Main function to loop over each user and apply checks
main() {
    # Get list of all home directories in /Users (excluding system accounts)
    for user_home in /Users/*; do
        if [ -d "$user_home" ] && [ "$user_home" != "/Users/Shared" ]; then
            echo "Scanning for user: $(basename "$user_home")"
            check_chrome_prefs "$user_home"
            secure_directories "$user_home"
            remove_suspicious_services "$user_home"
        fi
    done
    
    # Check for processes and /tmp files system-wide
    check_processes
    check_tmp_files
    secure_system_binaries

    echo "System-wide scan and remediation complete."
}

# Run the main function
main