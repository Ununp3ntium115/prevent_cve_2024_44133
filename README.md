# prevent_cve_2024_44133

prevent_cve_2024_44133

Because Apple has been slow.... this script should thwart CVE-2024-44133

Start with "sudo nano /usr/local/bin/cve_2024_44133_remediation.sh" Copy the code and save >

Then "sudo chmod +x /usr/local/bin/cve_2024_44133_remediation.sh"

and "sudo nano /Library/LaunchDaemons/com.company.security_remediation.plist"

Then run the launchd process "sudo launchctl load /Library/LaunchDaemons/com.company.security_remediation.plist"
