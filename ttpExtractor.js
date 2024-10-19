const predefinedStatements = {
"Credential Dumping": `
    T1003 – Credential Dumping
        a. Procedure: Attackers attempt to dump credentials from memory, registry, or system files to gain access to user accounts.
        b. Detection:
            i. Monitor processes accessing LSASS (Local Security Authority Subsystem Service).
            ii. Log PowerShell commands for suspicious behavior.
        c. Mitigation:
            i. Implement Credential Guard on Windows to prevent LSASS access.
            ii. Enforce the use of multi-factor authentication (MFA) to limit the use of stolen credentials.
`,
"Command and Scripting Interpreter": `
    T1059 – Command and Scripting Interpreter
        a. Procedure: Attackers use command-line interfaces or scripting environments to execute code and automate tasks.
        b. Detection:
            i. Monitor command-line execution logs (e.g., bash, PowerShell, cmd.exe).
            ii. Analyze command usage patterns for unusual scripts or commands.
        c. Mitigation:
            i. Limit script execution privileges to authorized users.
            ii. Enforce code-signing policies to ensure that only trusted scripts are executed.
`,
"Valid Accounts": `
    T1078 – Valid Accounts
        a. Procedure: Attackers use legitimate user credentials to access systems and move laterally within the network.
        b. Detection:
            i. Monitor account activity for unusual login patterns or access to resources.
            ii. Correlate access attempts with known compromise indicators.
        c. Mitigation:
            i. Enforce strong, complex password policies.
            ii. Implement MFA to reduce the impact of stolen credentials.
`,
"Exploit Public-Facing Application": `
    T1190 – Exploit Public-Facing Application
        a. Procedure: Attackers exploit vulnerabilities in public-facing applications to gain unauthorized access to systems.
        b. Detection:
            i. Monitor application logs for unusual or suspicious requests.
            ii. Use web application firewalls (WAF) to detect exploitation attempts.
        c. Mitigation:
            i. Regularly update and patch public-facing software.
            ii. Conduct regular vulnerability assessments and penetration testing.
`,
"Phishing": `
    T1566 – Phishing
        a. Procedure: Attackers send deceptive emails or messages to lure users into clicking malicious links or downloading attachments.
        b. Detection:
            i. Monitor email traffic for malicious attachments or URLs.
            ii. Log and analyze user click events on email links.
        c. Mitigation:
            i. Deploy email filtering solutions to block malicious content.
            ii. Conduct regular phishing awareness training for employees.
`,
"Process Injection": `
    T1055 – Process Injection
        a. Procedure: Attackers inject malicious code into legitimate processes to avoid detection or escalate privileges.
        b. Detection:
            i. Monitor for unusual memory allocation in processes.
            ii. Track API calls related to process injection techniques (e.g., WriteProcessMemory).
        c. Mitigation:
            i. Use endpoint detection and response (EDR) tools to identify injection activity.
            ii. Enable security features like DEP (Data Execution Prevention) and ASLR (Address Space Layout Randomization).
`,
"Remote Services": `
    T1021 – Remote Services
        a. Procedure: Attackers use remote desktop or SSH to access systems over the network.
        b. Detection:
            i. Monitor login attempts on remote services.
            ii. Correlate remote access with abnormal user activity.
        c. Mitigation:
            i. Limit remote service access through firewalls and access control lists (ACLs).
            ii. Enforce MFA on remote services.
`,
"Scheduled Task/Job": `
    T1053 – Scheduled Task/Job
        a. Procedure: Attackers schedule tasks on the system to execute malicious commands at a later time.
        b. Detection:
            i. Monitor task scheduler logs for unusual jobs or tasks.
            ii. Correlate scheduled task execution with system changes or access anomalies.
        c. Mitigation:
            i. Limit access to task scheduling to authorized users.
            ii. Regularly review scheduled tasks on critical systems.
`,
"Indicator Removal on Host": `
    T1070 – Indicator Removal on Host
        a. Procedure: Attackers delete logs, disable logging, or remove artifacts to avoid detection.
        b. Detection:
            i. Monitor for tampering of log files or changes in logging configuration.
            ii. Use tools that can detect anomalies in event logs or logging mechanisms.
        c. Mitigation:
            i. Enforce centralized logging where logs are sent to a remote server.
            ii. Use immutable logging systems that cannot be easily altered by adversaries.
`,
"PowerShell": `
    T1059.001 – PowerShell (Sub-Technique of Command and Scripting Interpreter)
        a. Procedure: Attackers use PowerShell for script execution and system automation, often to avoid detection.
        b. Detection:
            i. Enable logging of PowerShell script execution and monitor for suspicious activity.
            ii. Monitor PowerShell usage with behavioral analytics for unusual script patterns.
        c. Mitigation:
            i. Use constrained language mode in PowerShell to restrict functionality.
            ii. Disable unnecessary PowerShell capabilities on critical systems.
`,
"System Network Connections Discovery": `
    T1049 – System Network Connections Discovery
        a. Procedure: Attackers discover network connections and resources on the compromised system.
        b. Detection:
            i. Monitor network scanning activities or commands used to discover network configurations (e.g., netstat, ipconfig).
        c. Mitigation:
            i. Limit network discovery privileges to authorized users only.
            ii. Implement network segmentation and firewall rules to limit unnecessary communication between systems.
`,
"Exploitation of Remote Services": `
    T1210 – Exploitation of Remote Services
        a. Procedure: Attackers exploit vulnerabilities in remote services like SMB, RDP, or SSH to gain access to target systems.
        b. Detection:
            i. Monitor for exploitation attempts on remote services, including abnormal traffic patterns or login failures.
        c. Mitigation:
            i. Regularly update and patch remote services.
            ii. Restrict access to remote services through ACLs or firewalls.
`,
"Initial Access Techniques": `
    1. T1190 – Exploit Public-Facing Application
        a. Procedure: Exploiting vulnerabilities in publicly accessible applications.
        b. Detection:
            i. Monitor for unusual HTTP requests and application logs.
        c. Mitigation:
            i. Regularly apply patches and updates.
            ii. Use Web Application Firewalls (WAFs).
    2. T1078 – Valid Accounts
        a. Procedure: Use stolen or valid accounts for initial access or lateral movement.
        b. Detection:
            i. Monitor unusual login patterns and account usage.
        c. Mitigation:
            i. Enforce multi-factor authentication (MFA).
            ii. Audit and rotate credentials frequently.
`,
"Execution Techniques": `
    1. T1059 – Command and Scripting Interpreter
        a. Procedure: Execute commands or scripts through interpreters such as bash, PowerShell, etc.
        b. Detection:
            i. Monitor command-line interface (CLI) activity.
            ii. Analyze scripting usage patterns.
        c. Mitigation:
            i. Restrict script execution privileges.
            ii. Enforce code signing for script execution.
    2. T1203 – Exploitation for Client Execution
        a. Procedure: Exploiting software vulnerabilities on a client machine to execute arbitrary code.
        b. Detection:
            i. Monitor for abnormal crashes or application behavior.
        c. Mitigation:
            i. Regularly patch software and update applications.
            ii. Use exploit mitigation controls (e.g., DEP, ASLR).
`,
"Persistence Techniques": `
    1. T1053 – Scheduled Task/Job
        a. Procedure: Create tasks that execute code at a specified time.
        b. Detection:
            i. Monitor task creation logs and scheduled job execution.
        c. Mitigation:
            i. Limit task scheduling privileges to authorized users.
            ii. Review scheduled tasks regularly.
    2. T1547 – Boot or Logon Autostart Execution
        a. Procedure: Automatically execute code upon system startup or user login.
        b. Detection:
            i. Monitor registry changes and startup scripts.
        c. Mitigation:
            i. Limit modification rights to autostart settings.
            ii. Use application whitelisting to prevent unauthorized startup.
`,
"Privilege Escalation Techniques": `
    1. T1068 – Exploitation for Privilege Escalation
        a. Procedure: Exploiting vulnerabilities in operating systems or applications to gain elevated privileges.
        b. Detection:
            i. Monitor for abnormal process creation or execution flows.
        c. Mitigation:
            i. Regularly patch vulnerable software and apply security controls like sandboxes.
    2. T1078 – Valid Accounts
        a. Procedure: Using compromised accounts with higher privileges to move laterally or escalate privileges.
        b. Detection:
            i. Correlate account activity with normal user behavior.
        c. Mitigation:
            i. Enforce least-privilege principles for accounts.
`,
"Defense Evasion Techniques": `
    1. T1070 – Indicator Removal on Host
        a. Procedure: Tampering with logs or security tools to evade detection.
        b. Detection:
            i. Monitor for disabled logging or event log deletions.
        c. Mitigation:
            i. Enable centralized logging and protect log integrity.
    2. T1027 – Obfuscated Files or Information
        a. Procedure: Using encoding or encryption to hide malicious code.
        b. Detection:
            i. Monitor file signatures and hash mismatches.
        c. Mitigation:
            i. Employ antivirus/EDR tools to detect obfuscated code.
`,
"Credential Access Techniques": `
    1. T1003 – Credential Dumping
        a. Procedure: Accessing credentials stored in system memory or files.
        b. Detection:
            i. Monitor for unauthorized access to LSASS or sensitive files.
        c. Mitigation:
            i. Enable Credential Guard (Windows) and restrict access to sensitive processes.
    2. T1110 – Brute Force
        a. Procedure: Systematically attempting to guess passwords or use default credentials.
        b. Detection:
            i. Monitor for multiple failed login attempts.
        c. Mitigation:
            i. Enforce account lockout policies and MFA.
`,
"Discovery Techniques": `
    1. T1083 – File and Directory Discovery
        a. Procedure: Accessing directories and files to gather information about the system or network.
        b. Detection:
            i. Monitor file access patterns for unauthorized users.
        c. Mitigation:
            i. Enforce least-privilege access to sensitive directories.
    2. T1082 – System Information Discovery
        a. Procedure: Gathering system details (OS version, hardware info, etc.) for further exploitation.
        b. Detection:
            i. Monitor for commands that gather system information (systeminfo, hostname, etc.).
        c. Mitigation:
            i. Limit access to system configuration commands.
`,
"Lateral Movement Techniques": `
    1. T1021 – Remote Services
        a. Procedure: Use of RDP, SSH, or other remote services to move laterally in a network.
        b. Detection:
            i. Monitor remote service usage and abnormal authentication patterns.
        c. Mitigation:
            i. Enforce MFA and restrict access to remote services.
    2. T1072 – Software Deployment Tools
        a. Procedure: Leveraging system management software to deploy malicious code across multiple systems.
        b. Detection:
            i. Monitor deployment tool usage and audit scripts.
        c. Mitigation:
            i. Limit access to deployment tools and restrict software execution.
`,
"Collection Techniques": `
    1. T1005 – Data from Local System
        a. Procedure: Accessing files on a local system to collect sensitive information.
        b. Detection:
            i. Monitor file read/write operations.
        c. Mitigation:
            i. Restrict access to sensitive files and use DLP (Data Loss Prevention) solutions.
    2. T1114 – Email Collection
        a. Procedure: Gathering email communications from compromised accounts.
        b. Detection:
            i. Monitor email client access and export functions.
        c. Mitigation:
            i. Encrypt email communications and enforce strong access controls.
`,
"Command and Control Techniques": `
    1. T1071 – Application Layer Protocol
        a. Procedure: Using HTTP/S, DNS, or other protocols to communicate with a command and control server.
        b. Detection:
            i. Monitor network traffic for abnormal protocols or connections.
        c. Mitigation:
            i. Implement network segmentation and use firewalls to block known malicious traffic.
    2. T1090 – Proxy
        a. Procedure: Using proxies to obfuscate the origin of C2 traffic.
        b. Detection:
            i. Monitor proxy usage and analyze traffic for unusual destinations.
        c. Mitigation:
            i. Block known proxy servers and enforce strict network traffic policies.
`,
"Command and Control": `
    1. T1071 – Application Layer Protocol
        a. Procedure: Using HTTP/S, DNS, or other protocols to communicate with a command and control server.
        b. Detection:
            i. Monitor network traffic for abnormal protocols or connections.
        c. Mitigation:
            i. Implement network segmentation and use firewalls to block known malicious traffic.
    2. T1090 – Proxy
        a. Procedure: Using proxies to obfuscate the origin of C2 traffic.
        b. Detection:
            i. Monitor proxy usage and analyze traffic for unusual destinations.
        c. Mitigation:
            i. Block known proxy servers and enforce strict network traffic policies.
`,
"Exfiltration Techniques": `
    1. T1041 – Exfiltration Over C2 Channel
        a. Procedure: Using the command and control channel to exfiltrate data from the network.
        b. Detection:
            i. Monitor outgoing network traffic for data exfiltration patterns.
        c. Mitigation:
            i. Use data loss prevention (DLP) systems to block unauthorized data transfers.
    2. T1052 – Exfiltration Over Physical Medium
        a. Procedure: Transferring data via USB or other physical media.
        b. Detection:
            i. Monitor for the use of removable media devices on sensitive systems.
        c. Mitigation:
            i. Restrict the use of removable media and enable logging for USB devices.
`
 
    // Add more predefined statements as needed
};

const extractTTPs = async (content) => {
    if (!content) throw new Error('No content provided');
    console.log('Processing content...'); // Debug statement
    const ttpSummary = [];
    for (const [keyword, statement] of Object.entries(predefinedStatements)) {
        const regex = new RegExp(`\\b${keyword}\\b`, 'i');
        if (regex.test(content)) {
            ttpSummary.push(`
            ${statement}
            `);
        }
    }
    if (ttpSummary.length === 0) {
        return 'No TTPs found in the document.';
    }
    return ttpSummary.join('\n');
};

module.exports = { extractTTPs };
