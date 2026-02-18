"""
RedAmon Tool Registry

Single source of truth for tool metadata used by dynamic prompt builders.
Dict insertion order defines tool priority (first = highest).
"""

TOOL_REGISTRY = {
    "query_graph": {
        "purpose": "Neo4j database queries",
        "when_to_use": "PRIMARY - Check graph first for recon data",
        "args_format": '"question": "natural language question about the graph data"',
        "description": (
            '**query_graph** (PRIMARY - Preferred starting point)\n'
            '   - Query Neo4j graph database using natural language\n'
            '   - This is your PRIMARY source of truth for reconnaissance data\n'
            '   - **Contains:**\n'
            '     - **Assets:** Domains, Subdomains, IPs, Ports, Services, BaseURLs, DNSRecords\n'
            '     - **Web:** Endpoints, Parameters, Certificates, Headers\n'
            '     - **Intelligence:** Technologies, Vulnerabilities, CVEs, MitreData (CWE), CAPEC attack patterns\n'
            '     - **Network:** Traceroute hops\n'
            '     - **Exploits:** Exploit results (agent), ExploitGvm (scanner-confirmed)\n'
            '     - **GitHub Secrets:** GithubHunt, Repositories, Paths, Secrets (API keys, credentials), SensitiveFiles (.env, configs)\n'
            '   - Skip if you already know you need a specific tool (e.g., direct nmap scan, curl probe)\n'
            '   - Example: "Show all critical vulnerabilities for this project"\n'
            '   - Example: "What ports are open on 10.0.0.5?"\n'
            '   - Example: "What technologies are running on the target?"\n'
            '   - Example: "What GitHub secrets were found for this project?"\n'
            '   - Example: "Show all endpoints and parameters for target.com"'
        ),
    },
    "web_search": {
        "purpose": "Web search (Tavily)",
        "when_to_use": "Research CVEs, exploits, service vulns",
        "args_format": '"query": "search query for CVE details, exploit techniques, etc."',
        "description": (
            '**web_search** (SECONDARY - Research from the web)\n'
            '   - Search the internet for security research information via Tavily\n'
            '   - Use AFTER query_graph when you need external context not in the graph\n'
            '   - **USE FOR:** CVE details, exploit PoCs, version-specific vulnerabilities, attack techniques\n'
            '   - **USE FOR:** Metasploit module documentation, security advisories, vendor bulletins\n'
            '   - **DO NOT USE AS:** A replacement for query_graph (graph has project-specific recon data)\n'
            '   - Example args: "CVE-2021-41773 Apache path traversal exploit PoC"\n'
            '   - Example args: "Apache 2.4.49 known vulnerabilities"\n'
            '   - Example args: "Metasploit module for CVE-2021-44228 log4shell"'
        ),
    },
    "execute_curl": {
        "purpose": "HTTP requests & vuln probing",
        "when_to_use": "Reachability checks + vulnerability testing as FALLBACK",
        "args_format": '"args": "curl command arguments without \'curl\' prefix"',
        "description": (
            '**execute_curl** (Reachability + Vulnerability Probing Fallback)\n'
            '   - Make HTTP requests to targets\n'
            '   - **PRIMARY USE:** Basic reachability checks (status code, headers)\n'
            '   - **FALLBACK USE:** Vulnerability probing when query_graph returns NO vulnerability data for the target\n'
            '     - Path traversal (e.g., `/../../../etc/passwd`)\n'
            '     - LFI/RFI checks\n'
            '     - Header injection, SSRF, open redirect probing\n'
            '     - Version/banner fingerprinting for unidentified services\n'
            '   - **WORKFLOW:** Always query_graph FIRST. Only use curl for vuln probing if graph has no relevant findings.\n'
            '   - Example args: "-s -I http://target.com" (reachability check)\n'
            '   - Example args: "-s http://target.com" (verify service responds)\n'
            "   - Example args: \"-s -o /dev/null -w '%{{http_code}}' http://target.com/../../../../etc/passwd\" (path traversal probe)\n"
            '   - Example args: "-s http://target.com/..;/manager/html" (Tomcat bypass probe)'
        ),
    },
    "execute_naabu": {
        "purpose": "Port scanning",
        "when_to_use": "ONLY to verify ports or scan new targets",
        "args_format": '"args": "naabu arguments without \'naabu\' prefix"',
        "description": (
            '**execute_naabu** (Auxiliary - for verification)\n'
            '   - Fast port scanner for verification\n'
            '   - Use ONLY to verify ports are actually open or scan new targets not in graph\n'
            '   - Example args: "-host 10.0.0.5 -p 80,443,8080 -json"'
        ),
    },
    "execute_nmap": {
        "purpose": "Deep network scanning",
        "when_to_use": "Service detection, OS fingerprint, NSE scripts",
        "args_format": '"args": "nmap arguments without \'nmap\' prefix"',
        "description": (
            '**execute_nmap** (Deep scanning - service detection, OS fingerprint)\n'
            '   - Full nmap scanner for detailed service analysis\n'
            '   - Use when you need version detection (-sV), OS fingerprinting (-O), or NSE scripts (-sC)\n'
            '   - Slower than naabu but much more detailed\n'
            '   - Example args: "-sV -sC 10.0.0.5 -p 80,443"\n'
            '   - Example args: "-sV --script vuln 10.0.0.5"\n'
            '   - Example args: "-A 10.0.0.5 -p 22,80"'
        ),
    },
    "metasploit_console": {
        "purpose": "Exploit execution",
        "when_to_use": "Execute exploits, manage sessions",
        "args_format": '"command": "msfconsole command to execute"',
        "description": None,  # Uses METASPLOIT_CONSOLE_HEADER block instead
    },
}
