"""
Network Recon MCP Server - HTTP Client & Port Scanner

Exposes curl HTTP client and naabu port scanner as MCP tools
for agentic penetration testing.

Tools:
    - execute_curl: Execute curl with any CLI arguments
    - execute_naabu: Execute naabu with any CLI arguments
"""

from fastmcp import FastMCP
import subprocess
import shlex
import re
import os

# Strip ANSI escape codes (terminal colors) from output
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

# Server configuration
SERVER_NAME = "network_recon"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("NETWORK_RECON_PORT", "8000"))

mcp = FastMCP(SERVER_NAME)


@mcp.tool()
def execute_curl(args: str) -> str:
    """
    Execute curl HTTP client with any valid CLI arguments.

    Curl is a command-line tool for transferring data with URLs. It supports
    HTTP, HTTPS, FTP, and many other protocols. Useful for HTTP enumeration,
    API testing, and exploiting web vulnerabilities.

    Args:
        args: Command-line arguments for curl (without the 'curl' command itself)

    Returns:
        Command output (stdout + stderr combined)

    Examples:
        Basic GET request with headers:
        - "-s -i http://10.0.0.5/"

        POST request with JSON:
        - "-s -X POST -H 'Content-Type: application/json' -d '{\"user\":\"admin\",\"pass\":\"admin\"}' http://10.0.0.5/api/login"

        HEAD request (headers only):
        - "-s -I http://10.0.0.5/"

        Custom User-Agent:
        - "-s -i -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)' http://10.0.0.5/"

        Follow redirects:
        - "-s -i -L http://10.0.0.5/"

        HTTPS with insecure (skip cert verification):
        - "-s -k https://10.0.0.5/"

        Get only HTTP status code:
        - "-s -o /dev/null -w '%{http_code}' http://10.0.0.5/"

        Send cookie:
        - "-s -i -b 'session=abc123' http://10.0.0.5/admin"

        Upload file:
        - "-s -X POST -F 'file=@/path/to/file.txt' http://10.0.0.5/upload"

        Basic authentication:
        - "-s -i -u admin:password http://10.0.0.5/admin"

        Custom timeout:
        - "-s -i --connect-timeout 10 --max-time 30 http://10.0.0.5/"

        Path traversal test:
        - "-s -i 'http://10.0.0.5/../../../../etc/passwd'"

        LFI test:
        - "-s -i 'http://10.0.0.5/index.php?page=../../../etc/passwd'"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["curl"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=60
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR]: {result.stderr}"
        return output if output.strip() else "[INFO] No response received"
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 60 seconds. Consider using --connect-timeout and --max-time flags."
    except FileNotFoundError:
        return "[ERROR] curl not found. Ensure it is installed and in PATH."
    except Exception as e:
        return f"[ERROR] {str(e)}"


@mcp.tool()
def execute_naabu(args: str) -> str:
    """
    Execute naabu port scanner with any valid CLI arguments.

    Naabu is a fast port scanner written in Go that allows you to enumerate
    valid ports for hosts in a fast and reliable manner. It can also integrate
    with nmap for service detection using the -nmap-cli flag.

    Args:
        args: Command-line arguments for naabu (without the 'naabu' command itself)

    Returns:
        Command output (stdout + stderr combined)

    Examples:
        Basic port scan:
        - "-host 10.0.0.5 -p 1-1000 -json"

        Scan with top ports:
        - "-host 192.168.1.0/24 -top-ports 100 -json"

        Scan from file:
        - "-list targets.txt -p 22,80,443,8080 -json"

        With nmap service detection:
        - "-host 10.0.0.5 -p 80,443 -nmap-cli 'nmap -sV -sC'"

        Fast scan with high rate:
        - "-host 10.0.0.5 -p 1-65535 -rate 5000 -json"

        Scan specific ports:
        - "-host 10.0.0.5 -p 21,22,23,25,53,80,443,445,3306,3389,5432,8080 -json"
    """
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["naabu"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=300
        )
        output = ANSI_ESCAPE.sub('', result.stdout)
        if result.stderr:
            # Strip ANSI codes then filter out progress/info messages, keep errors
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            stderr_lines = [
                line for line in clean_stderr.split('\n')
                if line and not line.startswith('[INF]')
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"
        return output if output.strip() else "[INFO] No open ports found"
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 300 seconds. Consider using a smaller port range or higher rate."
    except FileNotFoundError:
        return "[ERROR] naabu not found. Ensure it is installed and in PATH."
    except Exception as e:
        return f"[ERROR] {str(e)}"


if __name__ == "__main__":
    import sys

    # Check transport mode from environment
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "sse":
        mcp.run(transport="sse", host=SERVER_HOST, port=SERVER_PORT)
    else:
        mcp.run(transport="stdio")
