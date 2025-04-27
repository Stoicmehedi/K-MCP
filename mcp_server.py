#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests
import json  # Make sure to import json explicitly

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_KALI_SERVER = "http://localhost:5000" # change to your linux IP
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for API requests

# Store active interactive sessions
active_sessions = {}

# Helper function to sanitize JSON responses
def sanitize_response(response_data):
    """
    Sanitize and properly format response data for the MCP client.
    Claude Desktop is sensitive to improperly formatted JSON.
    """
    try:
        # If it's already a string, don't double-encode it
        if isinstance(response_data, str):
            return response_data
            
        # Convert to a properly formatted JSON string
        return json.dumps(response_data)
    except Exception as e:
        logger.error(f"Error sanitizing response: {str(e)}")
        return str(response_data)  # Fallback to simple string conversion

class KaliToolsClient:
    """Client for communicating with the Kali Linux Tools API Server"""
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the Kali Tools Client
        
        Args:
            server_url: URL of the Kali Tools API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {server_url}")
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters
            
        Returns:
            Response data as dictionary
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send
            
        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"
        
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            
            try:
                # Get the response text and ensure it's properly decoded
                json_text = response.text
                # Parse it as JSON
                return response.json()
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON response: {str(e)}")
                logger.error(f"Response text: {response.text[:200]}...")
                return {"error": f"Invalid JSON response: {str(e)}", "success": False}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str) -> Dict[str, Any]:
        """
        Execute a generic command on the Kali server
        
        Args:
            command: Command to execute
            
        Returns:
            Command execution results
        """
        return self.safe_post("api/command", {"command": command})
    
    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Kali Tools API Server
        
        Returns:
            Health status information
        """
        return self.safe_get("health")
    
    def start_interactive_session(self, command: str) -> Dict[str, Any]:
        """
        Start an interactive session for a command
        
        Args:
            command: Command to run in interactive mode
            
        Returns:
            Session information with session_id
        """
        return self.safe_post("api/interactive/start", {"command": command})
    
    def send_to_interactive_session(self, session_id: str, command: str) -> Dict[str, Any]:
        """
        Send a command to an existing interactive session
        
        Args:
            session_id: The session ID
            command: Command to send to the session
            
        Returns:
            Output from the command
        """
        return self.safe_post("api/interactive/send", {
            "session_id": session_id,
            "command": command
        })
    
    def read_interactive_session(self, session_id: str) -> Dict[str, Any]:
        """
        Read output from an interactive session
        
        Args:
            session_id: The session ID
            
        Returns:
            Current output from the session
        """
        return self.safe_post("api/interactive/read", {"session_id": session_id})
    
    def close_interactive_session(self, session_id: str) -> Dict[str, Any]:
        """
        Close an interactive session
        
        Args:
            session_id: The session ID
            
        Returns:
            Status of session closure
        """
        return self.safe_post("api/interactive/close", {"session_id": session_id})
    
    def evil_winrm(self, ip: str, username: str, password: str = "", hash_value: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Start an Evil-WinRM session
        
        Args:
            ip: Target IP address
            username: Username
            password: Password (optional if hash is provided)
            hash_value: NTLM hash (optional if password is provided)
            additional_args: Additional arguments for evil-winrm
            
        Returns:
            Session information
        """
        return self.safe_post("api/tools/evil-winrm", {
            "ip": ip,
            "username": username,
            "password": password,
            "hash": hash_value,
            "additional_args": additional_args
        })

def setup_mcp_server(kali_client: KaliToolsClient) -> FastMCP:
    """
    Set up the MCP server with all tool functions
    
    Args:
        kali_client: Initialized KaliToolsClient
        
    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("kali-mcp")
    
    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target.
        
        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nmap", data)

    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts.
        
        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gobuster", data)

    @mcp.tool()
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirb web content scanner.
        
        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dirb", data)

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.
        
        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nikto", data)

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.
        
        Args:
            url: The target URL
            data: POST data string
            additional_args: Additional SQLmap arguments
            
        Returns:
            Scan results
        """
        post_data = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sqlmap", post_data)

    @mcp.tool()
    def metasploit_run(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a Metasploit module.
        
        Args:
            module: The Metasploit module path
            options: Dictionary of module options
            
        Returns:
            Module execution results
        """
        data = {
            "module": module,
            "options": options
        }
        return kali_client.safe_post("api/tools/metasploit", data)

    @mcp.tool()
    def hydra_attack(
        target: str, 
        service: str, 
        username: str = "", 
        username_file: str = "", 
        password: str = "", 
        password_file: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool.
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments
            
        Returns:
            Attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hydra", data)

    @mcp.tool()
    def john_crack(
        hash_file: str, 
        wordlist: str = "/usr/share/wordlists/rockyou.txt", 
        format_type: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments
            
        Returns:
            Cracking results
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/john", data)

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner.
        
        Args:
            url: The target WordPress URL
            additional_args: Additional WPScan arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wpscan", data)

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool.
        
        Args:
            target: The target IP or hostname
            additional_args: Additional enum4linux arguments
            
        Returns:
            Enumeration results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/enum4linux", data)

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the Kali API server.
        
        Returns:
            Server health information
        """
        return kali_client.check_health()
    
    @mcp.tool()
    def execute_command(command: str) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the Kali server.
        If the command is detected as interactive (like ssh, evil-winrm), it will
        automatically be routed to an interactive session.
        
        Args:
            command: The command to execute
            
        Returns:
            Command execution results or interactive session details
        """
        # Check if this is a command that should be handled interactively
        interactive_command_patterns = [
            "evil-winrm ",
            "ssh ",
            "msfconsole",
            "mysql -u",
            "psql ",
            "telnet ",
            "nc ",
            "netcat ",
            "sqlplus ",
            "python -c \"import pty; pty.spawn",
            "webshell",
            "redis-cli",
            "ftp ",
            "sftp "
        ]
        
        is_interactive = any(pattern in command for pattern in interactive_command_patterns)
        
        if is_interactive and "-c " not in command and not command.endswith("&"):
            logger.info(f"Detected interactive command: {command}. Starting interactive session.")
            result = kali_client.start_interactive_session(command)
            
            # Process the result to ensure proper JSON formatting
            if isinstance(result, dict) and "initial_output" in result:
                # Sanitize any terminal control characters or escape sequences
                result["initial_output"] = sanitize_response(result["initial_output"])
            
            # Store the session ID for later use
            if result.get("success") and "session_id" in result:
                session_id = result["session_id"]
                active_sessions[session_id] = {
                    "command": command,
                    "created_at": "now"
                }
                
                # Return a different format to indicate this is an interactive session
                return {
                    "message": f"Started interactive session for '{command}'",
                    "interactive": True,
                    "session_id": session_id,
                    "initial_output": result.get("initial_output", ""),
                    "usage": "Use interactive_send(session_id='"+session_id+"', command='your_command') to send commands to this session.",
                    "success": True
                }
        
        # Default behavior for non-interactive commands
        result = kali_client.execute_command(command)
        
        # Process the result to ensure proper JSON formatting
        if isinstance(result, dict):
            if "stdout" in result:
                result["stdout"] = sanitize_response(result["stdout"])
            if "stderr" in result:
                result["stderr"] = sanitize_response(result["stderr"])
        
        return result

    @mcp.tool()
    def start_interactive(command: str) -> Dict[str, Any]:
        """
        Start an interactive session for a command that requires continuous interaction.
        
        Args:
            command: Command to run in interactive mode
            
        Returns:
            Session information including session_id and initial output
        """
        result = kali_client.start_interactive_session(command)
        
        # Process the result to ensure proper JSON formatting
        if isinstance(result, dict) and "initial_output" in result:
            # Sanitize any terminal control characters or escape sequences
            result["initial_output"] = sanitize_response(result["initial_output"])
        
        # Store the session ID for later use
        if result.get("success") and "session_id" in result:
            active_sessions[result["session_id"]] = {
                "command": command,
                "created_at": "now"  # You could use datetime here
            }
        
        return result
    
    @mcp.tool()
    def interactive_send(session_id: str, command: str) -> Dict[str, Any]:
        """
        Send a command to an existing interactive session.
        
        Args:
            session_id: ID of the session to send command to
            command: Command to send
            
        Returns:
            Output from the command
        """
        if session_id not in active_sessions:
            return {
                "error": f"Session {session_id} not found or expired",
                "success": False
            }
        
        result = kali_client.send_to_interactive_session(session_id, command)
        
        # Process the result to ensure proper JSON formatting
        if isinstance(result, dict) and "output" in result:
            # Sanitize any terminal control characters or escape sequences
            result["output"] = sanitize_response(result["output"])
            
        return result
    
    @mcp.tool()
    def interactive_read(session_id: str) -> Dict[str, Any]:
        """
        Read output from an interactive session without sending new commands.
        
        Args:
            session_id: ID of the session to read from
            
        Returns:
            Current output from the session
        """
        if session_id not in active_sessions:
            return {
                "error": f"Session {session_id} not found or expired",
                "success": False
            }
        
        result = kali_client.read_interactive_session(session_id)
        
        # Process the result to ensure proper JSON formatting
        if isinstance(result, dict) and "output" in result:
            # Sanitize any terminal control characters or escape sequences
            result["output"] = sanitize_response(result["output"])
            
        return result
    
    @mcp.tool()
    def interactive_close(session_id: str) -> Dict[str, Any]:
        """
        Close an interactive session.
        
        Args:
            session_id: ID of the session to close
            
        Returns:
            Status of session closure
        """
        if session_id not in active_sessions:
            return {
                "error": f"Session {session_id} not found or expired",
                "success": False
            }
        
        result = kali_client.close_interactive_session(session_id)
        
        if result.get("success"):
            del active_sessions[session_id]
        
        return result

    @mcp.tool()
    def evil_winrm_connect(ip: str, username: str, password: str = "", hash_value: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Start an interactive Evil-WinRM session to connect to a Windows machine.
        
        Args:
            ip: Target IP address
            username: Username for authentication
            password: Password (optional if hash is provided)
            hash_value: NTLM hash (optional if password is provided)
            additional_args: Additional arguments for evil-winrm
            
        Returns:
            Session information including session_id for subsequent interaction
        """
        result = kali_client.evil_winrm(ip, username, password, hash_value, additional_args)
        
        # Process the result to ensure proper JSON formatting
        if isinstance(result, dict) and "initial_output" in result:
            # Sanitize any terminal control characters or escape sequences
            result["initial_output"] = sanitize_response(result["initial_output"])
        
        # Store the session ID for later use
        if result.get("success") and "session_id" in result:
            active_sessions[result["session_id"]] = {
                "command": f"evil-winrm to {ip} as {username}",
                "created_at": "now"  # You could use datetime here
            }
        
        return result
    
    @mcp.tool()
    def list_active_sessions() -> Dict[str, Any]:
        """
        List all active interactive sessions.
        
        Returns:
            Dictionary of active sessions
        """
        return {
            "sessions": active_sessions,
            "count": len(active_sessions),
            "success": True
        }

    return mcp

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER, 
                      help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()
    
    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Initialize the Kali Tools client
    kali_client = KaliToolsClient(args.server, args.timeout)
    
    # Check server health and log the result
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health['status']}")
        if not health.get("all_essential_tools_available", False):
            logger.warning("Not all essential tools are available on the Kali server")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools: {', '.join(missing_tools)}")
    
    # Set up and run the MCP server
    mcp = setup_mcp_server(kali_client)
    logger.info("Starting Kali MCP server")
    mcp.run()

if __name__ == "__main__":
    main()
