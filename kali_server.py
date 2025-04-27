#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
import pty
import select
import fcntl
import time
import uuid
from typing import Dict, Any
from flask import Flask, request, jsonify, Response, stream_with_context

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 300  # 5 minutes default timeout
INTERACTIVE_TIMEOUT = 1800  # 30 minutes for interactive sessions

app = Flask(__name__)

# Store for interactive sessions
interactive_sessions = {}

class CommandExecutor:
    """Class to handle command execution with better timeout management"""
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line
    
    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {self.command}")
        
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")
                
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()
                
                # Update final output
                self.return_code = -1
            
            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
        
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


class InteractiveSession:
    """Handles interactive terminal sessions for tools like evil-winrm"""
    
    def __init__(self, command, timeout=INTERACTIVE_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.session_id = str(uuid.uuid4())
        self.master = None
        self.slave = None
        self.process = None
        self.last_activity = time.time()
        self.lock = threading.Lock()
        self.buffer = ""
        self.running = False
    
    def start(self):
        """Start the interactive session"""
        try:
            # Create pseudo-terminal
            self.master, self.slave = pty.openpty()
            
            # Make the master non-blocking
            flags = fcntl.fcntl(self.master, fcntl.F_GETFL)
            fcntl.fcntl(self.master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            # Start the process
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdin=self.slave,
                stdout=self.slave,
                stderr=self.slave,
                preexec_fn=os.setsid,
                text=True
            )
            
            self.running = True
            
            # Start monitoring thread
            self.monitor_thread = threading.Thread(target=self._monitor)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            
            logger.info(f"Started interactive session {self.session_id} for command: {self.command}")
            return True
        except Exception as e:
            logger.error(f"Error starting interactive session: {str(e)}")
            logger.error(traceback.format_exc())
            self.cleanup()
            return False
    
    def _monitor(self):
        """Monitor the session for output and timeout"""
        while self.running:
            try:
                if time.time() - self.last_activity > self.timeout:
                    logger.warning(f"Session {self.session_id} timed out after {self.timeout} seconds of inactivity")
                    self.cleanup()
                    break
                
                # Check for new output
                self._read_output()
                
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error in session monitor: {str(e)}")
                break
    
    def _read_output(self):
        """Read available output from the process"""
        try:
            r, _, _ = select.select([self.master], [], [], 0.1)
            if r:
                with self.lock:
                    data = os.read(self.master, 4096).decode('utf-8', errors='replace')
                    self.buffer += data
                    self.last_activity = time.time()
        except (OSError, IOError) as e:
            if e.errno == 5:  # Input/output error, likely process terminated
                self.running = False
            elif e.errno != 11:  # Not a "resource temporarily unavailable" error
                logger.error(f"Error reading from session: {str(e)}")
    
    def send_command(self, command):
        """Send a command to the interactive session"""
        if not self.running:
            return {"error": "Session is not running", "success": False}
        
        try:
            with self.lock:
                os.write(self.master, (command + "\n").encode())
                self.last_activity = time.time()
            
            # Give some time for the command to execute and produce output
            time.sleep(0.5)
            
            # Read any new output
            output = self.read_output()
            
            return {
                "session_id": self.session_id,
                "output": output,
                "success": True
            }
        except Exception as e:
            logger.error(f"Error sending command: {str(e)}")
            return {
                "error": f"Failed to send command: {str(e)}",
                "success": False
            }
    
    def read_output(self):
        """Read and clear the current output buffer"""
        with self.lock:
            output = self.buffer
            self.buffer = ""
            self.last_activity = time.time()
            return output
    
    def cleanup(self):
        """Clean up resources"""
        self.running = False
        
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), 15)  # SIGTERM
                time.sleep(0.5)
                if self.process.poll() is None:
                    os.killpg(os.getpgid(self.process.pid), 9)  # SIGKILL
            except:
                pass
        
        if self.master:
            try:
                os.close(self.master)
            except:
                pass
        
        if self.slave:
            try:
                os.close(self.slave)
            except:
                pass
        
        if self.session_id in interactive_sessions:
            del interactive_sessions[self.session_id]
        
        logger.info(f"Closed interactive session {self.session_id}")


def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a shell command and return the result
    
    Args:
        command: The command to execute
        
    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    executor = CommandExecutor(command)
    return executor.execute()


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.json
        command = params.get("command", "")
        
        if not command:
            logger.warning("Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        # Check if this is likely an interactive command that should use a PTY
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
        
        # If it's an interactive command that isn't using the -c option (for one-off commands)
        # or running in the background with &, route it to an interactive session
        is_interactive = any(pattern in command for pattern in interactive_command_patterns)
        force_non_interactive = "-c " in command or command.endswith("&") or params.get("force_non_interactive", False)
        
        if is_interactive and not force_non_interactive:
            logger.info(f"Routing interactive command to session handler: {command}")
            
            # Start an interactive session
            session = InteractiveSession(command)
            if not session.start():
                return jsonify({
                    "error": "Failed to start interactive session"
                }), 500
            
            # Store the session
            interactive_sessions[session.session_id] = session
            
            # Wait a moment for initial output
            time.sleep(1.5)
            initial_output = session.read_output()
            
            return jsonify({
                "session_id": session.session_id,
                "initial_output": initial_output,
                "interactive": True,
                "message": "Interactive command started. Use the interactive endpoints to communicate.",
                "success": True
            })
        
        # For non-interactive commands, use the regular executor
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/interactive/start", methods=["POST"])
def start_interactive_session():
    """Start an interactive session for tools like evil-winrm"""
    try:
        params = request.json
        command = params.get("command", "")
        
        if not command:
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        # Create and start the session
        session = InteractiveSession(command)
        if not session.start():
            return jsonify({
                "error": "Failed to start interactive session"
            }), 500
        
        # Store the session
        interactive_sessions[session.session_id] = session
        
        # Wait a moment for initial output
        time.sleep(1)
        initial_output = session.read_output()
        
        return jsonify({
            "session_id": session.session_id,
            "initial_output": initial_output,
            "success": True
        })
    except Exception as e:
        logger.error(f"Error starting interactive session: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/interactive/send", methods=["POST"])
def send_to_interactive_session():
    """Send a command to an existing interactive session"""
    try:
        params = request.json
        session_id = params.get("session_id", "")
        command = params.get("command", "")
        
        if not session_id or not command:
            return jsonify({
                "error": "Both session_id and command parameters are required"
            }), 400
        
        if session_id not in interactive_sessions:
            return jsonify({
                "error": f"Session {session_id} not found or expired"
            }), 404
        
        session = interactive_sessions[session_id]
        result = session.send_command(command)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error sending to interactive session: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/interactive/read", methods=["POST"])
def read_interactive_session():
    """Read output from an existing interactive session"""
    try:
        params = request.json
        session_id = params.get("session_id", "")
        
        if not session_id:
            return jsonify({
                "error": "session_id parameter is required"
            }), 400
        
        if session_id not in interactive_sessions:
            return jsonify({
                "error": f"Session {session_id} not found or expired"
            }), 404
        
        session = interactive_sessions[session_id]
        output = session.read_output()
        
        return jsonify({
            "session_id": session_id,
            "output": output,
            "success": True
        })
    except Exception as e:
        logger.error(f"Error reading from interactive session: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/interactive/close", methods=["POST"])
def close_interactive_session():
    """Close an interactive session"""
    try:
        params = request.json
        session_id = params.get("session_id", "")
        
        if not session_id:
            return jsonify({
                "error": "session_id parameter is required"
            }), 400
        
        if session_id not in interactive_sessions:
            return jsonify({
                "error": f"Session {session_id} not found or already closed"
            }), 404
        
        session = interactive_sessions[session_id]
        session.cleanup()
        
        return jsonify({
            "message": f"Session {session_id} closed successfully",
            "success": True
        })
    except Exception as e:
        logger.error(f"Error closing interactive session: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/evil-winrm", methods=["POST"])
def evil_winrm():
    """Start an evil-winrm session with the provided parameters."""
    try:
        params = request.json
        ip = params.get("ip", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_value = params.get("hash", "")
        additional_args = params.get("additional_args", "")
        
        if not ip:
            return jsonify({
                "error": "IP parameter is required"
            }), 400
        
        if not username:
            return jsonify({
                "error": "Username parameter is required"
            }), 400
        
        if not password and not hash_value:
            return jsonify({
                "error": "Either password or hash parameter is required"
            }), 400
        
        command = f"evil-winrm -i {ip} -u '{username}'"
        
        if password:
            command += f" -p '{password}'"
        elif hash_value:
            command += f" -H '{hash_value}'"
        
        if additional_args:
            command += f" {additional_args}"
        
        # Start interactive session
        session = InteractiveSession(command)
        if not session.start():
            return jsonify({
                "error": "Failed to start evil-winrm session"
            }), 500
        
        # Store the session
        interactive_sessions[session.session_id] = session
        
        # Wait a moment for initial output
        time.sleep(2)
        initial_output = session.read_output()
        
        return jsonify({
            "session_id": session.session_id,
            "initial_output": initial_output,
            "message": "Evil-WinRM session started. Use the interactive endpoints to communicate.",
            "success": True
        })
    except Exception as e:
        logger.error(f"Error in evil-winrm endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        
        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400        
        
        command = f"nmap {scan_type}"
        
        if ports:
            command += f" -p {ports}"
        
        if additional_args:
            # Basic validation for additional args - more sophisticated validation would be better
            command += f" {additional_args}"
        
        command += f" {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400
        
        command = f"gobuster {mode} -u {url} -w {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"dirb {url} {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nikto -h {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"sqlmap -u {url} --batch"
        
        if data:
            command += f" --data=\"{data}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400
        
        # Format options for Metasploit
        options_str = ""
        for key, value in options.items():
            options_str += f" {key}={value}"
        
        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"
        
        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)
        
        command = f"msfconsole -q -r {resource_file}"
        result = execute_command(command)
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400
        
        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400
        
        command = f"hydra -t 4"
        
        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"
        
        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target} {service}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
        
        command = f"john"
        
        if format_type:
            command += f" --format={format_type}"
        
        if wordlist:
            command += f" --wordlist={wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {hash_file}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"wpscan --url {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        
        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"enum4linux {additional_args} {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # Check if essential tools are installed
    essential_tools = ["nmap", "gobuster", "dirb", "nikto"]
    tools_status = {}
    
    for tool in essential_tools:
        try:
            result = execute_command(f"which {tool}")
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False
    
    all_essential_tools_available = all(tools_status.values())
    
    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available
    })

@app.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    # Return tool capabilities similar to our existing MCP server
    pass

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    # Direct tool execution without going through the API server
    pass

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    
    if args.port != API_PORT:
        API_PORT = args.port
    
    logger.info(f"Starting Kali Linux Tools API Server on port {API_PORT}")
    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)
