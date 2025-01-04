import subprocess
import json
import time
import requests
from typing import Optional, Dict, Any

class TunnelManager:
    def __init__(self):
        self.active_tunnels: Dict[str, subprocess.Popen] = {}

    def _get_tunnel_url(self, retries: int = 5, delay: float = 1.0) -> str:
        """Get the ngrok tunnel URL with retries."""
        for attempt in range(retries):
            try:
                response = requests.get('http://localhost:4040/api/tunnels')
                tunnels = response.json().get('tunnels', [])
                if tunnels:
                    return tunnels[0]['public_url']
            except Exception as e:
                if attempt == retries - 1:
                    raise Exception(f"Failed to get tunnel URL: {str(e)}")
            time.sleep(delay)
        raise Exception("No tunnels found after retries")

    def start_tunnel(self, port: int) -> Dict[str, Any]:
        """Start an ngrok tunnel for the specified port."""
        try:
            # Check if tunnel already exists
            if str(port) in self.active_tunnels:
                # Check if process is still running
                if self.active_tunnels[str(port)].poll() is None:
                    try:
                        url = self._get_tunnel_url()
                        return {"status": "success", "url": url}
                    except Exception:
                        # If we can't get URL, tunnel might be dead, remove it
                        self.stop_tunnel(port)
                else:
                    # Process has ended, remove it
                    del self.active_tunnels[str(port)]

            # Start new tunnel
            process = subprocess.Popen(
                ['ngrok', 'http', str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.active_tunnels[str(port)] = process
            
            # Wait for tunnel to be ready and get URL
            try:
                url = self._get_tunnel_url()
                return {"status": "success", "url": url}
            except Exception as e:
                self.stop_tunnel(port)
                return {"status": "error", "message": str(e)}
                
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def stop_tunnel(self, port: int) -> Dict[str, str]:
        """Stop the ngrok tunnel for the specified port."""
        try:
            if str(port) in self.active_tunnels:
                process = self.active_tunnels[str(port)]
                process.terminate()
                process.wait(timeout=5)  # Wait up to 5 seconds for process to terminate
                del self.active_tunnels[str(port)]
                return {"status": "success", "message": f"Tunnel for port {port} stopped"}
            return {"status": "error", "message": f"No active tunnel found for port {port}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_active_tunnels(self) -> Dict[str, bool]:
        """Get a dictionary of active tunnel ports and their status."""
        active = {}
        for port in list(self.active_tunnels.keys()):
            process = self.active_tunnels[port]
            active[port] = process.poll() is None
            if not active[port]:
                del self.active_tunnels[port]
        return active

# Create a global instance
tunnel_manager = TunnelManager()