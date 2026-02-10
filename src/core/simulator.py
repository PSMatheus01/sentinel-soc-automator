import socket
import random
import asyncio
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

class AttackSimulator:
    def __init__(self, target_host: str = "wazuh-manager", target_port: int = 514):
        self.target: Tuple[str, int] = (target_host, target_port)
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    def _send_log(self, message: str) -> None:
        formatted_log = f"<13>Feb 10 10:00:00 simulated-host sshd[1234]: {message}"
        self.sock.sendto(formatted_log.encode(), self.target)
        logger.info(f"Log simulado enviado: {message}")

    async def run_ssh_brute_force(self) -> str:
        attacker_ips = ["192.168.1.50", "10.0.0.66", "45.33.22.11"]
        target_ip = random.choice(attacker_ips)
        
        logger.info(f"--- Iniciando Simulação: SSH Brute Force de {target_ip} ---")
        for _ in range(6):
            self._send_log(f"Failed password for invalid user admin from {target_ip} port 4422 ssh2")
            await asyncio.sleep(0.5)
        
        return target_ip