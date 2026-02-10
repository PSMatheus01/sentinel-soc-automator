import httpx
import json
import logging
import os
from typing import List, Dict, Tuple, Any, Optional
from src.config import settings

logger = logging.getLogger(__name__)

class WazuhOrchestrator:
    def __init__(self):
        self.base_url: str = settings.WAZUH_API_URL
        self.auth: Tuple[str, str] = (settings.WAZUH_API_USER, settings.WAZUH_API_PASSWORD)
        self.token: Optional[str] = None
        self.client: httpx.AsyncClient = httpx.AsyncClient(verify=False, timeout=10.0)
        self.alerts_log_path: str = "/wazuh_logs_mount/alerts/alerts.json"

    async def _get_token(self) -> str:
        try:
            response = await self.client.post(f"{self.base_url}/security/user/authenticate", auth=self.auth)
            response.raise_for_status()
            self.token = response.json()['data']['token']
            logger.info("Token JWT do Wazuh obtido/renovado com sucesso.")
            return self.token
        except Exception as e:
            logger.critical(f"Falha CRÍTICA ao obter token do Wazuh: {e}")
            raise

    async def get_recent_alerts(self) -> List[Dict[str, Any]]:
        alerts = []
        if not os.path.exists(self.alerts_log_path):
            logger.error(f"Arquivo de alertas não encontrado: {self.alerts_log_path}")
            return []
        try:
            with open(self.alerts_log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()[-100:]
            processed_ips = set()
            for line in reversed(lines):
                try:
                    data = json.loads(line)
                    src_ip = data.get('data', {}).get('srcip')
                    if src_ip and src_ip not in processed_ips:
                        alerts.append(data)
                        processed_ips.add(src_ip)
                        if len(alerts) >= 3: break
                except: continue
            return alerts
        except Exception as e:
            logger.error(f"Erro ao processar logs: {e}")
            return []

    async def trigger_active_response(self, agent_id: str, ip: str) -> Tuple[bool, Any]:
        if not self.token: await self._get_token()
        headers = {"Authorization": f"Bearer {self.token}"}
        payload = {"command": "firewall-drop", "custom": True, "alert": {"data": {"srcip": ip}}}
        target_agent = agent_id if agent_id else "000"
        url = f"{self.base_url}/active-response?agents_list={target_agent}"

        try:
            resp = await self.client.put(url, headers=headers, json=payload)
            if resp.status_code == 401:
                logger.warning("Token expirado. Renovando e tentando novamente...")
                await self._get_token()
                headers["Authorization"] = f"Bearer {self.token}"
                resp = await self.client.put(url, headers=headers, json=payload)
            resp.raise_for_status()
            return True, resp.json()
        except Exception as e:
            logger.error(f"Falha ao executar Active Response: {e}")
            return False, str(e)

    async def check_ip_reputation(self, ip: str) -> str:
        if not settings.ABUSEIPDB_KEY: return "N/A (Chave não configurada)"
        try:
            headers = {'Key': settings.ABUSEIPDB_KEY, 'Accept': 'application/json'}
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params={'ipAddress': ip})
                score = resp.json().get('data', {}).get('abuseConfidenceScore', 0)
                return f"Abuse Score: {score}%"
        except Exception:
            return "Falha na Verificação"