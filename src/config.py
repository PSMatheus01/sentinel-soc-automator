from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

class Settings(BaseSettings):
    TELEGRAM_TOKEN: str
    ALLOWED_USER_IDS: List[int]

    WAZUH_API_URL: str = "https://wazuh-manager:55000"
    WAZUH_API_USER: str = "wazuh"
    WAZUH_API_PASSWORD: str = "wazuh"
    
    ABUSEIPDB_KEY: str | None = None
    VIRUSTOTAL_KEY: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding='utf-8'
    )

settings = Settings()