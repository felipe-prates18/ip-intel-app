from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # ======== CHAVES DE API ========
    VT_API_KEY: str = Field(..., description="VirusTotal API key")
    ABUSEIPDB_API_KEY: str = Field(..., description="AbuseIPDB API key")
    OTX_API_KEY: str = Field(..., description="OTX AlienVault API key")
    IPQS_API_KEY: str = Field(..., description="IPQualityScore API key")
    IPINFO_API_KEY: str = Field(..., description="IPinfo.io API token")
    HYBRID_API_KEY: str = Field(default="", description="Hybrid Analysis API key (opcional)")

    # ======== BASES / CONFIGURAÇÕES ========
    ENV: str = Field(default="production", description="Ambiente de execução")
    VT_BASE: str = Field(default="https://www.virustotal.com/api/v3", description="Endpoint base VirusTotal")
    ABUSEIPDB_BASE: str = Field(default="https://api.abuseipdb.com/api/v2", description="Endpoint base AbuseIPDB")
    OTX_BASE: str = Field(default="https://otx.alienvault.com/api/v1", description="Endpoint base OTX AlienVault")
    HYBRID_BASE: str = Field(default="https://www.hybrid-analysis.com/api/v2", description="Endpoint base Hybrid Analysis")

    REQUEST_TIMEOUT_SECONDS: int = Field(default=15, description="Timeout total das requisições (s)")
    CONNECT_TIMEOUT_SECONDS: int = Field(default=5, description="Timeout de conexão (s)")
    MAX_AGE_DAYS_ABUSEIPDB: int = Field(default=90, description="Idade máxima (em dias) para resultados do AbuseIPDB")

    # ======== INTELIGÊNCIA ARTIFICIAL ========
    ENABLE_AI: bool = Field(default=True, description="Ativa/desativa o recurso de IA (OpenAI)")
    OPENAI_API_KEY: str = Field(default="", description="Chave de API da OpenAI")
    OPENAI_MODEL: str = Field(default="gpt-4o-mini", description="Modelo da OpenAI (ex: gpt-4o-mini)")

    # ======== CONFIGURAÇÃO DO MODELO ========
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

# Instância global
settings = Settings()

