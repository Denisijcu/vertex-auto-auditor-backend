import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    PROJECT_NAME: str = Field(default="Vertex Auto-Auditor SaaS")
    ENVIRONMENT: str = Field(default="development")
    DEBUG: bool = Field(default=True)
    
    # Database
    DATABASE_URL: str = Field(..., validation_alias="DATABASE_URL")
    
    # LLM Providers
    OPENAI_API_KEY: str | None = Field(default=None)
    ANTHROPIC_API_KEY: str | None = Field(default=None)
    
    # MCP
    MCP_SERVER_NAME: str = Field(default="vertex-auditor-mcp")
    MCP_SERVER_VERSION: str = Field(default="0.1.0")
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

# Instancia única para importar en toda la app
settings = Settings()