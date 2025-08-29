from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr, PostgresDsn
from pathlib import Path


class Settings(BaseSettings):
    APP_NAME: str = "task_manager"
    DEBUG: bool = True

    DB_URL: PostgresDsn

    secret_key: str
    algorithm: str
    access_token_expire_minutes: int = 1 * 24 * 60
    refresh_token_expire_days: int = 15

    def get_auth_data(self):
        return {
            'secret_key': self.secret_key,
            'algorithm': self.algorithm
        }

    model_config = SettingsConfigDict(
        env_file=Path(__file__).parent / ".env", extra="ignore"
    )
