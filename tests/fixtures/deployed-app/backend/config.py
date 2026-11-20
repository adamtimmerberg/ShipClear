# FIXTURE: a settings class whose defaults let the app boot with no config.
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    secret_key: str = "change-me-dev-only"
    is_production: bool = False


settings = Settings()
