import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class KaananConfig:
    api_key: str
    model: str


@dataclass(frozen=True)
class VaptConfig:
    api_key: str
    model: str
    target_ip: str
    target_port: int
    target_file: str
    max_tokens_per_api: int
    test_username: str = ""   # optional: auto-authentication credential
    test_password: str = ""   # optional: auto-authentication credential

    @property
    def base_url(self) -> str:
        return f"http://{self.target_ip}:{self.target_port}"


def _ensure_dotenv_loaded() -> None:
    env_path = Path.cwd() / ".env"
    if not env_path.exists():
        raise FileNotFoundError(
            f"No .env file found in {Path.cwd()}.\n"
            "Create one with KAANAN_API_KEY and KAANAN_MODEL.\n"
            "Run `kaanan init` to scaffold one automatically."
        )
    load_dotenv(dotenv_path=env_path, override=True)


def load_config() -> KaananConfig:
    """
    Reads .env from the directory where the user runs `kaanan`.
    Equivalent to Pydantic BaseSettings with env_file=".env".
    """
    _ensure_dotenv_loaded()

    api_key = os.getenv("KAANAN_API_KEY", "").strip()
    model   = os.getenv("KAANAN_MODEL",   "").strip()

    if not api_key:
        raise ValueError("KAANAN_API_KEY is missing or empty in your .env file.")
    if not model:
        raise ValueError("KAANAN_MODEL is missing or empty in your .env file.")

    return KaananConfig(api_key=api_key, model=model)


def load_vapt_config() -> VaptConfig:
    """
    Reads all VAPT-specific vars from .env in addition to the base LLM config.

    Required .env keys:
        KAANAN_API_KEY            — LLM provider API key
        KAANAN_MODEL              — LiteLLM model string
        KAANAN_TARGET_IP          — IP where the target server is running
        KAANAN_TARGET_PORT        — Port the target server listens on
        KAANAN_TARGET_FILE        — Entry-point file (e.g. app.py, index.js)
        KAANAN_MAX_TOKENS_PER_API — Token budget per endpoint (e.g. 5000)
    """
    _ensure_dotenv_loaded()

    api_key     = os.getenv("KAANAN_API_KEY",            "").strip()
    model       = os.getenv("KAANAN_MODEL",              "").strip()
    target_ip   = os.getenv("KAANAN_TARGET_IP",          "").strip()
    port_str    = os.getenv("KAANAN_TARGET_PORT",        "").strip()
    target_file = os.getenv("KAANAN_TARGET_FILE",        "").strip()
    tokens_str  = os.getenv("KAANAN_MAX_TOKENS_PER_API", "5000").strip()
    test_user   = os.getenv("KAANAN_TEST_USERNAME",      "").strip()
    test_pass   = os.getenv("KAANAN_TEST_PASSWORD",      "").strip()

    if not api_key:
        raise ValueError("KAANAN_API_KEY is missing or empty in your .env file.")
    if not model:
        raise ValueError("KAANAN_MODEL is missing or empty in your .env file.")
    if not target_ip:
        raise ValueError("KAANAN_TARGET_IP is missing from your .env file.")
    if not port_str:
        raise ValueError("KAANAN_TARGET_PORT is missing from your .env file.")
    if not target_file:
        raise ValueError("KAANAN_TARGET_FILE is missing from your .env file.")

    try:
        target_port = int(port_str)
    except ValueError:
        raise ValueError(
            f"KAANAN_TARGET_PORT must be an integer, got: '{port_str}'"
        )

    try:
        max_tokens = int(tokens_str)
        if max_tokens < 100:
            raise ValueError
    except ValueError:
        raise ValueError(
            f"KAANAN_MAX_TOKENS_PER_API must be a positive integer >= 100, "
            f"got: '{tokens_str}'"
        )

    return VaptConfig(
        api_key=api_key,
        model=model,
        target_ip=target_ip,
        target_port=target_port,
        target_file=target_file,
        max_tokens_per_api=max_tokens,
        test_username=test_user,
        test_password=test_pass,
    )