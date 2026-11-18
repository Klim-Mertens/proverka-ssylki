"""
Настройки бота. Все секреты берутся ТОЛЬКО из переменных окружения
(на хостинге — раздел «Environment / Secrets»; локально — файл .env).
В коде и в репозитории токенов быть не должно.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# Токен бота выглядит так: 123456789:AAH... (цифры, двоеточие, 35 символов).
_TOKEN_RE = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,50}$")

# Секрет webhook: Telegram разрешает только эти символы, длина 1–256.
_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")

# Ключ URLhaus (abuse.ch): строка из латиницы и цифр. Проверяем формат,
# чтобы случайно не отправить в заголовок что-то лишнее (перенос строки и т.п.).
_URLHAUS_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class ConfigError(Exception):
    """Неверные или отсутствующие настройки."""


def load_dotenv(path: str = ".env") -> None:
    """
    Минимальное чтение файла .env (чтобы не ставить лишнюю библиотеку).
    Строки вида ИМЯ=значение; уже заданные переменные окружения НЕ
    перезаписываются (на хостинге приоритет у настоящих секретов).
    """
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip().strip("'\""))
    except FileNotFoundError:
        pass


@dataclass(frozen=True)
class Config:
    token: str = field(repr=False)  # repr=False: токен не попадёт в логи при печати объекта
    webhook_secret: str = field(repr=False, default="")
    port: int = 8080
    # Публичный https-адрес сервиса (например, https://имя.onrender.com).
    # Если задан, бот сам сообщает его Telegram при запуске.
    public_url: str = ""
    # Сколько проверок в минуту разрешено одному человеку (защита от спама).
    rate_per_minute: int = 6
    # Ключ базы опасных сайтов URLhaus. Пусто — внешняя проверка выключена.
    urlhaus_key: str = field(repr=False, default="")


def load_config(need_webhook_secret: bool = False) -> Config:
    token = os.environ.get("BOT_TOKEN", "")
    if not _TOKEN_RE.match(token):
        raise ConfigError(
            "Не задан BOT_TOKEN или он неправильный. Получите токен у @BotFather "
            "и положите его в переменную окружения BOT_TOKEN (не в код!)."
        )
    secret = os.environ.get("WEBHOOK_SECRET", "")
    if need_webhook_secret and not _SECRET_RE.match(secret):
        raise ConfigError(
            "Для режима webhook нужен WEBHOOK_SECRET: 16–256 символов "
            "(латиница, цифры, _ и -). Придумайте длинную случайную строку."
        )
    try:
        port = int(os.environ.get("PORT", "8080"))
    except ValueError as exc:
        raise ConfigError("PORT должен быть числом") from exc
    if not 1 <= port <= 65535:
        raise ConfigError("PORT вне диапазона 1–65535")
    # Render сам задаёт RENDER_EXTERNAL_URL; для других хостингов — PUBLIC_URL.
    public_url = (os.environ.get("PUBLIC_URL") or os.environ.get("RENDER_EXTERNAL_URL") or "").rstrip("/")
    if public_url and not public_url.startswith("https://"):
        raise ConfigError("PUBLIC_URL должен начинаться с https://")
    urlhaus_key = os.environ.get("URLHAUS_KEY", "").strip()
    if urlhaus_key and not _URLHAUS_KEY_RE.match(urlhaus_key):
        raise ConfigError("URLHAUS_KEY неправильного вида: скопируйте ключ из abuse.ch целиком, без пробелов.")
    return Config(token=token, webhook_secret=secret, port=port, public_url=public_url,
                  urlhaus_key=urlhaus_key)
