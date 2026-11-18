"""Общий TLS-контекст для всех HTTPS-запросов бота.

Python с python.org на macOS не видит системные корневые сертификаты, пока не
запущен «Install Certificates.command», и тогда любое HTTPS-соединение падает
с CERTIFICATE_VERIFY_FAILED. Если установлен certifi, берём сертификаты из него
(как делает aiogram). Проверка сертификата не отключается ни в одном случае.
"""

from __future__ import annotations

import ssl
from functools import lru_cache


@lru_cache(maxsize=1)
def https_context() -> ssl.SSLContext:
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def describe_network_error(exc: BaseException) -> str:
    """Понятная причина сетевой ошибки без токена и адреса запроса."""
    reason = getattr(exc, "reason", exc)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return ("не удалось проверить сертификат сервера. На Mac: откройте папку "
                "«Программы → Python 3.x» и запустите «Install Certificates.command», "
                "либо выполните pip install certifi")
    return f"сеть недоступна ({type(reason).__name__})"


@lru_cache(maxsize=1)
def max_context() -> ssl.SSLContext:
    """TLS-контекст только для соединений с MAX. Сервер MAX использует сертификат
    российского удостоверяющего центра Минцифры (Russian Trusted Root/Sub CA): его нет
    ни в certifi, ни в системе macOS. Добавляем центр ТОЛЬКО в этот контекст, не в
    систему и не в Telegram. Проверка сертификата остаётся включённой."""
    from pathlib import Path

    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx.load_verify_locations(cafile=certifi.where())
    except ImportError:
        pass
    ctx.load_verify_locations(cafile=str(Path(__file__).resolve().parents[1] / "proverka_max" / "russiantrustedca.pem"))
    return ctx
