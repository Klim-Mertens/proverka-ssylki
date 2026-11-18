"""
Минимальный клиент Telegram Bot API на стандартной библиотеке (без внешних
зависимостей — меньше чужого кода, меньше уязвимостей в цепочке поставок).

Безопасность:
  * адрес API жёстко зашит (https://api.telegram.org) — токен уходит только туда;
  * у каждого запроса есть таймаут (иначе зависший ответ повесит бота);
  * токен НЕ попадает в сообщения об ошибках и логи: мы не печатаем адрес
    запроса, а в ошибках оставляем только тип исключения;
  * сообщения отправляются простым текстом (без parse_mode) — чужие куски
    текста не могут сломать разметку или внедрить HTML.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any

API_HOST = "https://api.telegram.org"
MAX_MESSAGE_LEN = 4096  # ограничение Telegram на длину одного сообщения


# Путь к файлу на серверах Telegram: только «безопасные» символы, без «..».
_FILE_PATH_RE = re.compile(r"^[A-Za-z0-9_\-/]{1,200}\.[A-Za-z0-9]{1,8}$")


class TelegramError(Exception):
    """Ошибка обращения к Telegram (без токена в тексте)."""


class TelegramAPI:
    def __init__(self, token: str, timeout: float = 15.0) -> None:
        self._token = token
        self._timeout = timeout

    def call(self, method: str, params: dict[str, Any], timeout: float | None = None) -> Any:
        url = f"{API_HOST}/bot{self._token}/{method}"
        data = json.dumps(params).encode("utf-8")
        # Адрес начинается с зашитого https://api.telegram.org — другие схемы (file:) невозможны.
        request = urllib.request.Request(  # noqa: S310  # nosec B310
            url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout or self._timeout) as resp:  # noqa: S310  # nosec B310
                payload = json.loads(resp.read(2_000_000))
        except urllib.error.HTTPError as exc:
            raise TelegramError(f"{method}: HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            # from None — чтобы в цепочке исключений не осталось URL с токеном.
            # Добавляем ТИП причины (например, SSLCertVerificationError или
            # TimeoutError) — он помогает понять, что не так с сетью, и не
            # содержит ни адреса, ни токена.
            reason = getattr(exc, "reason", None)
            kind = type(exc).__name__
            if reason is not None:
                kind += f"({type(reason).__name__})"
            raise TelegramError(f"{method}: {kind}") from None
        if not isinstance(payload, dict) or not payload.get("ok"):
            raise TelegramError(f"{method}: отказ Telegram")
        return payload.get("result")

    def send_message(self, chat_id: int, text: str,
                     reply_markup: dict[str, Any] | None = None) -> None:
        params: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text[:MAX_MESSAGE_LEN],
            "disable_web_page_preview": True,
        }
        if reply_markup is not None:
            params["reply_markup"] = reply_markup  # кнопки-памятки под полем ввода
        self.call("sendMessage", params)

    def get_updates(self, offset: int | None, timeout: int = 30) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"timeout": timeout, "allowed_updates": ["message"]}
        if offset is not None:
            params["offset"] = offset
        result = self.call("getUpdates", params, timeout=timeout + 10)
        return result if isinstance(result, list) else []

    def set_webhook(self, url: str, secret: str) -> None:
        self.call("setWebhook", {
            "url": url,
            "secret_token": secret,
            "allowed_updates": ["message"],
            "drop_pending_updates": True,
            "max_connections": 10,
        })

    def download_file(self, file_id: str, max_bytes: int) -> bytes:
        """
        Скачивает файл (фото), который пользователь прислал боту. Только с
        серверов Telegram, с ограничением размера; на диск не сохраняем.
        """
        info = self.call("getFile", {"file_id": file_id})
        if not isinstance(info, dict):
            raise TelegramError("getFile: странный ответ")
        path = info.get("file_path")
        size = info.get("file_size", 0)
        if not isinstance(path, str) or not _FILE_PATH_RE.match(path) or ".." in path:
            raise TelegramError("getFile: странный путь")
        if not isinstance(size, int) or size > max_bytes:
            raise TelegramError("getFile: файл слишком большой")
        url = f"{API_HOST}/file/bot{self._token}/{path}"
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:  # noqa: S310  # nosec B310
                data: bytes = resp.read(max_bytes + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TelegramError(f"download: {type(exc).__name__}") from None
        if len(data) > max_bytes:
            raise TelegramError("download: файл слишком большой")
        return data

    def get_webhook_url(self) -> str:
        """Адрес, на который Telegram сейчас шлёт сообщения ('' — не задан)."""
        info = self.call("getWebhookInfo", {})
        url = info.get("url", "") if isinstance(info, dict) else ""
        return url if isinstance(url, str) else ""

    def delete_webhook(self) -> None:
        self.call("deleteWebhook", {})
