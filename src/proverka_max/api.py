"""
Минимальный клиент MAX Bot API (https://dev.max.ru/docs-api) на стандартной
библиотеке, без сторонних пакетов — как и клиент Telegram в proverka_bot.

  * токен передаётся в заголовке Authorization (не в адресе: адреса попадают в логи);
  * проверка TLS-сертификата не отключается;
  * сообщения отправляются простым текстом (format не задаём) — в отчёте есть
    куски чужого сообщения, разметка открыла бы дорогу HTML-инъекции.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from proverka_bot.tls import describe_network_error, max_context

API_URL = "https://platform-api2.max.ru"
MAX_MESSAGE_LEN = 4000


class MaxError(Exception):
    """Ошибка обращения к MAX (без токена в тексте)."""


class MaxAPI:
    def __init__(self, token: str, timeout: float = 15.0) -> None:
        self._headers = {"Authorization": token, "Content-Type": "application/json"}
        self._timeout = timeout

    def call(self, method: str, path: str, params: dict[str, Any] | None = None,
             body: dict[str, Any] | None = None, timeout: float | None = None) -> Any:
        url = API_URL + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, headers=self._headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout or self._timeout, context=max_context()) as resp:  # noqa: S310  # nosec B310
                raw = resp.read(1_000_000)
        except urllib.error.HTTPError as exc:
            raise MaxError(f"HTTP {exc.code} в {path}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise MaxError(describe_network_error(exc)) from None
        try:
            result = json.loads(raw) if raw else {}
        except ValueError:
            raise MaxError(f"неожиданный ответ в {path}") from None
        if isinstance(result, dict) and result.get("success") is False:
            raise MaxError(f"{result.get('code', 'error')} в {path}")
        return result

    def send_message(self, user_id: int, text: str,
                     buttons: list[list[dict[str, Any]]] | None = None) -> None:
        body: dict[str, Any] = {"text": text[:MAX_MESSAGE_LEN], "attachments": []}
        if buttons:
            body["attachments"].append({"type": "inline_keyboard", "payload": {"buttons": buttons}})
        self.call("POST", "/messages", {"user_id": user_id, "disable_link_preview": "true"}, body)

    def me(self) -> dict[str, Any]:
        result = self.call("GET", "/me")
        return result if isinstance(result, dict) else {}

    def subscriptions(self) -> list[dict[str, Any]]:
        result = self.call("GET", "/subscriptions")
        return (result.get("subscriptions") or []) if isinstance(result, dict) else []

    def answer_callback(self, callback_id: str) -> None:
        self.call("POST", "/answers", {"callback_id": callback_id}, {})

    def get_updates(self, marker: int | None, timeout: int = 30) -> dict[str, Any]:
        params: dict[str, Any] = {"timeout": timeout, "limit": 100,
                                  "types": "message_created,message_callback,bot_started"}
        if marker is not None:
            params["marker"] = marker
        result = self.call("GET", "/updates", params, timeout=timeout + 10)
        return result if isinstance(result, dict) else {}
