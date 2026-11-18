"""
Проверка ссылок по бесплатной базе опасных сайтов URLhaus (abuse.ch).

Что такое URLhaus: открытая база адресов, с которых распространяют вирусы
(в том числе поддельные «приложения банков» .apk). Её ведёт швейцарский
некоммерческий проект abuse.ch. Документация: https://urlhaus-api.abuse.ch/

ПРИВАТНОСТЬ И БЕЗОПАСНОСТЬ:
  * В abuse.ch уходит ТОЛЬКО адрес ссылки (или имя сайта). Текст сообщения,
    имя и номер человека никуда не отправляются.
  * Мы НЕ открываем саму ссылку — только спрашиваем базу «знаешь ли ты
    этот адрес?». Наш сервер на сайт мошенников не заходит.
  * Ключ (Auth-Key) берётся только из переменной окружения URLHAUS_KEY и
    никогда не попадает в логи и тексты ошибок.
  * Любая ошибка сети или странный ответ = «база ничего не сказала». Бот
    при этом продолжает работать по своим правилам.
  * Сертификат HTTPS проверяется всегда (стандартный контекст ssl).
  * Ответ читается не больше MAX_RESPONSE байт: защита от «бесконечного» ответа.
"""

from __future__ import annotations

import json
import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from proverka.data import SHORTENERS
from proverka.extract import FoundUrl
from proverka.url_rules import USER_CONTENT_DOMAINS

log = logging.getLogger("proverka_bot.urlhaus")

API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
API_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
MAX_RESPONSE = 1_000_000  # 1 МБ хватает с запасом
MAX_URL_LEN = 2048
USER_AGENT = "proverka-bot/1.0"

# Большие площадки, где тысячи чужих страниц. Если в базе есть ОДНА опасная
# ссылка на drive.google.com, это не значит, что опасна любая ссылка туда.
# Для них проверяем только точный адрес, но не сайт целиком.
SHARED_HOSTS = frozenset({
    "drive.google.com", "docs.google.com", "storage.googleapis.com",
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "gitlab.com", "bitbucket.org", "dropbox.com", "www.dropbox.com",
    "dl.dropboxusercontent.com", "onedrive.live.com", "1drv.ms",
    "cdn.discordapp.com", "mediafire.com", "www.mediafire.com",
    "disk.yandex.ru", "yadi.sk", "cloud.mail.ru", "transfer.sh",
}) | USER_CONTENT_DOMAINS | SHORTENERS

# Веса признака. Точное совпадение адреса — почти гарантия опасности.
WEIGHT_EXACT = 90
WEIGHT_HOST_ONLINE = 80
WEIGHT_HOST_OLD = 40

# Функция отправки запроса: (адрес API, данные формы, заголовки) → тело ответа.
# В тестах подменяется заглушкой, поэтому тесты не ходят в интернет.
Sender = Callable[[str, bytes, dict[str, str]], bytes]


def _default_sender(timeout: float) -> Sender:
    context = ssl.create_default_context()  # проверка сертификата включена

    def send(api_url: str, data: bytes, headers: dict[str, str]) -> bytes:
        # api_url — одна из констант выше (https://urlhaus-api.abuse.ch/...),
        # поэтому схемы вроде file:// здесь невозможны.
        request = urllib.request.Request(api_url, data=data, headers=headers, method="POST")  # noqa: S310  # nosec B310
        with urllib.request.urlopen(request, timeout=timeout, context=context) as resp:  # noqa: S310  # nosec B310
            body: bytes = resp.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise ValueError("слишком большой ответ")
        return body

    return send


class UrlhausChecker:
    """
    Проверка одной ссылки. Объект можно передать в analyze(..., reputation=...):
    он вызывается как функция и возвращает (вес, пояснение) или None.
    """

    def __init__(self, auth_key: str, timeout: float = 4.0, sender: Sender | None = None) -> None:
        self._key = auth_key
        self._send = sender or _default_sender(timeout)

    def __repr__(self) -> str:  # ключ не должен попасть в логи при печати объекта
        return "UrlhausChecker(<ключ скрыт>)"

    def _query(self, api_url: str, field: str, value: str) -> dict[str, Any] | None:
        data = urllib.parse.urlencode({field: value}).encode("ascii")
        headers = {
            "Auth-Key": self._key,
            "User-Agent": USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            body = self._send(api_url, data, headers)
            payload = json.loads(body)
        except urllib.error.HTTPError as exc:
            # 401 — неверный ключ. Пишем только код, без ключа и без адреса.
            log.warning("URLhaus: HTTP %s", exc.code)
            return None
        except Exception as exc:  # noqa: BLE001 — любая ошибка = «база молчит»
            log.warning("URLhaus недоступен: %s", type(exc).__name__)
            return None
        return payload if isinstance(payload, dict) else None

    def _check_exact(self, address: str) -> tuple[int, str] | None:
        payload = self._query(API_URL, "url", address)
        if not payload or payload.get("query_status") != "ok":
            return None  # "no_results" — адреса в базе нет
        status = payload.get("url_status")
        if status == "online":
            return WEIGHT_EXACT, "Сейчас по этой ссылке распространяют вирус."
        return WEIGHT_EXACT, "По этой ссылке распространяли вирус."

    def _check_host(self, host: str) -> tuple[int, str] | None:
        payload = self._query(API_HOST, "host", host)
        if not payload or payload.get("query_status") != "ok":
            return None
        urls = payload.get("urls")
        if not isinstance(urls, list) or not urls:
            return None
        online = any(isinstance(u, dict) and u.get("url_status") == "online" for u in urls[:200])
        if online:
            return WEIGHT_HOST_ONLINE, "С этого сайта сейчас распространяют вирусы."
        return WEIGHT_HOST_OLD, "С этого сайта раньше распространяли вирусы."

    def __call__(self, url: FoundUrl) -> tuple[int, str] | None:
        host = url.host_ascii.lower()
        if not host:
            return None
        address = url.raw if url.scheme else "http://" + url.raw
        if len(address) <= MAX_URL_LEN:
            exact = self._check_exact(address)
            if exact is not None:
                return exact
        if host in SHARED_HOSTS:
            return None
        return self._check_host(host)
