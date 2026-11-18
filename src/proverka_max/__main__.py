"""
Запуск MAX-бота «Проверь ссылку» (long polling):
    MAX_TOKEN=... python -m proverka_max
Переменные: MAX_TOKEN (обязательно), RATE_PER_MINUTE, URLHAUS_KEY (как у Telegram-бота).
"""

from __future__ import annotations

import logging
import os
import re
import sys
import time

from proverka_bot.config import _URLHAUS_KEY_RE, load_dotenv
from proverka_bot.handler import handle_update
from proverka_bot.ratelimit import RateLimiter
from proverka_bot.urlhaus import UrlhausChecker

from .api import MaxAPI, MaxError
from .convert import MENU_BUTTONS, to_telegram_update

log = logging.getLogger("proverka_max")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-.]{20,256}$")


def process(event: object, api: MaxAPI, limiter: RateLimiter, reputation=None) -> None:
    """Один event; ошибки логируем без текста сообщения."""
    try:
        update, callback_id, uid = to_telegram_update(event)
        if callback_id:
            api.answer_callback(callback_id)
        if update is None or uid is None:
            return
        if "_reply" in update:
            api.send_message(uid, update["_reply"], MENU_BUTTONS)
            return
        reply = handle_update(update, limiter, reputation)
        if isinstance(reply, tuple):
            api.send_message(uid, reply[1], MENU_BUTTONS)
    except MaxError as exc:
        log.warning("не удалось ответить: %s", exc)
    except Exception:  # noqa: BLE001
        log.exception("ошибка при разборе события")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    load_dotenv()
    token = os.environ.get("MAX_TOKEN", "").strip()
    if not _TOKEN_RE.fullmatch(token):
        print("Ошибка настроек: задайте MAX_TOKEN (токен из business.max.ru → Чат-боты → Настройки)")
        return 1
    rate = int(os.environ.get("RATE_PER_MINUTE", "10") or 10)
    api, limiter = MaxAPI(token), RateLimiter(rate)
    reputation = None
    key = os.environ.get("URLHAUS_KEY", "").strip()
    if key:
        if _URLHAUS_KEY_RE.fullmatch(key):
            reputation = UrlhausChecker(key)
            log.info("проверка ссылок по базе URLhaus включена")
        else:
            log.warning("URLHAUS_KEY неправильного вида — проверка по базе выключена")
    log.info("MAX-бот запущен (polling). Остановить: Ctrl+C")
    marker = None
    while True:
        try:
            data = api.get_updates(marker)
        except MaxError as exc:
            log.warning("ошибка получения событий: %s", exc)
            time.sleep(5)
            continue
        except KeyboardInterrupt:
            return 0
        if isinstance(data.get("marker"), int):
            marker = data["marker"]
        for event in data.get("updates") or []:
            process(event, api, limiter, reputation)


if __name__ == "__main__":
    sys.exit(main())
