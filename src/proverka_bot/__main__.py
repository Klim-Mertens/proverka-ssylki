"""
Запуск бота:
    python -m proverka_bot poll                        # на своём компьютере
    python -m proverka_bot serve                       # на хостинге (webhook-сервер)
    python -m proverka_bot set-webhook https://адрес   # один раз: сообщить Telegram адрес
"""

from __future__ import annotations

import logging
import sys

from .config import ConfigError, load_config, load_dotenv
from .server import WEBHOOK_PATH, run_polling, run_webhook
from .telegram_api import TelegramAPI, TelegramError


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    load_dotenv()
    mode = argv[1] if len(argv) > 1 else ""
    try:
        if mode == "poll":
            run_polling(load_config())
        elif mode == "serve":
            run_webhook(load_config(need_webhook_secret=True))
        elif mode == "set-webhook" and len(argv) == 3:
            url = argv[2].rstrip("/")
            if not url.startswith("https://"):
                print("Адрес должен начинаться с https:// (Telegram требует защищённое соединение)")
                return 2
            config = load_config(need_webhook_secret=True)
            TelegramAPI(config.token).set_webhook(url + WEBHOOK_PATH, config.webhook_secret)
            print("Готово: Telegram будет присылать сообщения на", url + WEBHOOK_PATH)
        else:
            print(__doc__)
            return 2
    except ConfigError as exc:
        print("Ошибка настроек:", exc)
        return 1
    except TelegramError as exc:
        print("Ошибка Telegram:", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
