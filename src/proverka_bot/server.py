"""
Приём сообщений от Telegram двумя способами:

  * webhook — Telegram сам присылает сообщения на наш HTTPS-адрес
    (подходит для хостинга: не нужно постоянно «опрашивать»);
  * polling — бот сам спрашивает Telegram (удобно проверять на своём
    компьютере без публичного адреса).

Защита webhook:
  1. Telegram добавляет заголовок X-Telegram-Bot-Api-Secret-Token с секретом,
     который мы задали сами. Без верного секрета запрос отбрасывается —
     иначе любой в интернете мог бы слать боту «сообщения от Telegram».
  2. Секрет сравнивается через hmac.compare_digest (постоянное время),
     чтобы его нельзя было подобрать по времени ответа.
  3. Ограничен размер тела запроса, а ошибки не раскрывают подробностей.
"""

from __future__ import annotations

import hmac
import json
import secrets
import logging
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .config import Config
from concurrent.futures import ThreadPoolExecutor

from . import ocr, qr
from proverka.analyzer import UrlReputation

from . import widget
from .handler import (OCR_FAIL_TEXT, OCR_WAIT_TEXT, PRIVATE_ONLY_TEXT, OcrJob, ReportReply, handle_update,
                      report_for_ocr_text)
from .memos import MENU
from .ratelimit import RateLimiter
from .telegram_api import TelegramAPI, TelegramError
from .urlhaus import UrlhausChecker

log = logging.getLogger("proverka_bot")

MAX_BODY = 256 * 1024  # настоящие сообщения Telegram гораздо меньше
WEBHOOK_PATH = "/webhook"


def make_reputation(config: Config) -> UrlReputation | None:
    """Проверка по базе URLhaus включается, только если задан URLHAUS_KEY."""
    if not config.urlhaus_key:
        log.info("проверка ссылок по базе URLhaus выключена (нет URLHAUS_KEY)")
        return None
    log.info("проверка ссылок по базе URLhaus включена")
    return UrlhausChecker(config.urlhaus_key)


def _show_progress(api: TelegramAPI, chat_id: int, text: str) -> None:
    """«Читаю картинку…» как черновик (sendMessageDraft, Bot API 9.3+): анимированная
    подсказка исчезает сама, когда придёт отчёт, и не остаётся мусором в чате.
    Если метод недоступен — обычное сообщение, как раньше."""
    try:
        api.call("sendMessageDraft", {"chat_id": chat_id, "draft_id": secrets.randbelow(2**31 - 1) + 1,
                                      "text": text})
    except TelegramError:
        api.send_message(chat_id, text)


def _run_ocr(job: OcrJob, api: TelegramAPI, reputation: UrlReputation | None = None) -> None:
    _show_progress(api, job.chat_id, OCR_WAIT_TEXT)
    try:
        data = api.download_file(job.file_id, ocr.MAX_FILE_BYTES)
        # QR-коды читаем до OCR: даже если текста на картинке нет, ссылка в
        # QR-коде будет проверена.
        qr_links = qr.links_from_codes(qr.decode_qr(data))
        try:
            text = ocr.image_to_text(data)
        except ocr.OcrError:
            if not qr_links:
                raise
            text = ""
        del data  # картинку сразу забываем
    except (TelegramError, ocr.OcrError) as exc:
        log.warning("OCR не удался: %s", exc)
        api.send_message(job.chat_id, OCR_FAIL_TEXT)
        return
    api.send_message(job.chat_id, report_for_ocr_text(text, job, reputation, qr_links), reply_markup=MENU)


def process_update(update: Any, api: TelegramAPI, limiter: RateLimiter,
                   reputation: UrlReputation | None = None) -> None:
    """Обрабатывает один update; любые сбои логируем БЕЗ текста сообщения."""
    try:
        reply = handle_update(update, limiter, reputation)
        if isinstance(reply, OcrJob):
            _run_ocr(reply, api, reputation)
        elif reply is not None:
            # Кнопки-памятки прикладываем к каждому ответу: так они точно есть
            # у всех, в том числе у тех, кто начал пользоваться ботом раньше.
            chat_id, text = reply
            if isinstance(reply, ReportReply) and widget.ENABLED and _send_widget(api, chat_id, reply):
                return
            # В группах кнопки не показываем: там бот не работает.
            markup = None if text == PRIVATE_ONLY_TEXT else MENU
            api.send_message(chat_id, text, reply_markup=markup)
    except TelegramError as exc:
        log.warning("не удалось отправить ответ: %s", exc)
    except Exception:  # noqa: BLE001 — бот не должен падать от одного странного сообщения
        log.exception("ошибка при разборе сообщения")  # трассировка без данных пользователя


def _send_widget(api: TelegramAPI, chat_id: int, reply: "ReportReply") -> bool:
    """Отчёт виджетом + советы текстом. False — виджет не удался, нужен обычный ответ."""
    try:
        api.call("sendWidget", {"chat_id": chat_id, "html": widget.HTML,
                                "chat_data": widget.widget_state(reply.result)})
    except TelegramError as exc:
        log.info("виджет недоступен, отвечаю текстом: %s", exc)
        return False
    api.send_message(chat_id, widget.advice_text(reply.result), reply_markup=MENU)
    return True


class Worker:
    """
    Ограниченная очередь обработки. Telegram ждёт быстрый ответ на webhook,
    а распознавание картинки может идти до минуты, поэтому отвечаем «ok»
    сразу, а работу делаем в фоне. Очередь ограничена: при наплыве лишние
    сообщения отбрасываются, а не съедают всю память.
    """

    def __init__(self, api: TelegramAPI, limiter: RateLimiter, max_pending: int = 30,
                 reputation: UrlReputation | None = None) -> None:
        self._pool = ThreadPoolExecutor(max_workers=2)
        self._api, self._limiter, self._reputation = api, limiter, reputation
        self._pending = threading.BoundedSemaphore(max_pending)

    def submit(self, update: Any) -> bool:
        if not self._pending.acquire(blocking=False):
            log.warning("очередь переполнена, сообщение пропущено")
            return False
        def task() -> None:
            try:
                process_update(update, self._api, self._limiter, self._reputation)
            finally:
                self._pending.release()
        self._pool.submit(task)
        return True


def make_handler(config: Config, api: TelegramAPI, limiter: RateLimiter,
                 worker: Worker | None = None) -> type[BaseHTTPRequestHandler]:
    secret = config.webhook_secret.encode()

    class Handler(BaseHTTPRequestHandler):
        server_version = "proverka"
        sys_version = ""  # не раскрываем версию Python
        timeout = 10  # секунд на чтение запроса: защита от «медленных» соединений

        def _reply(self, code: int, body: bytes = b"") -> None:
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 — имя задано стандартной библиотекой
            # Проверка «жив ли сервис» для хостинга.
            self._reply(200, b"ok")

        def do_POST(self) -> None:  # noqa: N802
            if self.path != WEBHOOK_PATH:
                return self._reply(404)
            got = self.headers.get("X-Telegram-Bot-Api-Secret-Token", "").encode()
            if not hmac.compare_digest(got, secret):
                return self._reply(403)
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self._reply(411)
            if length <= 0 or length > MAX_BODY:
                return self._reply(413)
            try:
                update = json.loads(self.rfile.read(length))
            except ValueError:
                return self._reply(400)
            if worker is not None:
                worker.submit(update)  # в фоне: ответ Telegram не ждёт распознавания
            else:
                process_update(update, api, limiter)
            self._reply(200, b"ok")  # всегда 200, иначе Telegram будет слать повторы

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return  # стандартный лог содержит адреса запросов — отключаем

    return Handler


def register_webhook(config: Config, api: TelegramAPI) -> None:
    """
    Сообщает Telegram адрес сервиса. Делается при каждом запуске, поэтому
    вручную запускать `set-webhook` на своём компьютере не нужно (удобно,
    если с компьютера Telegram недоступен). Сбой не роняет сервис: пробуем
    несколько раз и пишем в лог причину.
    """
    if not config.public_url:
        log.info("PUBLIC_URL не задан: webhook нужно зарегистрировать командой set-webhook")
        return
    for attempt in range(1, 4):
        try:
            api.set_webhook(config.public_url + WEBHOOK_PATH, config.webhook_secret)
            log.info("webhook зарегистрирован: %s%s", config.public_url, WEBHOOK_PATH)
            return
        except TelegramError as exc:
            log.warning("не удалось зарегистрировать webhook (попытка %d/3): %s", attempt, exc)
            time.sleep(2 * attempt)


WATCHDOG_INTERVAL = 600  # секунд (10 минут)


def check_webhook_once(config: Config, api: TelegramAPI) -> bool:
    """
    Проверяет, что Telegram шлёт сообщения именно на наш адрес; если нет
    (например, адрес переписал старый или удалённый сервис) — регистрирует
    заново. Возвращает True, если пришлось перерегистрировать.
    """
    expected = config.public_url + WEBHOOK_PATH
    try:
        current = api.get_webhook_url()
    except TelegramError as exc:
        log.warning("не удалось проверить webhook: %s", exc)
        return False
    if current == expected:
        return False
    log.warning("webhook указывает не на нас — регистрирую заново")
    register_webhook(config, api)
    return True


def webhook_watchdog(config: Config, api: TelegramAPI) -> None:
    """Регистрация при запуске + проверка каждые 10 минут (самовосстановление)."""
    register_webhook(config, api)
    if not config.public_url:
        return
    while True:
        time.sleep(WATCHDOG_INTERVAL)
        check_webhook_once(config, api)


def run_webhook(config: Config) -> None:
    api = TelegramAPI(config.token)
    # Регистрируем в отдельном потоке: сервер должен сразу начать отвечать
    # на проверки хостинга, не дожидаясь Telegram.
    threading.Thread(target=webhook_watchdog, args=(config, api), daemon=True).start()
    limiter = RateLimiter(config.rate_per_minute)
    worker = Worker(api, limiter, reputation=make_reputation(config))
    httpd = ThreadingHTTPServer(("0.0.0.0", config.port), make_handler(config, api, limiter, worker))  # noqa: S104  # nosec B104 — на хостинге слушать нужно все адреса
    httpd.daemon_threads = True
    log.info("webhook-сервер запущен на порту %d", config.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def run_polling(config: Config) -> None:
    api = TelegramAPI(config.token)
    limiter = RateLimiter(config.rate_per_minute)
    reputation = make_reputation(config)
    api.delete_webhook()  # polling и webhook одновременно работать не могут
    log.info("бот запущен (polling). Остановить: Ctrl+C")
    offset: int | None = None
    while True:
        try:
            updates = api.get_updates(offset)
        except TelegramError as exc:
            log.warning("ошибка получения сообщений: %s", exc)
            time.sleep(5)
            continue
        except KeyboardInterrupt:
            sys.exit(0)
        for upd in updates:
            if isinstance(upd, dict) and isinstance(upd.get("update_id"), int):
                offset = upd["update_id"] + 1
            process_update(upd, api, limiter, reputation)
