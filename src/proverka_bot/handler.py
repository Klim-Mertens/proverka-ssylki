"""
Разбор сообщений Telegram и составление ответа. Здесь нет сети: функция
получает «update» (словарь от Telegram) и возвращает текст ответа, поэтому
её легко тестировать.

Приватность: текст сообщения не сохраняется и не пишется в логи.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from proverka import analyze, format_report
from proverka.extract import parse_url
from proverka.models import CheckResult
from proverka.url_rules import defang
from proverka.analyzer import SENDER_BOT, SENDER_CHANNEL, SENDER_HIDDEN, SENDER_USER, UrlReputation

from . import ocr
from .memos import memo_for
from .ratelimit import RateLimiter

# Максимум символов, которые мы читаем. Ядро тоже ограничивает, но
# отсекаем лишнее как можно раньше.
MAX_INPUT = 10_000

HELP_TEXT = (
    "Здравствуйте! Я помогаю понять, не мошенники ли вам написали.\n\n"
    "Просто перешлите мне подозрительное сообщение, вставьте его текст "
    "или пришлите снимок экрана — я оценю риск от 0 до 100 и объясню "
    "простыми словами почему.\n\n"
    "• Ссылки я не открываю — проверяю только их текст.\n"
    "• Ваши сообщения я не сохраняю.\n"
    "• Моя оценка — подсказка, а не гарантия. Сомневаетесь — посоветуйтесь с близкими "
    "или позвоните в банк по номеру на карте.\n\n"
    "Никому не называйте коды из СМС и пароли — даже мне.\n\n"
    "Внизу есть кнопки-памятки: что делать, если вы уже перевели деньги, "
    "как распознать мошенника и куда звонить."
)

# Добавляется к приветствию, только если проверка по базе включена:
# человек должен знать, что адрес ссылки уходит стороннему сервису.
URLHAUS_NOTE = (
    "\n\nℹ️ Адреса ссылок (только адреса, без текста сообщения) я сверяю с "
    "бесплатной международной базой опасных сайтов URLhaus (abuse.ch, Швейцария)."
)

RATE_TEXT = "Слишком много сообщений подряд. Подождите минуту и попробуйте снова."
EMPTY_TEXT = ("Пришлите, пожалуйста, текст сообщения (можно переслать его сюда) "
              "или снимок экрана как фото.")
NO_OCR_TEXT = ("Пока я не умею читать картинки. Пришлите, пожалуйста, текст "
               "сообщения (можно переслать его сюда).")
DOCUMENT_TEXT = ("Пришлите снимок экрана как обычное фото (не файлом) — "
                 "тогда я смогу прочитать текст на нём.")
OCR_WAIT_TEXT = "Читаю текст на картинке, это займёт до минуты…"
OCR_FAIL_TEXT = ("Не получилось прочитать текст на картинке. Попробуйте прислать "
                 "снимок крупнее или перешлите само сообщение текстом.")


class ReportReply(tuple):
    """Ответ-отчёт: ведёт себя как (chat_id, текст), но несёт и сам результат
    проверки — он нужен, чтобы показать отчёт виджетом (см. widget.py)."""

    result: CheckResult

    def __new__(cls, chat_id: int, text: str, result: CheckResult) -> "ReportReply":
        obj = super().__new__(cls, (chat_id, text))
        obj.result = result
        return obj


@dataclass(frozen=True)
class OcrJob:
    """Задание: распознать фото и проверить текст. Выполняет server.py."""

    chat_id: int
    file_id: str
    caption: str
    links: tuple[str, ...]
    forwarded_from: tuple[str, str] | None = None


def report_for_ocr_text(text: str, job: OcrJob, reputation: UrlReputation | None = None,
                        qr_links: list[str] | None = None) -> str:
    """Отчёт по тексту, распознанному с картинки (плюс подпись к фото и QR-коды)."""
    qr_links = qr_links or []
    full = (job.caption + "\n" + text).strip()[:MAX_INPUT]
    if len(full) < 5 and not qr_links:
        return OCR_FAIL_TEXT
    # Куда ведут QR-коды: показываем только «обезвреженное» имя сайта.
    qr_lines = ""
    for link in qr_links:
        parsed = parse_url(link)
        if parsed is not None:
            qr_lines += "🔳 QR-код на картинке ведёт на сайт: " + defang(parsed.host) + "\n"
    if qr_lines:
        qr_lines += "\n"
    # Показываем, что именно удалось прочитать: человек увидит, если
    # распознавание ошиблось, и сможет прислать текст вручную.
    preview = " ".join(text.split())
    if len(preview) > 300:
        preview = preview[:300] + "…"
    head = ("📷 Текст на картинке (как я его прочитал):\n«" + preview + "»\n\n") if preview else ""
    return (head + qr_lines
            + format_report(analyze(full, extra_urls=list(job.links) + qr_links, reputation=reputation,
                                    forwarded_from=job.forwarded_from)))
PRIVATE_ONLY_TEXT = "Я работаю только в личной переписке. Напишите мне напрямую."


def _collect_links(message: dict[str, Any]) -> list[str]:
    """
    Ссылки, спрятанные под словами («нажмите тут»), в тексте не видны, но
    Telegram присылает их отдельно в `entities`. Достаём их, иначе самый
    частый приём мошенников остался бы незамеченным.
    Границы entities считаются в единицах UTF-16, поэтому для обычных
    ссылок (type == "url") просто не вырезаем текст, а скрытые берём из
    поля `url`.
    """
    links: list[str] = []
    entities = (message.get("entities") or []) + (message.get("caption_entities") or [])
    for ent in entities[:100]:  # не больше 100 штук
        if not isinstance(ent, dict):
            continue
        if ent.get("type") == "text_link" and isinstance(ent.get("url"), str):
            links.append(ent["url"][:2000])
    return links


def _forward_origin(message: dict[str, Any]) -> tuple[str, str] | None:
    """
    От кого переслано сообщение (поле forward_origin, Bot API 7.0+).
    Возвращает (тип, имя) или None. Данные приходят из интернета, поэтому
    проверяем каждый тип и обрезаем длину.
    """
    origin = message.get("forward_origin")
    if not isinstance(origin, dict):
        return None
    kind = origin.get("type")
    if kind == "user":
        user = origin.get("sender_user")
        if not isinstance(user, dict):
            return None
        parts = [user.get("first_name"), user.get("last_name"), user.get("username")]
        name = " ".join(p for p in parts if isinstance(p, str))
        return (SENDER_BOT if user.get("is_bot") is True else SENDER_USER, name[:200])
    if kind == "hidden_user":
        hidden_name = origin.get("sender_user_name")
        return (SENDER_HIDDEN, hidden_name[:200]) if isinstance(hidden_name, str) else None
    if kind in ("chat", "channel"):
        chat = origin.get("sender_chat") if kind == "chat" else origin.get("chat")
        if not isinstance(chat, dict):
            return None
        parts = [chat.get("title"), chat.get("username")]
        return (SENDER_CHANNEL, " ".join(p for p in parts if isinstance(p, str))[:200])
    return None


def handle_update(update: Any, limiter: RateLimiter,
                  reputation: UrlReputation | None = None) -> tuple[int, str] | OcrJob | None:
    """
    Возвращает (chat_id, текст_ответа) или None, если отвечать не нужно.
    Любой неожиданный формат данных обрабатываем спокойно: update приходит
    из интернета, ему нельзя доверять.
    """
    if not isinstance(update, dict):
        return None
    message = update.get("message")
    if not isinstance(message, dict):
        return None
    chat = message.get("chat")
    sender = message.get("from")
    if not isinstance(chat, dict) or not isinstance(sender, dict):
        return None
    chat_id = chat.get("id")
    user_id = sender.get("id")
    if not isinstance(chat_id, int) or not isinstance(user_id, int) or sender.get("is_bot"):
        return None
    # В группах не отвечаем: иначе бот станет спамить и читать чужие разговоры.
    if chat.get("type") != "private":
        return (chat_id, PRIVATE_ONLY_TEXT)

    # Фото (снимок экрана): распознаём текст, если на сервере есть Tesseract.
    if "photo" in message:
        if not ocr.is_available():
            return (chat_id, NO_OCR_TEXT)
        file_id = ocr.pick_photo(message.get("photo"))
        if file_id is None:
            return (chat_id, OCR_FAIL_TEXT)
        if not limiter.allow(user_id):
            return (chat_id, RATE_TEXT)
        caption = message.get("caption")
        return OcrJob(chat_id, file_id,
                      caption[:MAX_INPUT] if isinstance(caption, str) else "",
                      tuple(_collect_links(message)), _forward_origin(message))
    document = message.get("document")
    if isinstance(document, dict) and str(document.get("mime_type", "")).startswith("image/"):
        return (chat_id, DOCUMENT_TEXT)

    raw = message.get("text")
    if not isinstance(raw, str):
        raw = message.get("caption")  # подпись к файлу/видео
    if not isinstance(raw, str) or not raw.strip():
        return (chat_id, EMPTY_TEXT)

    text = raw[:MAX_INPUT]
    stripped = text.strip()
    if stripped.split(maxsplit=1)[0].split("@")[0] in ("/start", "/help"):
        return (chat_id, HELP_TEXT if reputation is None else HELP_TEXT + URLHAUS_NOTE)

    # Нажатие кнопки-памятки: отвечаем сразу, без проверки и без лимита —
    # человеку, у которого беда, нельзя отвечать «подождите минуту».
    memo = memo_for(stripped)
    if memo is not None:
        return (chat_id, memo)

    if not limiter.allow(user_id):
        return (chat_id, RATE_TEXT)

    result = analyze(text, extra_urls=_collect_links(message), reputation=reputation,
                     forwarded_from=_forward_origin(message))
    return ReportReply(chat_id, format_report(result), result)
