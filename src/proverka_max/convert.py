"""
Перевод событий MAX в формат сообщения Telegram, который понимает
proverka_bot.handler.handle_update. Так вся логика (лимиты, памятки, отчёт)
остаётся в одном месте и уже покрыта тестами.

События приходят из интернета — любые поля проверяем на тип.
"""

from __future__ import annotations

from typing import Any

from proverka_bot.memos import BTN_PHONES, BTN_SIGNS, BTN_SOS

# Кнопки-памятки: в MAX нет постоянной клавиатуры под полем ввода, поэтому
# используем inline-кнопки. payload — это текст кнопки, его распознаёт memo_for().
MENU_BUTTONS: list[list[dict[str, Any]]] = [
    [{"type": "callback", "text": BTN_SOS, "payload": BTN_SOS, "intent": "negative"}],
    [{"type": "callback", "text": BTN_SIGNS, "payload": BTN_SIGNS},
     {"type": "callback", "text": BTN_PHONES, "payload": BTN_PHONES}],
]
_ALLOWED_PAYLOADS = {BTN_SOS, BTN_SIGNS, BTN_PHONES}

PHOTO_TEXT = ("В MAX я пока не читаю картинки. Пришлите, пожалуйста, текст сообщения "
              "(можно переслать его сюда).")


def _user_id(obj: Any) -> int | None:
    if isinstance(obj, dict) and not obj.get("is_bot"):
        uid = obj.get("user_id")
        if isinstance(uid, int):
            return uid
    return None


def to_telegram_update(event: Any) -> tuple[dict[str, Any] | None, str | None, int | None]:
    """
    Возвращает (update_для_handler, callback_id, user_id).
    update = None — отвечать не нужно; callback_id — если надо подтвердить нажатие.
    """
    if not isinstance(event, dict):
        return None, None, None
    kind = event.get("update_type")

    if kind == "bot_started":
        uid = _user_id(event.get("user"))
        return (_msg(uid, "/start") if uid else None), None, uid

    if kind == "message_callback":
        cb = event.get("callback")
        if not isinstance(cb, dict):
            return None, None, None
        uid = _user_id(cb.get("user"))
        payload = cb.get("payload")
        callback_id = cb.get("callback_id") if isinstance(cb.get("callback_id"), str) else None
        if uid is None or payload not in _ALLOWED_PAYLOADS:   # чужие payload игнорируем
            return None, callback_id, uid
        return _msg(uid, payload), callback_id, uid

    if kind != "message_created":
        return None, None, None
    message = event.get("message")
    if not isinstance(message, dict):
        return None, None, None
    recipient = message.get("recipient") if isinstance(message.get("recipient"), dict) else {}
    uid = _user_id(message.get("sender"))
    if uid is None:
        return None, None, None
    chat_type = "private" if recipient.get("chat_type") in (None, "dialog") else "group"

    body = message.get("body") if isinstance(message.get("body"), dict) else {}
    text = body.get("text") if isinstance(body.get("text"), str) else ""
    # Пересланное сообщение: его текст лежит в link.message.text
    link = message.get("link") if isinstance(message.get("link"), dict) else {}
    linked = link.get("message") if isinstance(link.get("message"), dict) else {}
    fwd_text = linked.get("text") if isinstance(linked.get("text"), str) else ""
    full = "\n".join(t for t in (text, fwd_text) if t)

    attachments = body.get("attachments") if isinstance(body.get("attachments"), list) else []
    if not full and any(isinstance(a, dict) and a.get("type") == "image" for a in attachments):
        return {"_reply": PHOTO_TEXT}, None, uid

    # Отправителя пересланного сообщения не передаём: проверки «кто прислал»
    # настроены на данные Telegram, а неполные данные MAX дали бы ложные признаки.
    return _msg(uid, full, chat_type), None, uid


def _msg(uid: int, text: str, chat_type: str = "private") -> dict[str, Any]:
    return {"update_id": 0, "message": {
        "message_id": 0, "date": 0, "text": text,
        "chat": {"id": uid, "type": chat_type},
        "from": {"id": uid, "is_bot": False, "first_name": ""},
    }}
