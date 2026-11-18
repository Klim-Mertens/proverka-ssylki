"""MAX-версия: перевод событий, кнопки-памятки, безопасность разбора."""
from __future__ import annotations

from proverka_bot.memos import BTN_SOS
from proverka_bot.ratelimit import RateLimiter
from proverka_max.__main__ import process
from proverka_max.convert import PHOTO_TEXT, to_telegram_update


class FakeAPI:
    def __init__(self):
        self.sent, self.answered = [], []

    def send_message(self, user_id, text, buttons=None):
        self.sent.append((user_id, text, buttons))

    def answer_callback(self, callback_id):
        self.answered.append(callback_id)


def msg(text, user=7, chat_type="dialog", link=None, attachments=None):
    m = {"sender": {"user_id": user, "is_bot": False}, "recipient": {"chat_type": chat_type},
         "body": {"text": text, "attachments": attachments}}
    if link:
        m["link"] = link
    return {"update_type": "message_created", "message": m}


def test_scam_message_gets_report_with_buttons():
    api = FakeAPI()
    process(msg("Ваша карта заблокирована! Срочно: sberbank-help.ru"), api, RateLimiter(10))
    uid, text, buttons = api.sent[0]
    assert uid == 7 and "Риск" in text and buttons


def test_forwarded_text_is_checked():
    api = FakeAPI()
    process(msg("", link={"type": "forward", "message": {"text": "Мама, это мой новый номер, переведи 5000"}}),
            api, RateLimiter(10))
    assert "Риск" in api.sent[0][1]


def test_memo_button_and_callback_ack():
    api = FakeAPI()
    ev = {"update_type": "message_callback",
          "callback": {"callback_id": "cb1", "payload": BTN_SOS, "user": {"user_id": 7}}}
    process(ev, api, RateLimiter(10))
    assert api.answered == ["cb1"] and "Что делать" in api.sent[0][1]


def test_unknown_callback_payload_ignored():
    api = FakeAPI()
    ev = {"update_type": "message_callback",
          "callback": {"callback_id": "cb2", "payload": "../../admin", "user": {"user_id": 7}}}
    process(ev, api, RateLimiter(10))
    assert api.answered == ["cb2"] and api.sent == []


def test_group_chat_not_answered_with_report():
    api = FakeAPI()
    process(msg("sberbank-help.ru", chat_type="chat"), api, RateLimiter(10))
    assert all("Риск" not in t for _, t, _ in api.sent)


def test_photo_without_text():
    upd, _, _ = to_telegram_update(msg("", attachments=[{"type": "image", "payload": {"url": "x"}}]))
    assert upd == {"_reply": PHOTO_TEXT}


def test_garbage_events_are_ignored():
    api = FakeAPI()
    for ev in (None, [], {"update_type": "message_created"}, {"update_type": "message_created", "message": "x"},
               {"update_type": "message_created", "message": {"sender": {"user_id": "7"}}},
               {"update_type": "bot_started", "user": {"user_id": 1, "is_bot": True}}):
        process(ev, api, RateLimiter(10))
    assert api.sent == []


def test_rate_limit():
    api = FakeAPI()
    lim = RateLimiter(2)
    for _ in range(4):
        process(msg("проверь sberbank-help.ru"), api, lim)
    assert any("Слишком много" in t for _, t, _ in api.sent)
