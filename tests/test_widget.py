"""Отчёт виджетом (Bot API 10.4): состояние, запасной текстовый режим."""
from __future__ import annotations

import json
import zlib

from proverka import analyze
from proverka_bot import server, widget
from proverka_bot.ratelimit import RateLimiter
from proverka_bot.telegram_api import TelegramError

SCAM = "Ваша карта заблокирована! Срочно назовите код из СМС: sberbank-help.ru"


def update(text):
    return {"update_id": 1, "message": {"message_id": 1, "date": 0, "text": text,
            "chat": {"id": 5, "type": "private"}, "from": {"id": 5, "is_bot": False, "first_name": "A"}}}


class FakeAPI:
    def __init__(self, widget_fails=False):
        self.calls, self.fail = [], widget_fails

    def call(self, method, params, timeout=None):
        if method == "sendWidget" and self.fail:
            raise TelegramError("Bad Request: method not found")
        self.calls.append((method, params))

    def send_message(self, chat_id, text, reply_markup=None):
        self.calls.append(("sendMessage", {"text": text, "reply_markup": reply_markup}))


def test_widget_fits_limits():
    raw = widget.HTML.encode()
    assert len(raw) <= 32768 and len(zlib.compress(raw, 9)) <= 4096
    assert "innerHTML" not in widget.HTML and "request(" not in widget.HTML


def test_state_has_no_message_text_and_fits():
    result = analyze(SCAM + " " + "очень длинный текст " * 200)
    state = widget.widget_state(result)
    assert len(state.encode()) <= 1024
    data = json.loads(state)
    assert data["s"] == result.score and data["r"]
    assert "очень длинный текст" not in state


def test_widget_sent_when_enabled(monkeypatch):
    monkeypatch.setattr(widget, "ENABLED", True)
    api = FakeAPI()
    server.process_update(update(SCAM), api, RateLimiter(10))
    methods = [m for m, _ in api.calls]
    assert methods == ["sendWidget", "sendMessage"]
    assert "allow_queries" not in api.calls[0][1]          # виджет не может слать запросы
    assert api.calls[1][1]["reply_markup"] is not None     # кнопки-памятки на месте


def test_fallback_to_text(monkeypatch):
    monkeypatch.setattr(widget, "ENABLED", True)
    api = FakeAPI(widget_fails=True)
    server.process_update(update(SCAM), api, RateLimiter(10))
    assert [m for m, _ in api.calls] == ["sendMessage"] and "Почему" in api.calls[0][1]["text"]


def test_disabled_by_default():
    api = FakeAPI()
    server.process_update(update(SCAM), api, RateLimiter(10))
    assert [m for m, _ in api.calls] == ["sendMessage"]
