"""Проверка отправителя пересланных сообщений (forward_origin)."""

import pytest

from proverka import analyze
from proverka_bot.handler import handle_update
from proverka_bot.ratelimit import RateLimiter


def fwd(origin, text="Здравствуйте, по вашей карте подозрительная операция."):
    return {"message": {"chat": {"id": 7, "type": "private"}, "from": {"id": 7},
                        "text": text, "forward_origin": origin}}


def score(update):
    report = handle_update(update, RateLimiter(10))[1]
    return int(report.split("Риск: ")[1].split()[0]), report


@pytest.mark.parametrize("origin", [
    {"type": "user", "date": 1, "sender_user": {"id": 5, "is_bot": False, "first_name": "Служба безопасности", "last_name": "Сбербанка"}},
    {"type": "hidden_user", "date": 1, "sender_user_name": "Госуслуги Поддержка"},
    {"type": "user", "date": 1, "sender_user": {"id": 5, "is_bot": False, "first_name": "ВТБ", "username": "vtb_help"}},
    # Латинская «е» в «Сбeрбанк» не спасает — имя нормализуется.
    {"type": "user", "date": 1, "sender_user": {"id": 5, "is_bot": False, "first_name": "Сбeрбанк"}},
])
def test_personal_account_named_as_bank_is_flagged(origin):
    value, report = score(fwd(origin))
    assert value >= 50 and "личных аккаунтов" in report


@pytest.mark.parametrize("origin", [
    {"type": "user", "date": 1, "sender_user": {"id": 5, "is_bot": False, "first_name": "Максим", "last_name": "Банков"}},
    {"type": "user", "date": 1, "sender_user": {"id": 5, "is_bot": False, "first_name": "Мама"}},
    {"type": "hidden_user", "date": 1, "sender_user_name": "Макс"},
    {"type": "channel", "date": 1, "chat": {"id": -1, "type": "channel", "title": "СберБанк"}, "message_id": 3},
])
def test_ordinary_senders_and_channels_not_flagged(origin):
    _, report = score(fwd(origin, text="Привет, как дела?"))
    assert "аккаунт" not in report and "бота" not in report


def test_bot_with_bank_name_is_mild():
    origin = {"type": "user", "date": 1, "sender_user": {"id": 5, "is_bot": True, "first_name": "Sber Support Bot"}}
    _, report = score(fwd(origin, text="Привет"))
    assert "бота с названием банка" in report


@pytest.mark.parametrize("origin", [None, "x", 5, {"type": "user"}, {"type": "user", "sender_user": "bad"},
                                    {"type": "hidden_user", "sender_user_name": 42}, {"type": "zzz"},
                                    {"type": "user", "sender_user": {"first_name": "Банк" * 1000}}])
def test_garbage_origin_does_not_crash(origin):
    handle_update(fwd(origin), RateLimiter(10))


def test_name_is_not_echoed_in_report():
    origin = {"type": "hidden_user", "date": 1, "sender_user_name": "Банк evil-site.ru"}
    _, report = score(fwd(origin))
    assert "evil-site" not in report


def test_analyze_without_sender_unchanged():
    t = "Здравствуйте, по вашей карте подозрительная операция."
    assert analyze(t).score == analyze(t, forwarded_from=("channel", "Сбер")).score
