"""Тесты Telegram-бота (без настоящей сети и без настоящего токена)."""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from proverka_bot.config import Config, ConfigError, load_config
from proverka_bot.handler import EMPTY_TEXT, HELP_TEXT, PRIVATE_ONLY_TEXT, RATE_TEXT, handle_update
from proverka_bot.ratelimit import RateLimiter
from proverka_bot.server import make_handler
from proverka_bot.telegram_api import TelegramAPI, TelegramError

FAKE_TOKEN = "123456789:" + "A" * 35
SECRET = "s" * 32


def msg(text=None, chat_type="private", user_id=1, **extra):
    m = {"chat": {"id": 10, "type": chat_type}, "from": {"id": user_id, "is_bot": False}}
    if text is not None:
        m["text"] = text
    m.update(extra)
    return {"update_id": 1, "message": m}


def limiter():
    return RateLimiter(per_minute=3)


def test_start_and_help():
    assert handle_update(msg("/start"), limiter()) == (10, HELP_TEXT)
    assert handle_update(msg("/help@proverka_bot"), limiter()) == (10, HELP_TEXT)


def test_scam_gets_report():
    chat_id, text = handle_update(
        msg("Ваша карта заблокирована! Срочно: sberbank-help.ru"), limiter())
    assert chat_id == 10 and "Риск:" in text and "sberbank-help[.]ru" in text


def test_hidden_link_in_entities_is_checked():
    upd = msg("Получите выплату тут", entities=[
        {"type": "text_link", "offset": 17, "length": 3, "url": "https://gosuslugi-pay.ru/x"}])
    _, text = handle_update(upd, limiter())
    assert "gosuslugi-pay[.]ru" in text


def test_caption_is_checked():
    upd = msg(None, caption="Срочно сообщите код из смс")
    assert "Риск:" in handle_update(upd, limiter())[1]


def test_no_text_gets_hint():
    assert handle_update(msg(None), limiter()) == (10, EMPTY_TEXT)


def test_group_chat_gets_private_only():
    assert handle_update(msg("привет", chat_type="group"), limiter()) == (10, PRIVATE_ONLY_TEXT)


@pytest.mark.parametrize("bad", [
    None, [], "x", 5, {}, {"message": None}, {"message": "x"}, {"message": {}},
    {"message": {"chat": {"id": "a"}, "from": {"id": 1}}},
    {"message": {"chat": {"id": 1, "type": "private"}, "from": {"id": 1, "is_bot": True}, "text": "x"}},
    {"message": {"chat": {"id": 1, "type": "private"}, "from": {"id": 1}, "text": 123}},
    {"message": {"chat": {"id": 1, "type": "private"}, "from": {"id": 1}, "text": "x",
                 "entities": ["a", None, {"type": "text_link", "url": 5}]}},
])
def test_garbage_updates_do_not_crash(bad):
    handle_update(bad, limiter())


def test_rate_limit():
    lim = limiter()
    for _ in range(3):
        assert handle_update(msg("привет"), lim)[1] != RATE_TEXT
    assert handle_update(msg("привет"), lim)[1] == RATE_TEXT
    # другой человек не страдает
    assert handle_update(msg("привет", user_id=2), lim)[1] != RATE_TEXT


def test_ratelimiter_recovers_and_is_bounded():
    lim = RateLimiter(per_minute=1, max_users=5)
    assert lim.allow(1, now=0) and not lim.allow(1, now=10) and lim.allow(1, now=61)
    for uid in range(100):
        lim.allow(uid, now=0)
    assert len(lim._hits) <= 5


# --- Настройки ---------------------------------------------------------------

def test_config_requires_valid_token(monkeypatch):
    monkeypatch.delenv("BOT_TOKEN", raising=False)
    with pytest.raises(ConfigError):
        load_config()
    monkeypatch.setenv("BOT_TOKEN", "bad")
    with pytest.raises(ConfigError):
        load_config()


def test_config_secret_and_repr(monkeypatch):
    monkeypatch.setenv("BOT_TOKEN", FAKE_TOKEN)
    monkeypatch.setenv("WEBHOOK_SECRET", "short")
    load_config()  # для polling секрет не нужен
    with pytest.raises(ConfigError):
        load_config(need_webhook_secret=True)
    monkeypatch.setenv("WEBHOOK_SECRET", SECRET)
    cfg = load_config(need_webhook_secret=True)
    assert FAKE_TOKEN not in repr(cfg) and SECRET not in repr(cfg)


def test_config_bad_port(monkeypatch):
    monkeypatch.setenv("BOT_TOKEN", FAKE_TOKEN)
    monkeypatch.setenv("PORT", "abc")
    with pytest.raises(ConfigError):
        load_config()
    monkeypatch.setenv("PORT", "70000")
    with pytest.raises(ConfigError):
        load_config()


# --- Telegram API: токен не должен утекать ------------------------------------

def test_api_errors_do_not_leak_token(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.URLError(f"https://api.telegram.org/bot{FAKE_TOKEN}/x failed")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with pytest.raises(TelegramError) as info:
        TelegramAPI(FAKE_TOKEN).send_message(1, "hi")
    assert FAKE_TOKEN not in str(info.value)
    assert info.value.__cause__ is None and info.value.__suppress_context__


def test_long_message_truncated(monkeypatch):
    sent = {}
    monkeypatch.setattr(TelegramAPI, "call", lambda self, m, p, timeout=None: sent.update(p))
    TelegramAPI(FAKE_TOKEN).send_message(1, "я" * 9000)
    assert len(sent["text"]) == 4096 and sent["disable_web_page_preview"] is True
    assert "parse_mode" not in sent


# --- Webhook-сервер: настоящий HTTP на localhost -------------------------------

class FakeAPI:
    def __init__(self):
        self.sent = []

    def send_message(self, chat_id, text, reply_markup=None):
        self.sent.append((chat_id, text))


@pytest.fixture()
def server():
    api = FakeAPI()
    cfg = Config(token=FAKE_TOKEN, webhook_secret=SECRET)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cfg, api, RateLimiter(5)))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", api
    httpd.shutdown()
    httpd.server_close()


def post(base, path="/webhook", body=b"{}", headers=None):
    req = urllib.request.Request(base + path, data=body, headers=headers or {}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_webhook_rejects_without_secret(server):
    base, api = server
    body = json.dumps(msg("Срочно сообщите код из смс")).encode()
    assert post(base, body=body) == 403
    assert post(base, body=body, headers={"X-Telegram-Bot-Api-Secret-Token": "wrong"}) == 403
    assert api.sent == []


def test_webhook_accepts_with_secret(server):
    base, api = server
    body = json.dumps(msg("Срочно сообщите код из смс")).encode()
    assert post(base, body=body, headers={"X-Telegram-Bot-Api-Secret-Token": SECRET}) == 200
    assert len(api.sent) == 1 and "Риск:" in api.sent[0][1]


def test_webhook_bad_requests(server):
    base, _ = server
    h = {"X-Telegram-Bot-Api-Secret-Token": SECRET}
    assert post(base, path="/other", headers=h) == 404
    assert post(base, body=b"not json", headers=h) == 400
    assert post(base, body=b"x" * (300 * 1024), headers=h) == 413


def test_health_and_no_version_leak(server):
    base, _ = server
    with urllib.request.urlopen(base + "/", timeout=5) as r:
        assert r.status == 200
        assert "Python" not in (r.headers.get("Server") or "")


# --- Автоматическая регистрация webhook ----------------------------------------

def test_register_webhook_calls_telegram(monkeypatch):
    from proverka_bot.server import register_webhook

    calls = []

    class Api:
        def set_webhook(self, url, secret):
            calls.append((url, secret))

    register_webhook(Config(token=FAKE_TOKEN, webhook_secret=SECRET, public_url="https://x.onrender.com"), Api())
    assert calls == [("https://x.onrender.com/webhook", SECRET)]


def test_register_webhook_skipped_without_url():
    from proverka_bot.server import register_webhook

    class Api:
        def set_webhook(self, url, secret):
            raise AssertionError("не должно вызываться")

    register_webhook(Config(token=FAKE_TOKEN, webhook_secret=SECRET), Api())


def test_register_webhook_survives_errors(monkeypatch):
    import proverka_bot.server as srv

    monkeypatch.setattr(srv.time, "sleep", lambda s: None)
    attempts = []

    class Api:
        def set_webhook(self, url, secret):
            attempts.append(1)
            raise TelegramError("setWebhook: URLError")

    srv.register_webhook(Config(token=FAKE_TOKEN, webhook_secret=SECRET, public_url="https://x.io"), Api())
    assert len(attempts) == 3  # три попытки, и сервис не упал


def test_public_url_from_env(monkeypatch):
    monkeypatch.setenv("BOT_TOKEN", FAKE_TOKEN)
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    monkeypatch.setenv("RENDER_EXTERNAL_URL", "https://abc.onrender.com/")
    assert load_config().public_url == "https://abc.onrender.com"
    monkeypatch.setenv("PUBLIC_URL", "http://insecure.example")
    with pytest.raises(ConfigError):
        load_config()


def test_error_message_shows_reason_type_without_token(monkeypatch):
    import ssl

    def boom(*a, **k):
        raise urllib.error.URLError(ssl.SSLCertVerificationError("self-signed"))

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with pytest.raises(TelegramError) as info:
        TelegramAPI(FAKE_TOKEN).send_message(1, "hi")
    assert "SSLCertVerificationError" in str(info.value)
    assert FAKE_TOKEN not in str(info.value)


def test_worker_processes_in_background_and_limits_queue():
    import time as _t
    from proverka_bot.server import Worker

    api = FakeAPI()
    worker = Worker(api, RateLimiter(100), max_pending=2)
    assert worker.submit(msg("Срочно сообщите код из смс"))
    for _ in range(50):
        if api.sent:
            break
        _t.sleep(0.05)
    assert api.sent and "Риск:" in api.sent[0][1]

    blocker = threading.Event()
    import proverka_bot.server as srv
    orig = srv.process_update
    srv.process_update = lambda *a: blocker.wait(2)
    try:
        assert worker.submit({}) and worker.submit({})
        assert not worker.submit({})  # очередь полна — третье отброшено
    finally:
        blocker.set()
        srv.process_update = orig



def test_watchdog_reregisters_when_url_differs():
    from proverka_bot.server import check_webhook_once

    calls = []

    class Api:
        def __init__(self, url):
            self.url = url

        def get_webhook_url(self):
            return self.url

        def set_webhook(self, url, secret):
            calls.append(url)

    cfg = Config(token=FAKE_TOKEN, webhook_secret=SECRET, public_url="https://new.onrender.com")
    assert check_webhook_once(cfg, Api("https://new.onrender.com/webhook")) is False
    assert calls == []
    assert check_webhook_once(cfg, Api("https://old-deleted.onrender.com/webhook")) is True
    assert calls == ["https://new.onrender.com/webhook"]


def test_watchdog_survives_telegram_errors():
    from proverka_bot.server import check_webhook_once

    class Api:
        def get_webhook_url(self):
            raise TelegramError("getWebhookInfo: URLError")

    cfg = Config(token=FAKE_TOKEN, webhook_secret=SECRET, public_url="https://x.io")
    assert check_webhook_once(cfg, Api()) is False


# --- Кнопки-памятки -------------------------------------------------------------

import proverka_bot.server as srv
from proverka_bot.memos import BTN_PHONES, BTN_SIGNS, BTN_SOS, MENU, PHONES_TEXT, SIGNS_TEXT, SOS_TEXT


@pytest.mark.parametrize("pressed,expected", [
    (BTN_SOS, SOS_TEXT), (BTN_SIGNS, SIGNS_TEXT), (BTN_PHONES, PHONES_TEXT),
    ("  " + BTN_SOS + "  ", SOS_TEXT), ("/sos", SOS_TEXT), ("/telefony@proverka_bot", PHONES_TEXT),
])
def test_memo_buttons(pressed, expected):
    assert handle_update(msg(pressed), limiter()) == (10, expected)


def test_memo_not_rate_limited():
    lim = RateLimiter(1)
    handle_update(msg("привет"), lim)
    assert handle_update(msg("привет"), lim)[1] == RATE_TEXT
    assert handle_update(msg(BTN_SOS), lim)[1] == SOS_TEXT


def test_text_containing_button_words_is_still_checked():
    # Только точное нажатие кнопки даёт памятку; сообщение мошенника,
    # в котором есть те же слова, проверяется как обычно.
    _, text = handle_update(msg(BTN_SOS + " срочно назовите код из СМС"), limiter())
    assert "Риск:" in text


def test_menu_attached_in_private_but_not_in_groups():
    class API:
        def __init__(self):
            self.markups = []

        def send_message(self, chat_id, text, reply_markup=None):
            self.markups.append(reply_markup)

    api = API()
    srv.process_update(msg("привет"), api, RateLimiter(5))
    srv.process_update(msg("привет", chat_type="group"), api, RateLimiter(5))
    assert api.markups == [MENU, None]


def test_memo_phones_are_official():
    for number in ("102", "112", "300", "8 800 300-30-00", "115"):
        assert number in PHONES_TEXT
