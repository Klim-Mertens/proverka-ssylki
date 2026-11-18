"""
Тесты проверки по базе URLhaus. Сеть НЕ используется: отправка запроса
подменяется заглушкой, которая возвращает заранее заданный ответ.
"""

import json
import logging
import urllib.error

import pytest

from proverka import analyze, format_report
from proverka.extract import parse_url
from proverka_bot.handler import HELP_TEXT, URLHAUS_NOTE, handle_update
from proverka_bot.ratelimit import RateLimiter
from proverka_bot.urlhaus import API_HOST, API_URL, UrlhausChecker

KEY = "TestKey_0123456789abcdef"


class FakeSender:
    """Запоминает запросы и отвечает по словарю {адрес API: ответ}."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, api_url, data, headers):
        self.calls.append((api_url, data, headers))
        answer = self.answers.get(api_url, {"query_status": "no_results"})
        if isinstance(answer, Exception):
            raise answer
        return answer if isinstance(answer, bytes) else json.dumps(answer).encode()


def url(raw):
    return parse_url(raw)


def test_exact_url_found_gives_high_weight():
    s = FakeSender({API_URL: {"query_status": "ok", "url_status": "online"}})
    weight, reason = UrlhausChecker(KEY, sender=s)(url("http://evil-apk.xyz/bank.apk"))
    assert weight >= 90 and "вирус" in reason
    api, data, headers = s.calls[0]
    assert api == API_URL and headers["Auth-Key"] == KEY
    assert b"evil-apk.xyz" in data


def test_host_online_and_old():
    on = FakeSender({API_HOST: {"query_status": "ok", "urls": [{"url_status": "online"}]}})
    assert UrlhausChecker(KEY, sender=on)(url("bad-site.top/x"))[0] == 80
    old = FakeSender({API_HOST: {"query_status": "ok", "urls": [{"url_status": "offline"}]}})
    assert UrlhausChecker(KEY, sender=old)(url("bad-site.top/x"))[0] == 40


def test_not_found_returns_none():
    assert UrlhausChecker(KEY, sender=FakeSender({}))(url("example.com")) is None


def test_shared_hosts_are_not_judged_by_host():
    # Одна вредная ссылка на drive.google.com не делает опасными все остальные.
    s = FakeSender({API_HOST: {"query_status": "ok", "urls": [{"url_status": "online"}]}})
    assert UrlhausChecker(KEY, sender=s)(url("https://drive.google.com/file/d/abc")) is None
    assert all(c[0] != API_HOST for c in s.calls)


@pytest.mark.parametrize("answer", [
    b"not json", b"[]", b"", urllib.error.HTTPError(API_URL, 401, "x", {}, None),
    TimeoutError(), OSError("net down"), ValueError("слишком большой ответ"),
])
def test_errors_mean_no_verdict_and_key_not_logged(answer, caplog):
    caplog.set_level(logging.WARNING)
    s = FakeSender({API_URL: answer, API_HOST: answer})
    assert UrlhausChecker(KEY, sender=s)(url("bad-site.top")) is None
    assert KEY not in caplog.text and "bad-site" not in caplog.text


def test_repr_hides_key():
    assert KEY not in repr(UrlhausChecker(KEY, sender=FakeSender({})))


def test_analyze_uses_reputation_and_skips_official_sites():
    seen = []

    def rep(u):
        seen.append(u.host)
        return (90, "Сейчас по этой ссылке распространяют вирус.")

    result = analyze("Обновите приложение: https://sberbank.ru и http://evil-apk.xyz/a", reputation=rep)
    assert seen == ["evil-apk.xyz"]  # официальный сайт никуда не отправляется
    assert result.score >= 80
    report = format_report(result)
    assert "evil-apk[.]xyz" in report and "базе опасных сайтов" in report


def test_analyze_limits_external_checks():
    calls = []
    text = " ".join(f"site{i}.xyz" for i in range(10))
    analyze(text, reputation=lambda u: calls.append(u) or None)
    assert len(calls) == 3


def test_reputation_crash_does_not_break_analysis():
    def boom(u):
        raise RuntimeError("boom")

    assert analyze("Перейдите на evil.xyz", reputation=boom).score >= 0


def test_no_reputation_means_offline_as_before():
    a = analyze("Перейдите на evil.xyz")
    b = analyze("Перейдите на evil.xyz", reputation=lambda u: None)
    assert a.score == b.score


def test_help_mentions_urlhaus_only_when_enabled():
    upd = {"message": {"chat": {"id": 1, "type": "private"}, "from": {"id": 1}, "text": "/start"}}
    assert handle_update(upd, RateLimiter(6)) == (1, HELP_TEXT)
    assert handle_update(upd, RateLimiter(6), reputation=lambda u: None) == (1, HELP_TEXT + URLHAUS_NOTE)


def test_config_urlhaus_key(monkeypatch):
    from proverka_bot.config import ConfigError, load_config

    monkeypatch.setenv("BOT_TOKEN", "123456789:" + "A" * 35)
    monkeypatch.setenv("URLHAUS_KEY", KEY)
    cfg = load_config()
    assert cfg.urlhaus_key == KEY and KEY not in repr(cfg)
    monkeypatch.setenv("URLHAUS_KEY", "bad key\r\nX-Evil: 1")
    with pytest.raises(ConfigError):
        load_config()
