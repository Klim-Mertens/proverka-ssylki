"""Тесты проверок ссылок."""

import pytest

from proverka.extract import parse_url
from proverka.url_rules import check_url, defang, registered_domain


def ids(raw):
    signals, _ = check_url(parse_url(raw))
    return {s.rule_id for s in signals}


@pytest.mark.parametrize("raw", [
    "https://sberbank-bonus.ru",
    "https://gosuslugi.ru.secure-login.com",
    "http://my-gosuslugi.online/login",
    "https://wildberries-sale.shop",
])
def test_brand_impersonation(raw):
    assert "brand_impersonation" in ids(raw)


@pytest.mark.parametrize("raw", [
    "https://sberbamk.ru",        # опечатка
    "https://sb3rbank.ru",        # цифра вместо буквы
    "https://gosuslugl.ru",       # l вместо i
    "https://tinkof.ru",          # пропущена буква
])
def test_brand_lookalike(raw):
    assert "brand_lookalike" in ids(raw)


def test_homoglyph_cyrillic_in_latin_domain():
    found = ids("https://sberbаnk.ru")  # «а» — кириллическая
    assert {"mixed_scripts", "brand_lookalike"} <= found


@pytest.mark.parametrize("raw", [
    "https://www.sberbank.ru/ru/person",
    "https://online.sberbank.ru",
    "https://www.gosuslugi.ru",
    "https://www.ozon.ru/product/123",
    "https://yandex.ru/maps",
    "https://example.com",
    "https://video.ru",           # не путать с mvideo
    "https://smartbank.com",      # не путать с tbank
    "https://пример.рф",          # обычный кириллический домен
])
def test_clean_urls_have_no_strong_signals(raw):
    signals, _ = check_url(parse_url(raw))
    assert all(s.weight < 20 for s in signals), signals


def test_official_note():
    _, notes = check_url(parse_url("https://www.gosuslugi.ru"))
    assert any("официальный" in n for n in notes)


def test_user_content_note():
    _, notes = check_url(parse_url("https://t.me/some_channel"))
    assert any("кто угодно" in n for n in notes)


@pytest.mark.parametrize("raw", [
    "http://185.10.20.30/login",
    "http://[2001:db8::1]/x",
    "http://3232235777/",
])
def test_ip(raw):
    assert "ip_host" in ids(raw)


def test_shortener():
    assert "shortener" in ids("https://bit.ly/abc")
    assert "shortener" in ids("https://clck.ru/xyz")


def test_dangerous_file():
    assert "dangerous_file" in ids("https://files.example.com/bank.apk?x=1")


def test_port_and_http():
    assert {"odd_port", "no_https"} <= ids("http://example.com:8080/")


def test_free_hosting():
    assert "free_hosting" in ids("https://bank-login.netlify.app")


def test_punycode_outside_rf():
    assert "punycode" in ids("https://раураӏ.com")


def test_registered_domain():
    assert registered_domain("a.b.sberbank.ru") == "sberbank.ru"
    assert registered_domain("shop.site.com.ru") == "site.com.ru"


def test_defang():
    assert defang("evil.com") == "evil[.]com"
