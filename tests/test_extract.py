"""Тесты извлечения ссылок и телефонов."""

from proverka.extract import clean_text, extract_phones, extract_urls, parse_url


def hosts(text):
    return [u.host for u in extract_urls(text)]


def test_url_with_scheme():
    assert hosts("Перейдите: https://example.com/path?x=1") == ["example.com"]


def test_url_without_scheme_and_punctuation_around():
    assert hosts("Зайдите на (sber-bonus.ru/vhod).") == ["sber-bonus.ru"]


def test_www_url():
    assert hosts("www.ozon.ru") == ["www.ozon.ru"]


def test_cyrillic_domain():
    urls = extract_urls("сайт пример.рф")
    assert urls[0].host == "пример.рф"
    assert urls[0].host_ascii.startswith("xn--")


def test_not_urls():
    # Сокращения, e-mail, числа с точкой, обычные слова — не ссылки.
    assert hosts("т.е. и т.д. г.Москва 3.14 user@mail.ru файл.docx") == []


def test_userinfo_trick():
    url = extract_urls("http://sberbank.ru@evil.com/login")[0]
    assert url.host == "evil.com"
    assert url.has_userinfo


def test_broken_port_does_not_crash():
    url = extract_urls("http://site.ru:99999/x")[0]
    assert url.host == "site.ru"
    assert url.port is None


def test_url_limit():
    text = " ".join(f"site{i}.ru" for i in range(100))
    assert len(extract_urls(text)) == 20


def test_parse_url_empty():
    assert parse_url("   ") is None


def test_phones():
    text = "Звоните +7 (912) 345-67-89 или 8 800 555 35 35, а не 12345"
    assert extract_phones(text) == ["+79123456789", "+78005553535"]


def test_invisible_chars_removed():
    cleaned, invisible, bidi = clean_text("сбер\u200bбанк \u202eabc")
    assert cleaned == "сбербанк abc"
    assert invisible and bidi
