"""Тесты итоговой оценки на реалистичных сообщениях."""

import socket
import time

import pytest

from proverka import analyze, format_report

SCAMS = [
    "Ваша карта заблокирована из-за подозрительной операции. Срочно перейдите "
    "по ссылке sberbank-unblock.ru и введите данные карты.",
    "Здравствуйте, служба безопасности банка. На ваше имя оформлен кредит. "
    "Переведите все свои деньги на безопасный счёт и никому не рассказывайте "
    "о нашем разговоре.",
    "Вам положена компенсация 18000 рублей! Оформите на gosuslugi.ru.lk-vyplaty.top",
    "Это сотрудник банка. Назовите код из СМС для отмены операции.",
    "Скачайте приложение для защиты счёта: http://bank-update.site/app.apk",
]

SUSPICIOUS = [
    "Привет! Проголосуй за мою племянницу: https://golos-konkurs.xyz/vote?id=1",
    "Мама, я попал в аварию, это мой новый номер, срочно переведи 50000 руб",
    "Позвоните по номеру +7 (912) 345-67-89, ваша карта заблокирована",
]

LEGIT = [
    "Привет, во сколько завтра встречаемся? Купил хлеб.",
    "Код для входа в Сбербанк Онлайн: 4821. Никому не сообщайте этот код, "
    "даже сотруднику банка.",
    "Посмотри, какой чайник: https://www.ozon.ru/product/123",
    "Ваш заказ доставлен в пункт выдачи. Хорошего дня!",
    "Бабушка, с днём рождения! Целуем, приедем в субботу.",
    "Запись к врачу на 12:30 подтверждена. Поликлиника №5.",
]


@pytest.mark.parametrize("text", SCAMS)
def test_scams_high(text):
    result = analyze(text)
    assert result.score >= 50, format_report(result)
    assert result.level in ("high", "critical")


@pytest.mark.parametrize("text", SUSPICIOUS)
def test_suspicious_at_least_medium(text):
    assert analyze(text).score >= 20


@pytest.mark.parametrize("text", LEGIT)
def test_legit_low(text):
    result = analyze(text)
    assert result.score < 20, format_report(result)


def test_empty():
    result = analyze("")
    assert result.score == 0 and result.level == "low"


def test_non_string_rejected():
    with pytest.raises(TypeError):
        analyze(None)  # type: ignore[arg-type]


def test_score_bounds():
    huge = " ".join(SCAMS * 10)
    assert 0 <= analyze(huge).score <= 100


def test_hidden_link_from_messenger():
    # Ссылка спрятана под словом и в тексте её нет.
    result = analyze("Получите выплату тут", extra_urls=["https://gosuslugi-pay.ru/x"])
    assert any(s.rule_id == "brand_impersonation" for s in result.signals)


def test_extra_urls_garbage_ignored():
    result = analyze("текст", extra_urls=[None, 123, "", "::::"])  # type: ignore[list-item]
    assert result.score == 0


def test_text_homoglyphs():
    # «Сбeрбанк» с латинской e, «зaблокирована» с латинской a.
    result = analyze("Сбeрбанк: ваша карта зaблокирована")
    ids = {s.rule_id for s in result.signals}
    assert {"text_homoglyphs", "blocked"} <= ids


def test_invisible_chars_detected():
    result = analyze("карта забло\u200bкирована")
    ids = {s.rule_id for s in result.signals}
    assert {"invisible_chars", "blocked"} <= ids


def test_report_is_plain_text_and_defanged():
    report = format_report(analyze("Срочно! https://sberbank-help.ru/login"))
    assert "sberbank-help[.]ru" in report
    assert "https://sberbank-help.ru" not in report


def test_long_text_truncated():
    result = analyze("а " * 20_000)
    assert result.truncated


# --- Безопасность ----------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "a" * 10_000,
    "." * 10_000,
    "-" * 10_000,
    "a." * 5_000,
    "http://" + "a" * 9_990,
    "переведите " * 1_000,
    "сообщи " * 1_500,
    "8 " * 5_000,
    "\u200b" * 10_000,
    "аa" * 5_000,
])
def test_no_slow_regex(payload):
    """Защита от ReDoS: даже на «злом» тексте проверка идёт быстро."""
    start = time.perf_counter()
    analyze(payload)
    assert time.perf_counter() - start < 1.0


def test_no_network(monkeypatch):
    """Анализ НИКОГДА не обращается в сеть (не открывает ссылки)."""
    def forbidden(*args, **kwargs):
        raise AssertionError("попытка сетевого подключения!")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    analyze("Срочно: http://bit.ly/abc https://sberbank-help.ru 185.1.1.1")


@pytest.mark.parametrize("text", [
    "Голосование за благоустройство двора на mos.ru до 1 декабря",
    "Внимание! Мошенники представляются сотрудниками банка. Никогда не сообщайте коды из СМС.",
    "Сбербанк: списание 350р. Магазин Пятёрочка. Баланс 12000р",
    "Т-Банк: вход в приложение с нового устройства. Если это не вы — позвоните 8 800 555-77-78",
])
def test_more_legit_low(text):
    result = analyze(text)
    assert result.score < 20, format_report(result)


def test_long_host_rejected_fast():
    result = analyze("http://" + "a" * 300 + ".ru")
    assert any(s.rule_id == "invalid_host" for s in result.signals)


def test_nfkc_expansion_truncated():
    result = analyze("ﷺ" * 10_000)  # каждый символ раскрывается в 18
    assert result.truncated


def ids_of(text):
    return {s.rule_id for s in analyze(text).signals}


def test_money_request_without_relative():
    found = ids_of("переведи мне деньги 100000 срочно")
    assert {"money_request", "urgency", "combo_money_urgent"} <= found
    assert "relative" not in found  # родственник не упоминался
    assert analyze("переведи мне деньги 100000 срочно").score >= 50


def test_relative_with_money():
    found = ids_of("Мама, я попал в аварию, срочно переведи 50000 руб")
    assert {"relative", "money_request", "combo_relative_urgent"} <= found


@pytest.mark.parametrize("text", [
    "Займите 5000 до пятницы",
    "скинь 300р на телефон",
    "Отправьте деньги на этот номер",
])
def test_money_request_variants(text):
    assert "money_request" in ids_of(text)


@pytest.mark.parametrize("text", [
    "Перевёл тебе 500 р, проверь",
    "Деньги пришли, спасибо",
    "Отправь мне фото с дачи",
])
def test_not_money_request(text):
    assert "money_request" not in ids_of(text)


def test_card_number_request_medium():
    result = analyze("скинь номер карты")
    assert result.score >= 40
