"""
Главный модуль: собирает все проверки вместе и выставляет оценку 0–100.

Как считается оценка (простыми словами):
  Каждый признак — это «шанс», что сообщение мошенническое. Например, вес 30
  означает «30% подозрения». Признаки складываются не простым сложением
  (иначе быстро получится больше 100), а так:
      риск = 1 − (1 − w1/100) × (1 − w2/100) × ...
  Пример: два признака по 30 → 1 − 0,7 × 0,7 = 0,51 → 51 из 100.
  Чем больше признаков, тем ближе к 100, но 100 не превышается никогда.

Хранение данных: функция ничего не сохраняет — ни текст, ни ссылки. Всё
живёт только в памяти на время одной проверки.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable

from .data import OFFICIAL_PHONES
from .extract import FoundUrl, clean_text, extract_phones, extract_urls, parse_url
from .models import CheckResult, Signal
from .text_rules import find_text_signals, normalize_text
from .url_rules import check_url, defang, is_trusted_url

# Максимальная длина текста. Защита от «тяжёлых» запросов: мошенническое
# сообщение почти никогда не бывает длиннее нескольких тысяч символов.
MAX_TEXT_LEN = 10_000
MAX_EXTRA_URLS = 20
# Сколько ссылок из одного сообщения можно сверить с внешней базой опасных
# сайтов. Ограничение бережёт бесплатный сервис и время ответа.
MAX_REPUTATION_CHECKS = 3

# Функция внешней проверки ссылки (например, по базе URLhaus). Получает
# разобранную ссылку и возвращает (вес 0–100, пояснение) или None, если о
# ссылке ничего плохого не известно. Само ядро в сеть НЕ ходит: такую
# функцию передаёт бот, а ядро только учитывает её ответ.
UrlReputation = Callable[[FoundUrl], "tuple[int, str] | None"]


def _combo_signals(ids: set[str], has_url: bool, has_phone: bool) -> list[Signal]:
    """
    Сочетания признаков, которые вместе говорят о мошенничестве сильнее,
    чем по отдельности.
    """
    combos: list[Signal] = []
    if has_url and ids & {"blocked", "prize", "vote", "delivery", "ask_code", "card_data",
                          "account_alert", "curiosity_bait", "pay_to_receive",
                          "subscription_scam", "operator_contract", "utilities",
                          "medical", "account_bait", "adult_bait", "refund_scam",
                          "fine_debt"}:
        combos.append(Signal(
            "combo_bait_link", 25,
            "Сообщение пугает или заманивает и сразу даёт ссылку — так устроено "
            "большинство мошеннических рассылок.", "combo"))
    if ids & {"authority", "fake_official_sender"} and ids & {"ask_code", "safe_account", "card_data", "secrecy"}:
        combos.append(Signal(
            "combo_fake_official", 40,
            "«Сотрудник» банка или полиции просит коды, деньги или тайну — это "
            "классическая схема телефонных мошенников.", "combo"))
    if "urgency" in ids and ids & {"blocked", "ask_code", "safe_account", "card_data"}:
        combos.append(Signal(
            "combo_pressure", 15,
            "Сочетание спешки и угрозы — давление, чтобы вы не успели подумать.", "combo"))
    if "relative" in ids and ids & {"urgency", "money_request"}:
        combos.append(Signal(
            "combo_relative_urgent", 20,
            "«Родственник» в беде просит денег — так начинается большинство "
            "обманов от имени близких.", "combo"))
    if "money_request" in ids and "urgency" in ids:
        combos.append(Signal(
            "combo_money_urgent", 25,
            "Деньги просят срочно — мошенники торопят, чтобы вы не успели "
            "перезвонить и проверить.", "combo"))
    if ids & {"legal_threat", "cash_handover"} and ids & {"authority", "secrecy", "safe_account"}:
        combos.append(Signal(
            "combo_police_pressure", 30,
            "«Следователь» или «сотрудник ЦБ» пугает уголовным делом и требует "
            "деньги или тайну. Настоящая полиция так не работает: положите "
            "трубку и позвоните 102.", "combo"))
    if "wrong_transfer" in ids and has_phone:
        combos.append(Signal(
            "combo_return_other", 25,
            "Просят «вернуть ошибочный перевод» на другой номер. Не переводите: "
            "если деньги правда пришли, банк вернёт их сам по заявлению.", "combo"))
    if "prize" in ids and "pay_to_receive" in ids:
        combos.append(Signal(
            "combo_prize_fee", 25,
            "Обещают приз, но просят за него заплатить — классический обман.", "combo"))
    if "fake_boss" in ids and ids & {"authority", "secrecy"}:
        combos.append(Signal(
            "combo_fake_boss", 30,
            "«Начальник» предупреждает о звонке «силовиков» и просит молчать — "
            "так начинается схема с переводом денег на «безопасный счёт».", "combo"))
    if "code_mention" in ids and ids & {"operator_contract", "medical", "utilities",
                                        "account_bait", "prize", "delivery"}:
        combos.append(Signal(
            "combo_code_pretext", 30,
            "Под видом «продления договора», «записи» или «выплаты» речь идёт о коде "
            "из СМС. Так крадут доступ к Госуслугам и банку.", "combo"))
    if ids & {"job_offer", "easy_job", "investment"} and "messenger_contact" in ids:
        combos.append(Signal(
            "combo_job_messenger", 30,
            "«Работа» с большим доходом и просьбой написать в мессенджер — "
            "типичная схема: сначала задания, потом просят «внести залог».", "combo"))
    if has_phone and ids & {"blocked", "authority", "prize", "account_alert",
                            "subscription_scam", "refund_scam", "legal_threat", "call_us"}:
        combos.append(Signal(
            "combo_call_number", 15,
            "Просят позвонить по номеру из сообщения. Звоните только по номеру "
            "на обороте вашей карты или с официального сайта.", "combo"))
    return combos


def _combine(weights: Iterable[int]) -> int:
    """Объединяет веса признаков в одну оценку 0–100 (см. описание модуля)."""
    remaining = 1.0
    for w in weights:
        w = max(0, min(100, w))  # на всякий случай ограничиваем
        remaining *= 1 - w / 100
    return round((1 - remaining) * 100)


def _level(score: int) -> tuple[str, str]:
    """Уровень риска и короткий вывод для человека."""
    if score >= 80:
        return "critical", "Очень похоже на мошенничество!"
    if score >= 50:
        return "high", "Похоже на мошенничество."
    if score >= 20:
        return "medium", "Есть подозрительные признаки. Будьте осторожны."
    return "low", ("Явных признаков мошенничества не найдено. Но это не гарантия: "
                   "если сомневаетесь — не спешите и посоветуйтесь с близкими.")


def _advice(ids: set[str], has_url: bool, level: str) -> list[str]:
    """Советы, что делать, в зависимости от найденных признаков."""
    tips: list[str] = []
    if level in ("high", "critical"):
        tips.append("Не отвечайте на это сообщение и ничего не делайте по его просьбе.")
    if has_url and level != "low":
        tips.append("Не переходите по ссылке. Если нужно — откройте приложение банка "
                    "или наберите адрес сайта сами.")
    if ids & {"ask_code", "card_data"}:
        tips.append("Никому не называйте коды из СМС, пароли, ПИН-код и три цифры "
                    "на обороте карты — даже «сотруднику банка».")
    if ids & {"blocked", "authority", "safe_account", "secrecy"}:
        tips.append("Не звоните по номерам из сообщения. Сами позвоните в банк по "
                    "номеру, который написан на обороте вашей карты. Если вам "
                    "позвонили — просто положите трубку.")
    if ids & {"relative", "money_request"}:
        tips.append("Прежде чем переводить деньги, перезвоните этому человеку по "
                    "старому, знакомому вам номеру и поговорите голосом.")
    if "known_bad_url" in ids:
        tips.append("Ни в коем случае не открывайте эту ссылку и не скачивайте "
                    "файлы по ней. Если уже открыли — не вводите никаких данных.")
    if ids & {"remote_app", "dangerous_file"}:
        tips.append("Не устанавливайте программы и приложения по просьбе незнакомых людей.")
    if level in ("high", "critical"):
        tips.append("Если вы уже перевели деньги или назвали код — сразу позвоните "
                    "в свой банк по номеру с карты и заблокируйте карту.")
    return tips


# Слова, по которым имя отправителя «притворяется» организацией: банк,
# поддержка, госорган. «Макс»/«max» специально НЕ включены — это частое имя.
_OFFICIAL_NAME_RE = re.compile(
    r"служб\w{0,3}\s+(безопасност|поддержк)|техподдержк|поддержк\w{0,2}\b|\bsupport|\bsecurity"
    r"|\b(банк|банка|банке|банку|bank)\b|\bсбер|\bsber|\bвтб\b|\bvtb|тинькофф|tinkoff|т-банк|t-bank"
    r"|альфа-?банк|alfa|газпромбанк|госуслуг|gosuslug|центробанк|центральн\w{0,3} банк|\bцб\b"
    r"|\bмвд\b|\bфсб\b|полици|прокуратур|следствен|налогов|\bфнс\b|соцфонд|социальн\w{0,3} фонд"
    r"|пенсионн|\bпфр\b|\bсфр\b|ростелеком|почта росси|\bозон\b|\bozon\b|wildberries|авито|avito"
)

# Как называть тип отправителя, если сообщение переслано (см. handler.py).
SENDER_USER = "user"            # обычный аккаунт человека
SENDER_HIDDEN = "hidden_user"   # аккаунт скрыт настройками приватности
SENDER_BOT = "bot"              # бот
SENDER_CHANNEL = "channel"      # канал или группа


def _sender_signals(forwarded_from: tuple[str, str]) -> list[Signal]:
    """
    Проверка отправителя пересланного сообщения. Имя придумывает сам
    владелец аккаунта, поэтому «Служба безопасности Сбербанка» у личного
    аккаунта — признак обмана: банки и госорганы не пишут людям с личных
    аккаунтов. Каналы не оцениваем: у банков бывают настоящие каналы, а
    отличить их по данным Telegram бот не может.
    Само имя в отчёт НЕ выводим: это чужой текст, в нём могут быть ссылки.
    """
    kind, name = forwarded_from
    if not isinstance(kind, str) or not isinstance(name, str):
        return []
    normalized, _ = normalize_text(unicodedata.normalize("NFKC", name[:200]))
    if not _OFFICIAL_NAME_RE.search(normalized):
        return []
    if kind in (SENDER_USER, SENDER_HIDDEN):
        return [Signal(
            "fake_official_sender", 45,
            "Сообщение переслано от обычного аккаунта, который называет себя банком, "
            "службой поддержки или госорганом. Настоящие банки и госорганы не пишут "
            "людям с личных аккаунтов в Telegram.", "sender")]
    if kind == SENDER_BOT:
        return [Signal(
            "official_name_bot", 20,
            "Сообщение переслано от бота с названием банка или госоргана. Мошенники "
            "делают ботов-двойников: официального бота ищите только по ссылке с "
            "сайта организации.", "sender")]
    return []


def _reputation_signals(urls: list[FoundUrl], reputation: UrlReputation) -> list[Signal]:
    """
    Сверяет ссылки с внешней базой через переданную функцию. Официальные
    сайты (sberbank.ru, gosuslugi.ru) не проверяем: незачем отправлять их
    куда-то ещё. Любая ошибка внешней проверки не должна ломать основной
    анализ — тогда просто считаем, что база ничего не сказала.
    """
    found: list[Signal] = []
    checked = 0
    for url in urls:
        if checked >= MAX_REPUTATION_CHECKS:
            break
        if is_trusted_url(url) or not url.host_ascii:
            continue
        checked += 1
        try:
            verdict = reputation(url)
        except Exception:  # noqa: BLE001 — внешняя проверка не должна ронять анализ
            verdict = None
        if verdict is None:
            continue
        weight, reason = verdict
        found.append(Signal(
            "known_bad_url", max(0, min(100, int(weight))),
            f"Адрес {defang(url.host)} есть в международной базе опасных сайтов. {reason}",
            "url"))
    return found


def analyze(text: str, extra_urls: Iterable[str] | None = None,
            reputation: UrlReputation | None = None,
            forwarded_from: tuple[str, str] | None = None) -> CheckResult:
    """
    Проверяет сообщение и возвращает оценку риска с объяснениями.

    text        — текст сообщения (что угодно, в том числе пустая строка).
    extra_urls  — ссылки, которых нет в видимом тексте (например, Telegram
                  позволяет «спрятать» ссылку под словом «тут»). Бот передаст
                  их сюда отдельно.
    reputation  — необязательная функция внешней проверки ссылок (см.
                  UrlReputation). Без неё анализ полностью офлайн.
    forwarded_from — для пересланных сообщений: (тип отправителя, его имя),
                  тип — одна из констант SENDER_*.
    """
    if not isinstance(text, str):
        raise TypeError("text должен быть строкой")

    truncated = len(text) > MAX_TEXT_LEN
    text = text[:MAX_TEXT_LEN]

    # 1. Очистка: NFKC (широкие/«красивые» буквы → обычные) и удаление
    #    невидимых символов.
    text = unicodedata.normalize("NFKC", text)
    # NFKC может «раздуть» строку (один символ ﷽ превращается в 18), поэтому
    # обрезаем ещё раз уже после нормализации.
    truncated = truncated or len(text) > MAX_TEXT_LEN
    text = text[:MAX_TEXT_LEN]
    text, had_invisible, had_bidi = clean_text(text)

    signals: list[Signal] = []
    notes: list[str] = []

    if had_bidi:
        signals.append(Signal(
            "bidi_chars", 30,
            "В сообщении есть скрытые символы, которые меняют порядок букв "
            "на экране. Так маскируют настоящие названия файлов и адресов.", "text"))
    if had_invisible:
        signals.append(Signal(
            "invisible_chars", 20,
            "В сообщении спрятаны невидимые символы. Обычные люди их не пишут — "
            "так пытаются обмануть фильтры.", "text"))

    # 2. Признаки в тексте.
    normalized, mixed_words = normalize_text(text)
    if mixed_words:
        signals.append(Signal(
            "text_homoglyphs", 30,
            "В словах сообщения русские буквы подменены похожими латинскими "
            "(например, «Сбeрбанк» с английской «e»). Так обходят защиту от спама.",
            "text"))
    for rule in find_text_signals(normalized):
        signals.append(Signal(rule.rule_id, rule.weight, rule.explanation, "text"))

    # 3. Ссылки и телефоны.
    urls: list[FoundUrl] = extract_urls(text)
    if extra_urls is not None:
        known = {u.raw for u in urls}
        for raw in list(extra_urls)[:MAX_EXTRA_URLS]:
            if not isinstance(raw, str):
                continue
            raw = unicodedata.normalize("NFKC", raw)
            raw, _, _ = clean_text(raw)
            parsed = parse_url(raw)
            if parsed and parsed.raw not in known:
                urls.append(parsed)
                known.add(parsed.raw)
    phones = extract_phones(text)

    for url in urls:
        url_signals, url_notes = check_url(url)
        signals.extend(url_signals)
        for note in url_notes:
            if note not in notes:
                notes.append(note)

    if reputation is not None:
        signals.extend(_reputation_signals(urls, reputation))
    if forwarded_from is not None:
        signals.extend(_sender_signals(forwarded_from))

    # 4. Один и тот же признак (например, из двух ссылок) учитываем один раз —
    #    с наибольшим весом. Объяснение берём первое.
    best: dict[str, Signal] = {}
    for s in signals:
        if s.rule_id not in best or s.weight > best[s.rule_id].weight:
            best[s.rule_id] = s
    unique = list(best.values())

    ids = set(best)
    # Ссылки только на официальные сайты (gosuslugi.ru, ozon.ru) не считаем
    # «приманкой» в сочетаниях. Но их собственные признаки уже учтены выше.
    has_untrusted_url = any(not is_trusted_url(u) for u in urls)
    unique.extend(_combo_signals(ids, has_url=has_untrusted_url, has_phone=any(p not in OFFICIAL_PHONES for p in phones)))

    # Сортируем: самые важные причины — первыми.
    unique.sort(key=lambda s: s.weight, reverse=True)
    risky = [s for s in unique if s.weight > 0]

    score = _combine(s.weight for s in risky)
    level, verdict = _level(score)

    if truncated:
        notes.append(f"Сообщение очень длинное, проверены первые {MAX_TEXT_LEN} символов.")

    return CheckResult(
        score=score,
        level=level,
        verdict=verdict,
        signals=risky,
        notes=notes,
        advice=_advice(ids, has_url=has_untrusted_url, level=level),
        urls=[defang(u.host) for u in urls],
        phones=phones,
        truncated=truncated,
    )


LEVEL_ICONS = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}


def format_report(result: CheckResult, max_reasons: int = 6) -> str:
    """
    Превращает результат в обычный текст для показа человеку (без HTML и
    Markdown). ВАЖНО для бота и сайта: этот текст содержит куски чужого
    сообщения (адреса сайтов), поэтому отправлять его нужно как ПРОСТОЙ ТЕКСТ,
    без parse_mode=HTML/Markdown, а на сайте — с экранированием (иначе
    возможна HTML-инъекция / XSS).
    """
    lines = [f"{LEVEL_ICONS[result.level]} Риск: {result.score} из 100", result.verdict]

    if result.signals:
        lines.append("")
        lines.append("Почему:")
        for s in result.signals[:max_reasons]:
            lines.append(f"• {s.text}")
        hidden = len(result.signals) - max_reasons
        if hidden > 0:
            lines.append(f"• …и ещё признаков: {hidden}")

    if result.notes:
        lines.append("")
        lines.extend(f"ℹ️ {n}" for n in result.notes)

    if result.advice:
        lines.append("")
        lines.append("Что делать:")
        lines.extend(f"✅ {a}" for a in result.advice)

    return "\n".join(lines)
