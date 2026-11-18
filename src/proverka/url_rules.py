"""
Проверки ССЫЛОК. Ссылка никогда не открывается — анализируется только её
текст (имя сайта, путь, порт и т.п.).

Главные приёмы мошенников, которые мы ищем:
  * подделка известного сайта: sberbank-bonus.ru, gosuslugi.ru.secure.com,
    sberbamk.ru (опечатка), sb3rbank.ru (цифра вместо буквы);
  * буквы-двойники: «sberbаnk.ru», где «а» — русская (выглядит одинаково!);
  * IP-адрес вместо имени сайта: http://185.12.34.56/login;
  * «логин@» в адресе: http://sberbank.ru@evil.com ведёт на evil.com;
  * сокращатели ссылок (bit.ly, clck.ru), скрывающие настоящий адрес;
  * дешёвые доменные зоны и бесплатные конструкторы сайтов;
  * ссылки на скачивание программ (.apk, .exe).
"""

from __future__ import annotations

import ipaddress

from .data import (
    BRAND_EXACT_ONLY,
    BRANDS,
    DIGIT_LOOKALIKES,
    FREE_HOSTING,
    LATIN_TO_CYRILLIC,
    MULTI_LEVEL_SUFFIXES,
    OFFICIAL_DOMAINS,
    SHORT_BRAND_MIN_LEN,
    SHORTENERS,
    SUSPICIOUS_TLDS,
    SUSPICIOUS_URL_WORDS,
)
from .extract import FoundUrl
from .models import Signal

# Обратная таблица: кириллические буквы-двойники → латиница.
CYRILLIC_TO_LATIN: dict[str, str] = {cyr.lower(): lat.lower() for lat, cyr in LATIN_TO_CYRILLIC.items()}
CYRILLIC_TO_LATIN.update({"і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "һ": "h"})

# Русские написания брендов, которые встречаются в адресах на .рф.
RUSSIAN_BRAND_NAMES: dict[str, str] = {
    "сбербанк": "sberbank", "сбер": "sber", "госуслуги": "gosuslugi",
    "тинькофф": "tinkoff", "втб": "vtb", "альфабанк": "alfabank",
    "почтабанк": "pochtabank", "озон": "ozon", "вайлдберриз": "wildberries",
    "авито": "avito", "яндекс": "yandex", "налог": "nalog", "сдэк": "cdek",
}

# Максимальная длина имени сайта по стандарту DNS.
MAX_HOST_LEN = 253

# Расширения файлов-программ: открывать такие ссылки на телефоне опасно.
DANGEROUS_EXTENSIONS = (".apk", ".exe", ".scr", ".bat", ".cmd", ".msi", ".vbs", ".jar", ".js")

# Официальный домен → название организации (для понятных пояснений).
DOMAIN_TO_BRAND: dict[str, str] = {
    domain: name for name, domains in BRANDS.values() for domain in domains
}

# Площадки, где страницы создают сами пользователи: домен настоящий,
# но содержимое — чьё угодно (канал в Telegram, группа ВКонтакте).
USER_CONTENT_DOMAINS = frozenset({"t.me", "vk.com", "vk.ru", "wa.me", "telegram.org"})

# Зоны, где кириллица в адресе — норма.
CYRILLIC_TLDS = frozenset({"рф", "москва", "рус", "дети", "онлайн", "сайт", "орг", "ком"})


def defang(address: str) -> str:
    """
    «Обезвреживает» адрес для показа человеку: sber-bonus.ru → sber-bonus[.]ru.
    Так Telegram и почтовые программы не превратят его в кликабельную ссылку,
    и пользователь случайно не перейдёт по ней из нашего же отчёта.
    """
    return address.replace(".", "[.]")


def registered_domain(host: str) -> str:
    """
    Упрощённо определяет «зарегистрированный» домен: online.sberbank.ru →
    sberbank.ru; site.com.ru → site.com.ru. Именно его владелец управляет
    сайтом. (Точный способ — Public Suffix List; здесь упрощённая версия.)
    """
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip(host: str) -> bool:
    """Является ли имя сайта IP-адресом (v4 или v6)."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    # Хитрые записи IPv4: десятичное число (http://3232235777) или
    # шестнадцатеричное (0xC0A80001) браузер тоже понимает как IP.
    # isascii(): иначе «١٢٣» (арабские цифры) тоже считались бы числом.
    if host.isascii() and host.isdigit() and len(host) <= 10:
        return True
    return host.startswith("0x") and all(c in "0123456789abcdef" for c in host[2:]) and len(host) > 2


def _levenshtein(a: str, b: str, limit: int = 3) -> int:
    """
    Расстояние Левенштейна — сколько букв нужно заменить/добавить/удалить,
    чтобы из одного слова получить другое. sberbamk → sberbank = 1.
    Если разница длин больше limit, сразу возвращаем limit+1 (экономим время).
    """
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(
                previous[j] + 1,               # удаление
                current[j - 1] + 1,            # вставка
                previous[j - 1] + (ca != cb),  # замена
            ))
        previous = current
    return previous[-1]


def _deconfuse(label: str) -> str:
    """Убирает типичные подмены: цифры-двойники, rn→m, vv→w, кириллицу → латиницу."""
    label = "".join(CYRILLIC_TO_LATIN.get(ch, ch) for ch in label)
    label = "".join(DIGIT_LOOKALIKES.get(ch, ch) for ch in label)
    return label.replace("rn", "m").replace("vv", "w")


def _has_mixed_scripts(label: str) -> bool:
    """Есть ли в одной части имени и латиница, и кириллица одновременно."""
    has_lat = any("a" <= ch <= "z" for ch in label)
    has_cyr = any("Ѐ" <= ch <= "ӿ" for ch in label)
    return has_lat and has_cyr


def _brand_match(host: str) -> tuple[str, str] | None:
    """
    Ищет в имени сайта упоминание или подделку известного бренда.
    Возвращает (название_бренда, вид) или None.
    Вид: 'mention' — бренд прямо в адресе, 'lookalike' — похожее написание.
    """
    labels = host.split(".")[:-1]  # без доменной зоны (.ru, .com)
    # Делим ещё и по дефисам: sberbank-bonus → sberbank, bonus
    parts = [p for label in labels for p in label.split("-") if p]
    # Целые метки тоже проверяем (dns-shop — бренд с дефисом).
    # dict.fromkeys убирает повторы, но сохраняет порядок (в отличие от set),
    # чтобы результат был одинаковым при каждом запуске.
    candidates = list(dict.fromkeys(parts + labels))

    for raw_part in candidates:
        # Русские написания на .рф: «сбербанк-бонус.рф»
        part = RUSSIAN_BRAND_NAMES.get(raw_part, raw_part)
        cleaned = _deconfuse(part)
        for brand_key, (brand_name, _) in BRANDS.items():
            short = len(brand_key) < SHORT_BRAND_MIN_LEN or brand_key in BRAND_EXACT_ONLY
            if part == brand_key:
                return brand_name, "mention"
            if short:
                continue  # для коротких (vk, sber) — только точное совпадение
            if brand_key in part:
                return brand_name, "mention"  # sberbankonline, mygosuslugi
            if cleaned == brand_key or brand_key in cleaned:
                return brand_name, "lookalike"  # sb3rbank, sberbаnk (кириллица)
            # Опечатка: проверяем только для длинных названий (от 7 букв),
            # иначе слишком много ложных срабатываний (video ≈ mvideo).
            # Допускаем 1 отличие, для очень длинных (от 9 букв) — 2.
            if len(brand_key) < 7:
                continue
            allowed = 1 if len(brand_key) < 9 else 2
            if 0 < _levenshtein(cleaned, brand_key, limit=allowed) <= allowed:
                return brand_name, "lookalike"
    return None


def is_trusted_url(url: FoundUrl) -> bool:
    """
    Ведёт ли ссылка на официальный сайт известной организации (и это не
    площадка, где страницы создают пользователи, вроде t.me или vk.com).
    """
    host = url.host.lower()
    if len(host) > MAX_HOST_LEN or url.has_userinfo or _is_ip(host):
        return False
    reg = registered_domain(host)
    reg_ascii = registered_domain((url.host_ascii or host).lower())
    official = reg in OFFICIAL_DOMAINS or reg_ascii in OFFICIAL_DOMAINS
    return official and reg not in USER_CONTENT_DOMAINS


def check_url(url: FoundUrl) -> tuple[list[Signal], list[str]]:
    """
    Проверяет одну ссылку. Возвращает (признаки_риска, нейтральные_пояснения).
    """
    signals: list[Signal] = []
    notes: list[str] = []
    host = url.host.lower()
    host_ascii = (url.host_ascii or host).lower()
    shown = defang(host)

    def add(rule_id: str, weight: int, text: str) -> None:
        signals.append(Signal(rule_id, weight, text, "url"))

    # 0. Слишком длинное имя: по стандарту DNS не больше 253 символов. Такое
    #    имя — либо мусор, либо попытка нагрузить проверку; дальше не идём.
    if len(host) > MAX_HOST_LEN:
        add("invalid_host", 20,
            "Адрес сайта записан неправильно (слишком длинный). Настоящие сайты "
            "так не выглядят.")
        return signals, notes

    # 1. IP-адрес вместо имени.
    if _is_ip(host):
        add("ip_host", 35,
            f"Ссылка ведёт не на сайт с названием, а на голый числовой адрес ({shown}). "
            "Настоящие банки и магазины так не делают.")
        if url.has_userinfo:
            add("userinfo", 35, "В ссылке спрятан обман: часть до знака «@» не имеет значения, "
                "на самом деле ссылка ведёт на другой сайт.")
        return signals, notes

    reg = registered_domain(host)
    reg_ascii = registered_domain(host_ascii)
    tld = host.rsplit(".", 1)[-1]

    # 2. «логин@сайт»: http://sberbank.ru@evil.com
    if url.has_userinfo:
        add("userinfo", 35,
            f"В ссылке спрятан обман: всё, что стоит до знака «@», не имеет значения. "
            f"На самом деле ссылка ведёт на {shown}.")

    # 3. Официальный сайт?
    is_official = reg in OFFICIAL_DOMAINS or reg_ascii in OFFICIAL_DOMAINS
    if is_official:
        brand_name = DOMAIN_TO_BRAND.get(reg) or DOMAIN_TO_BRAND.get(reg_ascii, "")
        if reg in USER_CONTENT_DOMAINS:
            notes.append(f"Ссылка {shown} ведёт внутрь «{brand_name}». Сама площадка "
                         "настоящая, но страницу или канал там мог создать кто угодно, "
                         "в том числе мошенник.")
        else:
            notes.append(f"Ссылка {shown} ведёт на официальный сайт «{brand_name}». "
                         "Но если сообщение просит коды или деньги — всё равно будьте осторожны.")
    else:
        # 4. Буквы-двойники: латиница и кириллица в одном имени.
        if any(_has_mixed_scripts(label) for label in host.split(".")):
            add("mixed_scripts", 45,
                f"В адресе {shown} перемешаны русские и латинские буквы, которые выглядят "
                "одинаково. Это приём подделки известных сайтов.")
        # 5. Подделка бренда.
        match = _brand_match(host)
        if match:
            brand_name, kind = match
            if kind == "mention":
                add("brand_impersonation", 50,
                    f"Адрес {shown} использует название «{brand_name}», но это НЕ официальный "
                    f"сайт «{brand_name}». Так мошенники делают сайты-подделки.")
            else:
                add("brand_lookalike", 50,
                    f"Адрес {shown} очень похож на сайт «{brand_name}», но отличается "
                    "одной-двумя буквами или цифрами. Это сайт-подделка.")
        # 6. Punycode (необычные буквы) там, где их быть не должно.
        if "xn--" in host_ascii and tld not in CYRILLIC_TLDS:
            add("punycode", 20,
                f"Адрес {shown} содержит необычные буквы (не латиница). Иногда так "
                "маскируют поддельные сайты под настоящие.")

    # 7. Сокращатель ссылок.
    if reg in SHORTENERS or host in SHORTENERS:
        add("shortener", 20,
            f"Это «короткая ссылка» ({shown}): она скрывает настоящий адрес сайта, "
            "куда вы попадёте.")

    # 8. Бесплатный хостинг / конструктор сайтов.
    if reg in FREE_HOSTING or any(host.endswith("." + h) for h in FREE_HOSTING):
        add("free_hosting", 15,
            f"Сайт {shown} сделан на бесплатном конструкторе. Банки и госорганы "
            "такими не пользуются.")

    # 9. Подозрительная доменная зона.
    if tld in SUSPICIOUS_TLDS:
        add("suspicious_tld", 15,
            f"Сайт находится в доменной зоне «.{tld}», которую часто выбирают "
            "мошенники из-за дешевизны.")

    # 10. Слишком много частей в имени: gosuslugi.ru.lk.secure-auth.top
    if len(host.split(".")) >= 5:
        add("many_subdomains", 10,
            f"Адрес {shown} очень длинный и запутанный. Настоящее имя сайта — "
            f"только последняя часть: {defang(reg)}.")

    # 11. Подозрительные слова в адресе (login, bonus, vyplata...).
    full_lower = (host + url.path).lower()
    if not is_official and any(word in full_lower for word in SUSPICIOUS_URL_WORDS):
        add("suspicious_words", 10,
            "В адресе есть слова вроде «вход», «бонус», «выплата», «подтверждение» — "
            "так часто выглядят ссылки на поддельные страницы.")

    # 12. Ссылка на скачивание программы.
    path_only = url.path.split("?", 1)[0].split("#", 1)[0].lower()
    if path_only.endswith(DANGEROUS_EXTENSIONS):
        add("dangerous_file", 45,
            "Ссылка скачивает программу или приложение. Через такие файлы "
            "мошенники заражают телефон и получают доступ к банку.")

    # 13. Нестандартный порт: http://site.ru:8080
    if url.port is not None and url.port not in (80, 443):
        add("odd_port", 15,
            "В адресе указан необычный «порт» (число после двоеточия). Обычные "
            "сайты так не выглядят.")

    # 14. Без шифрования (http://).
    if url.scheme == "http":
        add("no_https", 5,
            "Ссылка без защищённого соединения (http, а не https).")

    # 15. Очень длинная ссылка.
    if len(url.raw) > 120:
        add("long_url", 5, "Ссылка очень длинная — так иногда прячут настоящий адрес.")

    return signals, notes
