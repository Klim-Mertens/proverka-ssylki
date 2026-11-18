"""
Справочные данные для проверок: известные бренды, сокращатели ссылок,
подозрительные доменные зоны и т.п.

Всё хранится прямо в коде (без скачивания из интернета), чтобы:
  * программа работала без сети и не зависела от чужих серверов;
  * было видно, на чём основаны выводы (объяснимость).

Списки неполные — их можно и нужно дополнять.
"""

# ---------------------------------------------------------------------------
# Официальные домены известных организаций.
# Ключ — «основа» имени (то, что мошенники любят подделывать),
# значение — (человеческое название, набор настоящих доменов).
# Домены указываем «зарегистрированные» (без поддоменов): sberbank.ru,
# а не online.sberbank.ru — поддомены проверяются отдельно.
# ---------------------------------------------------------------------------
BRANDS: dict[str, tuple[str, frozenset[str]]] = {
    "sberbank": ("Сбербанк", frozenset({"sberbank.ru", "sberbank.com", "sber.ru"})),
    "sber": ("Сбербанк", frozenset({"sberbank.ru", "sberbank.com", "sber.ru"})),
    "gosuslugi": ("Госуслуги", frozenset({"gosuslugi.ru"})),
    "tinkoff": ("Т-Банк (Тинькофф)", frozenset({"tinkoff.ru", "tbank.ru"})),
    "tbank": ("Т-Банк (Тинькофф)", frozenset({"tinkoff.ru", "tbank.ru"})),
    "vtb": ("ВТБ", frozenset({"vtb.ru"})),
    "alfabank": ("Альфа-Банк", frozenset({"alfabank.ru"})),
    "pochtabank": ("Почта Банк", frozenset({"pochtabank.ru"})),
    "pochta": ("Почта России", frozenset({"pochta.ru"})),
    "gazprombank": ("Газпромбанк", frozenset({"gazprombank.ru"})),
    "raiffeisen": ("Райффайзенбанк", frozenset({"raiffeisen.ru"})),
    "sovcombank": ("Совкомбанк", frozenset({"sovcombank.ru"})),
    "rshb": ("Россельхозбанк", frozenset({"rshb.ru"})),
    "ozon": ("Ozon", frozenset({"ozon.ru"})),
    "wildberries": ("Wildberries", frozenset({"wildberries.ru", "wb.ru"})),
    "avito": ("Авито", frozenset({"avito.ru"})),
    "yandex": ("Яндекс", frozenset({"yandex.ru", "ya.ru", "yandex.com"})),
    "nalog": ("Налоговая служба (ФНС)", frozenset({"nalog.ru", "nalog.gov.ru"})),
    "sfr": ("Социальный фонд России", frozenset({"sfr.gov.ru"})),
    "cbr": ("Центральный банк", frozenset({"cbr.ru"})),
    "mos": ("Портал Москвы", frozenset({"mos.ru"})),
    "rzd": ("РЖД", frozenset({"rzd.ru"})),
    "cdek": ("СДЭК", frozenset({"cdek.ru"})),
    "vk": ("ВКонтакте", frozenset({"vk.com", "vk.ru"})),
    "telegram": ("Telegram", frozenset({"telegram.org", "t.me"})),
    "whatsapp": ("WhatsApp", frozenset({"whatsapp.com", "wa.me"})),
    "mvideo": ("М.Видео", frozenset({"mvideo.ru"})),
    "dns-shop": ("DNS", frozenset({"dns-shop.ru"})),
    # --- Добавлено 2026-11-05: операторы связи, ещё банки, госсервисы,
    # доставка, маркетплейсы и мессенджер MAX — их чаще всего подделывают
    # в схемах из предупреждений МВД и Минцифры (см. docs/SOURCES.md).
    "mts": ("МТС", frozenset({"mts.ru"})),
    "mtsbank": ("МТС Банк", frozenset({"mtsbank.ru"})),
    "megafon": ("МегаФон", frozenset({"megafon.ru"})),
    "beeline": ("Билайн", frozenset({"beeline.ru"})),
    "tele2": ("Т2 (Tele2)", frozenset({"tele2.ru", "t2.ru"})),
    "rostelecom": ("Ростелеком", frozenset({"rt.ru", "rostelecom.ru"})),
    "yoomoney": ("ЮMoney", frozenset({"yoomoney.ru"})),
    "psbank": ("ПСБ", frozenset({"psbank.ru"})),
    "rosbank": ("Росбанк", frozenset({"rosbank.ru"})),
    "uralsib": ("Уралсиб", frozenset({"uralsib.ru"})),
    "homecredit": ("Хоум Банк", frozenset({"homecredit.ru", "homebank.ru"})),
    "domclick": ("ДомКлик", frozenset({"domclick.ru"})),
    "pfr": ("Социальный фонд России", frozenset({"sfr.gov.ru", "pfr.gov.ru"})),
    "fssp": ("Служба судебных приставов", frozenset({"fssp.gov.ru"})),
    "gibdd": ("ГИБДД", frozenset({"gibdd.ru"})),
    "mvd": ("МВД", frozenset({"mvd.ru", "xn--b1aew.xn--p1ai"})),
    "rosreestr": ("Росреестр", frozenset({"rosreestr.gov.ru"})),
    "emias": ("ЕМИАС", frozenset({"emias.info", "mos.ru"})),
    "max": ("Мессенджер MAX", frozenset({"max.ru"})),
    "aliexpress": ("AliExpress", frozenset({"aliexpress.ru", "aliexpress.com"})),
    "boxberry": ("Boxberry", frozenset({"boxberry.ru"})),
    "stoloto": ("Столото", frozenset({"stoloto.ru"})),
}

# Все официальные домены одним множеством — для быстрой проверки.
OFFICIAL_DOMAINS: frozenset[str] = frozenset(
    domain for _, domains in BRANDS.values() for domain in domains
)

# Короткие основы (vk, sber, mos, sfr...) слишком часто встречаются внутри
# обычных слов, поэтому для них «похожесть» и «вхождение» не проверяем —
# только точное совпадение метки (например, vk-bonus.ru → метка «vk»).
SHORT_BRAND_MIN_LEN = 5

# Основы, которые тоже проверяем только на точное совпадение, хотя они
# длиннее: «tbank» встречается внутри «smartbank», «netbanking» и т.п.
BRAND_EXACT_ONLY: frozenset[str] = frozenset({"tbank", "pochta"})

# ---------------------------------------------------------------------------
# Сервисы коротких ссылок. Сами по себе не опасны, но скрывают настоящий
# адрес, поэтому мошенники ими пользуются.
# ---------------------------------------------------------------------------
SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "goo.su", "clck.ru", "cutt.ly", "t.ly",
    "is.gd", "v.gd", "ow.ly", "rebrand.ly", "shorturl.at", "s.id",
    "u.to", "vk.cc", "bit.do", "tiny.cc", "rb.gy", "qps.ru", "lnnk.in",
    "surl.li", "inlnk.ru", "shorturl.com", "goo.gl",
})

# ---------------------------------------------------------------------------
# Доменные зоны, которые очень дёшевы или бесплатны и поэтому часто
# используются для одноразовых мошеннических сайтов. Хорошие сайты там тоже
# бывают — это лишь слабый признак.
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "xyz", "top", "click", "site", "online", "shop", "icu", "buzz", "live",
    "tk", "ml", "ga", "cf", "gq", "work", "fun", "space", "website", "store",
    "cyou", "rest", "monster", "sbs", "cfd", "lol", "pw", "info",
})

# Конструкторы сайтов и бесплатные хостинги: на них любой за минуту делает
# страницу, похожую на банк. Тоже слабый признак.
FREE_HOSTING: frozenset[str] = frozenset({
    "tilda.ws", "netlify.app", "vercel.app", "pages.dev", "web.app",
    "firebaseapp.com", "glitch.me", "000webhostapp.com", "github.io",
    "ngrok.io", "ngrok-free.app", "wixsite.com", "weebly.com",
    "ucoz.ru", "ucoz.net", "narod.ru", "blogspot.com", "herokuapp.com",
})

# Доменные зоны, которые мы считаем «настоящими» при поиске ссылок без
# http:// (например, «зайдите на sberbank-bonus.ru»). Список нужен, чтобы не
# принимать за ссылку обычный текст вроде «т.е.» или «и т.д.».
KNOWN_TLDS: frozenset[str] = frozenset({
    "ru", "рф", "su", "com", "net", "org", "info", "biz", "io", "me", "app",
    "dev", "ws", "cc", "co", "uk", "de", "by", "kz", "ua", "uz", "am", "ge",
    "online", "site", "xyz", "top", "click", "shop", "store", "live", "pro",
    "icu", "buzz", "tk", "ml", "ga", "cf", "gq", "work", "fun", "space",
    "website", "cyou", "rest", "monster", "sbs", "cfd", "lol", "pw", "ly",
    "gl", "at", "id", "to", "gd", "in", "li", "tv", "link", "club", "best",
    "москва", "moscow", "gov",
})

# Составные зоны второго уровня: для «site.com.ru» зарегистрированный
# домен — это «site.com.ru», а не «com.ru». Упрощённая замена Public Suffix
# List (полный список мы не скачиваем, чтобы не зависеть от сети).
MULTI_LEVEL_SUFFIXES: frozenset[str] = frozenset({
    "com.ru", "net.ru", "org.ru", "pp.ru", "msk.ru", "spb.ru", "msk.su",
    "gov.ru", "co.uk", "org.uk", "com.ua", "com.kz", "com.by",
})

# Слова в адресе, которые часто встречаются на поддельных страницах.
SUSPICIOUS_URL_WORDS: tuple[str, ...] = (
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "bonus", "prize", "gift", "promo",
    "vyplat", "kompens", "viplat", "podarok", "priz", "akcia", "akciya",
    "unblock", "razblok", "support", "help-", "-help", "oplata", "pay-",
    "-pay", "card", "karta", "vote", "golos", "konkurs",
)

# Буквы латиницы, которые выглядят как кириллица (и наоборот).
# Используется, чтобы найти слова-«хамелеоны» вроде «Сбeрбанк»
# (где «e» — латинская).
LATIN_TO_CYRILLIC: dict[str, str] = {
    "a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у",
    "k": "к", "m": "м", "t": "т", "h": "н", "b": "в",
    "A": "А", "C": "С", "E": "Е", "O": "О", "P": "Р", "X": "Х", "Y": "У",
    "K": "К", "M": "М", "T": "Т", "H": "Н", "B": "В",
}

# Цифры и сочетания, которыми подменяют буквы в доменах: sberbank → sb3rbank.
DIGIT_LOOKALIKES: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
}

# Официальные горячие линии крупных банков (номера с сайтов банков и обратной
# стороны карт). Если в сообщении только такие номера, признак «звонят по
# номеру из сообщения» не ставим. ВНИМАНИЕ: список составлен по памяти —
# перед расширением сверяйте номера с официальными сайтами. Мошенники умеют
# подделывать входящий номер, поэтому это лишь снятие подозрения с ТЕКСТА.
OFFICIAL_PHONES: frozenset[str] = frozenset({
    "+78005555550",  # Сбербанк
    "+78005557778",  # Т-Банк
    "+78001002424",  # ВТБ
    "+78002000000",  # Альфа-Банк
})
