"""
Извлечение ссылок и телефонов из текста.

ВАЖНО ПО БЕЗОПАСНОСТИ:
  * Мы НИКОГДА не открываем найденные ссылки. Анализ идёт только по тексту
    адреса. Открыть ссылку — значит, возможно, сообщить мошенникам, что номер
    «живой», или скачать вредоносный файл.
  * Мы не используем «тяжёлые» регулярные выражения для поиска ссылок.
    Сложные регулярки с вложенными повторениями могут работать
    экспоненциально долго на специально подобранном тексте (атака ReDoS —
    Regular expression Denial of Service). Вместо этого текст режется на
    слова по пробелам, и каждое слово проверяется простыми правилами.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .data import KNOWN_TLDS

# Символы, которые часто «прилипают» к ссылке в тексте: скобки, кавычки,
# точка в конце предложения и т.п. Их отрезаем по краям слова.
_EDGE_PUNCT = "()[]{}<>\"'«»“”„‘’.,;:!?…"

# Невидимые символы (нулевой ширины и т.п.). Мошенники вставляют их внутрь
# слов и адресов, чтобы обмануть фильтры. Мы их удаляем перед анализом.
INVISIBLE_CHARS = (
    "\u200b"  # zero width space
    "\u200c"  # zero width non-joiner
    "\u200d"  # zero width joiner
    "\u2060"  # word joiner
    "\ufeff"  # BOM / zero width no-break space
    "\u00ad"  # мягкий перенос
    "\u180e"  # mongolian vowel separator
)
_INVISIBLE_RE = re.compile(f"[{INVISIBLE_CHARS}]")

# Символы управления направлением текста (RTL override и т.п.). Позволяют
# показать «exe.pdf» как «fdp.exe» — классический трюк.
BIDI_CHARS = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f"
_BIDI_RE = re.compile(f"[{BIDI_CHARS}]")

# Российский телефон: +7 или 8, затем 10 цифр с возможными пробелами,
# дефисами и скобками. Все повторения ограничены ({0,2}), вложенных
# повторений нет — регулярка работает за линейное время.
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+7|8)[\s\-(]{0,2}\d{3}[\s\-)]{0,2}\d{3}[\s\-]{0,2}\d{2}[\s\-]{0,2}\d{2}(?!\d)"
)

# Схемы, которые считаем ссылками.
_SCHEMES = ("http://", "https://")


@dataclass(frozen=True)
class FoundUrl:
    """Найденная в тексте ссылка."""

    raw: str          # как было написано в тексте
    host: str         # имя сайта в нижнем регистре, без порта ('' если не удалось разобрать)
    host_ascii: str   # то же в ASCII (кириллица → punycode xn--...)
    scheme: str       # 'http', 'https' или '' (если в тексте было без схемы)
    port: int | None  # порт, если явно указан
    has_userinfo: bool  # есть ли в адресе «логин@» перед именем сайта
    path: str         # путь и параметры после имени сайта


def clean_text(text: str) -> tuple[str, bool, bool]:
    """
    Удаляет невидимые символы и символы управления направлением текста.

    Возвращает (очищенный_текст, были_невидимые, были_bidi).
    """
    had_invisible = bool(_INVISIBLE_RE.search(text))
    had_bidi = bool(_BIDI_RE.search(text))
    text = _INVISIBLE_RE.sub("", text)
    text = _BIDI_RE.sub("", text)
    return text, had_invisible, had_bidi


def _to_ascii_host(host: str) -> str:
    """
    Переводит имя сайта в ASCII-вид (IDNA/punycode): «пример.рф» →
    «xn--e1afmkfd.xn--p1ai». Если перевести нельзя (мусор в имени) —
    возвращает пустую строку. Исключения не пробрасываем наружу: на вход
    может прийти что угодно.
    """
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return ""


def _looks_like_bare_domain(token: str) -> bool:
    """
    Похоже ли слово без http:// на адрес сайта, например «sber-bonus.ru/vxod».
    Требуем: есть точка, последняя часть имени — известная доменная зона,
    и все части имени состоят только из допустимых символов.
    """
    host = re.split(r"[/?#:]", token, maxsplit=1)[0]
    if "." not in host or "@" in host:
        return False  # «@» — это скорее e-mail, а не ссылка
    labels = host.lower().split(".")
    if len(labels) < 2 or labels[-1] not in KNOWN_TLDS:
        return False
    for label in labels:
        # Часть имени: 1–63 символа, буквы/цифры/дефис, не с дефиса.
        if not (1 <= len(label) <= 63) or label.startswith("-") or label.endswith("-"):
            return False
        if not all(ch.isalnum() or ch == "-" for ch in label):
            return False
    # Отсекаем сокращения вроде «т.е.», «г.москва»: первая часть должна
    # быть длиннее одной буквы.
    return len(labels[0]) > 1


def _parse_url(raw: str) -> FoundUrl | None:
    """Разбирает строку-ссылку. Возвращает None, если это не адрес сайта."""
    lower = raw.lower()
    if lower.startswith(_SCHEMES):
        to_parse = raw
        scheme_given = True
    else:
        # Без схемы urlsplit не поймёт, где имя сайта, поэтому добавляем «//».
        to_parse = "//" + raw
        scheme_given = False

    try:
        parts = urlsplit(to_parse)
        host = (parts.hostname or "").rstrip(".")
        port = parts.port  # может бросить ValueError на «:99999» или «:abc»
    except ValueError:
        # Сломанный адрес: всё равно сообщаем о нём, но без разбора порта.
        try:
            parts = urlsplit(to_parse)
            host = (parts.hostname or "").rstrip(".")
        except ValueError:
            return None
        port = None

    if not host:
        return None

    path = parts.path
    if parts.query:
        path += "?" + parts.query
    if parts.fragment:
        path += "#" + parts.fragment

    return FoundUrl(
        raw=raw,
        host=host,
        host_ascii=_to_ascii_host(host),
        scheme=parts.scheme.lower() if scheme_given else "",
        port=port,
        # «@» до имени сайта: http://sberbank.ru@evil.com ведёт на evil.com!
        has_userinfo=bool(parts.username) or "@" in parts.netloc,
        path=path,
    )


def extract_urls(text: str, max_urls: int = 20) -> list[FoundUrl]:
    """
    Находит ссылки в тексте. Ограничиваем количество (max_urls), чтобы
    огромное сообщение из тысяч ссылок не нагружало программу.
    """
    found: list[FoundUrl] = []
    seen: set[str] = set()
    for token in text.split():
        token = token.strip(_EDGE_PUNCT)
        if not token:
            continue
        lower = token.lower()
        is_url = (
            lower.startswith(_SCHEMES)
            or lower.startswith("www.")
            or _looks_like_bare_domain(token)
        )
        if not is_url or token in seen:
            continue
        parsed = _parse_url(token)
        if parsed is None:
            continue
        seen.add(token)
        found.append(parsed)
        if len(found) >= max_urls:
            break
    return found


def parse_url(raw: str) -> FoundUrl | None:
    """
    Публичная обёртка: разобрать одну ссылку, пришедшую не из текста
    (например, «скрытую» ссылку под словом в Telegram).
    """
    raw = raw.strip()
    if not raw:
        return None
    return _parse_url(raw)


def extract_phones(text: str, max_phones: int = 10) -> list[str]:
    """Находит российские номера телефонов и приводит их к виду +7XXXXXXXXXX."""
    phones: list[str] = []
    for match in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        normalized = "+7" + digits[-10:]
        if normalized not in phones:
            phones.append(normalized)
        if len(phones) >= max_phones:
            break
    return phones
