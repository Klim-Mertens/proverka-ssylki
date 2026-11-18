"""
Чтение QR-кодов на картинке.

Зачем: мошенники клеят поддельные QR-коды на квитанции, парковки,
объявления и присылают их в сообщениях. Человек видит только квадрат,
а внутри — ссылка на поддельный сайт оплаты.

Как устроено:
  * Картинку открывает Pillow (с теми же ограничениями, что и для чтения
    текста: только JPEG/PNG/WEBP, не больше 12 Мп и MAX_SIDE по стороне).
  * В библиотеку zbar (через pyzbar) передаются уже ГОТОВЫЕ пиксели в
    оттенках серого, а не файл: так чужой файл разбирает только Pillow,
    и поверхность атаки не растёт.
  * Мы НЕ открываем ссылку из QR-кода — только передаём её текст в
    обычную проверку ссылок.
  * Если pyzbar или libzbar не установлены — функция просто возвращает
    пустой список, бот работает как раньше.
"""

from __future__ import annotations

import io
import logging

from .ocr import MAX_SIDE

log = logging.getLogger("proverka_bot.qr")

MAX_CODES = 5          # больше пяти QR-кодов на одном снимке не бывает
MAX_PAYLOAD = 2000     # длина содержимого одного кода
MAX_PIXELS = 12_000_000


def is_available() -> bool:
    try:
        from pyzbar import pyzbar  # noqa: F401
    except (ImportError, OSError):  # OSError — нет системной libzbar
        return False
    return True


def decode_qr(data: bytes) -> list[str]:
    """Возвращает тексты QR-кодов с картинки (без повторов), или []."""
    try:
        from PIL import Image, ImageOps
        from pyzbar.pyzbar import ZBarSymbol, decode
    except (ImportError, OSError):
        return []
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    try:
        with Image.open(io.BytesIO(data), formats=["JPEG", "PNG", "WEBP"]) as img:
            # open() читает только заголовок: проверяем размер ДО распаковки.
            if img.width * img.height > MAX_PIXELS or max(img.size) > MAX_SIDE:
                return []
            gray = ImageOps.grayscale(img)
        found = decode(gray, symbols=[ZBarSymbol.QRCODE])
    except Exception as exc:  # noqa: BLE001 — сбой чтения QR не должен ломать ответ
        log.warning("QR не прочитан: %s", type(exc).__name__)
        return []
    result: list[str] = []
    for item in found[:MAX_CODES * 2]:
        raw = getattr(item, "data", b"")
        if not isinstance(raw, bytes):
            continue
        text = raw[:MAX_PAYLOAD].decode("utf-8", errors="replace").strip()
        if text and text not in result:
            result.append(text)
        if len(result) >= MAX_CODES:
            break
    return result


def links_from_codes(codes: list[str]) -> list[str]:
    """
    Из содержимого QR-кодов оставляет только похожее на ссылки. Платёжные
    QR (ST00012|Name=...) и прочий текст ссылками не считаем.
    """
    links = []
    for code in codes:
        first = code.split()[0] if code.split() else ""
        low = first.lower()
        if low.startswith(("http://", "https://", "www.")):
            links.append(first[:MAX_PAYLOAD])
    return links
