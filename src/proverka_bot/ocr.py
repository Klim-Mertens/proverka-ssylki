"""
Распознавание текста на скриншотах (OCR) с помощью программы Tesseract.

Почему Tesseract: бесплатный, работает прямо на нашем сервере — картинка
НИКУДА не отправляется (на скриншотах бывают личные данные).

Безопасность (картинка пришла из интернета, ей нельзя доверять):
  * берём только «фото» Telegram — Telegram сам пересжимает их в JPEG, так что
    до нас не доходят хитро собранные файлы;
  * ограничиваем размер файла и сторон картинки;
  * Tesseract запускается отдельным процессом с таймаутом и ограничением
    памяти (prlimit): даже если файл «тяжёлый», бот не зависнет и не упадёт;
  * картинка не сохраняется на диск: передаётся через stdin и забывается;
  * одновременно распознаётся только одна картинка (сервер слабый).
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess  # nosec B404 (фиксированная команда)
import threading

MAX_FILE_BYTES = 5 * 1024 * 1024    # 5 МБ
MAX_SIDE = 2600                     # пикселей (Telegram сжимает фото до 2560)
TIMEOUT_SEC = 60
MEMORY_LIMIT = 350 * 1024 * 1024    # 350 МБ на процесс tesseract
MAX_TEXT = 10_000

_one_at_a_time = threading.Semaphore(1)


class OcrError(Exception):
    """Не удалось распознать текст (без подробностей о содержимом)."""


def is_available() -> bool:
    """Установлен ли Tesseract (на хостинге — да, через Dockerfile)."""
    return shutil.which("tesseract") is not None


def _command() -> list[str]:
    # stdin/stdout — файл не пишется на диск. rus+eng — русский и латиница (адреса сайтов).
    cmd = ["tesseract", "stdin", "stdout", "-l", "rus+eng"]
    prlimit = shutil.which("prlimit")
    if prlimit:
        # Жёсткий предел памяти для процесса. Работает и из потоков
        # (в отличие от preexec_fn, который в многопоточной программе небезопасен).
        cmd = [prlimit, f"--as={MEMORY_LIMIT}", "--"] + cmd
    return cmd


def _run_tesseract(data: bytes) -> str:
    """Один запуск Tesseract на готовых байтах картинки."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "OMP_THREAD_LIMIT": "1",  # один поток: сервер слабый, так стабильнее
    }
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603 (фиксированная команда)
            _command(), input=data, capture_output=True,
            timeout=TIMEOUT_SEC, env=env, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise OcrError(type(exc).__name__) from None
    if result.returncode != 0:
        raise OcrError(f"код {result.returncode}")
    return result.stdout[: MAX_TEXT * 4].decode("utf-8", errors="replace")[:MAX_TEXT]


_LETTER_RE = re.compile(r"[A-Za-zА-Яа-яЁё]")


def _letters(text: str) -> int:
    return len(_LETTER_RE.findall(text))


def _bright_text_variant(data: bytes) -> bytes | None:
    """
    Вариант картинки для ТЁМНОЙ темы: светлые буквы на тёмном или цветном
    (синем, зелёном) «пузыре». Tesseract такие плохо видит, поэтому делаем
    чёрные буквы на белом: всё очень светлое — в чёрное, остальное — в белое,
    и увеличиваем в 2 раза (Telegram сильно уменьшает скриншоты).

    Нужна библиотека Pillow. Если её нет или картинка странная — None.
    """
    try:
        from PIL import Image, ImageOps, ImageStat
    except ImportError:
        return None
    # Защита от «бомб»: картинка в мегапиксели гигантского размера.
    Image.MAX_IMAGE_PIXELS = 12_000_000
    try:
        with Image.open(io.BytesIO(data), formats=["JPEG", "PNG", "WEBP"]) as img:
            # open() читает только заголовок; проверяем размер ДО распаковки.
            if img.width * img.height > Image.MAX_IMAGE_PIXELS or max(img.size) > MAX_SIDE:
                return None
            gray = ImageOps.grayscale(img)
        if ImageStat.Stat(gray).mean[0] >= 110:
            return None  # светлая тема — исходная картинка читается хорошо
        bw = gray.point(lambda p: 0 if p > 190 else 255)
        if max(bw.size) < 2000:
            bw = bw.resize((bw.width * 2, bw.height * 2))
        out = io.BytesIO()
        bw.save(out, format="PNG")
        return out.getvalue()
    except (OSError, ValueError, Image.DecompressionBombError):
        return None


def clean_ocr_text(text: str) -> str:
    """
    Чинит типичные огрехи распознавания:
      * перенос слова через строку: «забло-\nкирована» → «заблокирована»;
      * пробел внутри адреса: «sberbank-help. ru» → «sberbank-help.ru».
    """
    text = re.sub(r"(\w)-\n(\w)", r"\1\2", text)
    return re.sub(r"(\w)\s?\.\s(ru|рф|com|net|org|xyz|top|site|online|su)\b", r"\1.\2", text)


def image_to_text(data: bytes) -> str:
    """
    Возвращает распознанный текст. Бросает OcrError при любой проблеме.
    Сначала читаем картинку как есть; для тёмной темы дополнительно читаем
    «перекрашенный» вариант и берём оба текста (правила просто ищут признаки,
    повтор им не мешает).
    """
    if not data or len(data) > MAX_FILE_BYTES:
        raise OcrError("размер файла")
    with _one_at_a_time:
        text = _run_tesseract(data)
        variant = _bright_text_variant(data)
        if variant is not None:
            extra = _run_tesseract(variant)
            if _letters(extra) > _letters(text):
                text, extra = extra, text  # более полный текст — первым
            if _letters(extra) > 10:
                text = text + "\n" + extra
    return clean_ocr_text(text)[:MAX_TEXT]


def pick_photo(photos: object) -> str | None:
    """
    Из вариантов размера фото (Telegram присылает несколько) выбирает самый
    крупный, который помещается в наши ограничения. Возвращает file_id.
    """
    if not isinstance(photos, list):
        return None
    best: tuple[int, str] | None = None
    for size in photos[:20]:
        if not isinstance(size, dict):
            continue
        w, h, fid = size.get("width"), size.get("height"), size.get("file_id")
        fsize = size.get("file_size", 0)
        if not (isinstance(w, int) and isinstance(h, int) and isinstance(fid, str)):
            continue
        if not isinstance(fsize, int) or fsize > MAX_FILE_BYTES or max(w, h) > MAX_SIDE:
            continue
        if best is None or w * h > best[0]:
            best = (w * h, fid)
    return best[1] if best else None
