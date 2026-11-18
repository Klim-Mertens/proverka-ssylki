"""Тесты чтения скриншотов (OCR). Настоящий Tesseract — если установлен."""

import io
import shutil

import pytest

from proverka_bot import handler, ocr
from proverka_bot.handler import NO_OCR_TEXT, OCR_FAIL_TEXT, DOCUMENT_TEXT, OcrJob, handle_update
from proverka_bot.ratelimit import RateLimiter
from proverka_bot.server import _run_ocr
from proverka_bot.telegram_api import TelegramAPI, TelegramError

FAKE_TOKEN = "123456789:" + "A" * 35
HAS_TESSERACT = shutil.which("tesseract") is not None


def photo_update(photos, caption=None):
    m = {"chat": {"id": 10, "type": "private"}, "from": {"id": 1}, "photo": photos}
    if caption:
        m["caption"] = caption
    return {"message": m}


SIZES = [
    {"file_id": "small", "width": 90, "height": 160, "file_size": 2000},
    {"file_id": "big", "width": 1170, "height": 2532, "file_size": 300_000},
    {"file_id": "huge", "width": 5000, "height": 9000, "file_size": 300_000},
    {"file_id": "heavy", "width": 800, "height": 800, "file_size": 50_000_000},
]


def test_pick_photo_respects_limits():
    assert ocr.pick_photo(SIZES) == "big"
    assert ocr.pick_photo("junk") is None
    assert ocr.pick_photo([None, {"file_id": 5}]) is None


def test_photo_becomes_ocr_job(monkeypatch):
    monkeypatch.setattr(ocr, "is_available", lambda: True)
    job = handle_update(photo_update(SIZES, caption="смотри"), RateLimiter(5))
    assert job == OcrJob(10, "big", "смотри", ())


def test_photo_without_tesseract(monkeypatch):
    monkeypatch.setattr(ocr, "is_available", lambda: False)
    assert handle_update(photo_update(SIZES), RateLimiter(5)) == (10, NO_OCR_TEXT)


def test_photo_too_big(monkeypatch):
    monkeypatch.setattr(ocr, "is_available", lambda: True)
    assert handle_update(photo_update(SIZES[2:]), RateLimiter(5)) == (10, OCR_FAIL_TEXT)


def test_image_document_asks_for_photo():
    upd = {"message": {"chat": {"id": 10, "type": "private"}, "from": {"id": 1},
                       "document": {"mime_type": "image/png", "file_id": "x"}}}
    assert handle_update(upd, RateLimiter(5)) == (10, DOCUMENT_TEXT)


def test_ocr_report_and_tiny_text():
    job = OcrJob(1, "f", "", ())
    report = handler.report_for_ocr_text("Ваша карта заблокирована, срочно сообщите код из смс", job)
    assert report.startswith("📷") and "Риск:" in report
    assert handler.report_for_ocr_text("  ", job) == OCR_FAIL_TEXT


class FakeAPI:
    def __init__(self, data=b"x", fail=False):
        self.sent, self.data, self.fail = [], data, fail

    def send_message(self, chat_id, text, reply_markup=None):
        self.sent.append(text)

    def download_file(self, file_id, max_bytes):
        if self.fail:
            raise TelegramError("download: URLError")
        return self.data


def test_run_ocr_download_failure_is_reported():
    api = FakeAPI(fail=True)
    _run_ocr(OcrJob(1, "f", "", ()), api)
    assert api.sent[-1] == OCR_FAIL_TEXT


def test_run_ocr_success(monkeypatch):
    monkeypatch.setattr(ocr, "image_to_text", lambda data: "Срочно сообщите код из смс")
    api = FakeAPI()
    _run_ocr(OcrJob(1, "f", "", ()), api)
    assert "Риск:" in api.sent[-1]


def test_image_to_text_rejects_empty_and_huge():
    with pytest.raises(ocr.OcrError):
        ocr.image_to_text(b"")
    with pytest.raises(ocr.OcrError):
        ocr.image_to_text(b"0" * (ocr.MAX_FILE_BYTES + 1))


@pytest.mark.skipif(not HAS_TESSERACT, reason="tesseract не установлен")
def test_garbage_image_does_not_crash():
    with pytest.raises(ocr.OcrError):
        ocr.image_to_text(b"\xff\xd8\xff not really a jpeg" * 100)


@pytest.mark.skipif(not HAS_TESSERACT, reason="tesseract не установлен")
def test_real_screenshot():
    pytest.importorskip("PIL")
    from PIL import Image, ImageDraw, ImageFont

    font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    try:
        font = ImageFont.truetype(font_path, 40)
    except OSError:
        pytest.skip("нет шрифта")
    img = Image.new("RGB", (1000, 500), "white")
    d = ImageDraw.Draw(img)
    for i, line in enumerate(["Ваша карта заблокирована.", "Срочно перейдите на", "sberbank-unblock.ru"]):
        d.text((40, 40 + i * 70), line, font=font, fill="black")
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    text = ocr.image_to_text(buf.getvalue())
    assert "заблокирована" in text.lower() and "sberbank-unblock.ru" in text


# --- Скачивание файла ------------------------------------------------------------

@pytest.mark.parametrize("info", [
    {"file_path": "../../etc/passwd.txt", "file_size": 10},
    {"file_path": "photos/a b.jpg", "file_size": 10},
    {"file_path": "photos/file.jpg", "file_size": 10 ** 9},
    "junk",
])
def test_download_rejects_bad_file_info(monkeypatch, info):
    monkeypatch.setattr(TelegramAPI, "call", lambda self, m, p, timeout=None: info)
    with pytest.raises(TelegramError):
        TelegramAPI(FAKE_TOKEN).download_file("id", ocr.MAX_FILE_BYTES)


def _screenshot(bg, bubble, fg, font_size=34):
    """Скриншот чата, уменьшенный и пересжатый, как это делает Telegram."""
    from PIL import Image, ImageDraw, ImageFont

    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", font_size)
    except OSError:
        pytest.skip("нет шрифта")
    lines = ["Здравствуйте, это служба безопасности", "банка. На ваше имя оформлен кредит.",
             "Переведите все свои деньги на", "безопасный счёт и никому не",
             "рассказывайте о нашем разговоре."]
    img = Image.new("RGB", (1170, 2532), bg)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((40, 700, 1130, 700 + len(lines) * font_size * 1.4 + 60), 40, fill=bubble)
    for i, line in enumerate(lines):
        d.text((70, 730 + i * font_size * 1.4), line, font=font, fill=fg)
    img.thumbnail((1280, 1280))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=80)
    return buf.getvalue()


@pytest.mark.skipif(not HAS_TESSERACT, reason="tesseract не установлен")
@pytest.mark.parametrize("colors", [
    ((255, 255, 255), (233, 233, 235), (0, 0, 0)),      # светлая тема, серый пузырь
    ((255, 255, 255), (0, 122, 255), (255, 255, 255)),  # светлая, синий пузырь
    ((0, 0, 0), (38, 38, 40), (255, 255, 255)),         # тёмная тема
    ((0, 0, 0), (0, 90, 200), (255, 255, 255)),         # тёмная, синий пузырь (раньше — пусто!)
    ((14, 22, 33), (43, 82, 120), (255, 255, 255)),     # тёмная тема Telegram
])
def test_screenshots_in_all_themes_are_detected(colors):
    pytest.importorskip("PIL")
    from proverka import analyze

    text = ocr.image_to_text(_screenshot(*colors))
    assert analyze(text).score >= 50, text


def test_clean_ocr_text():
    assert ocr.clean_ocr_text("забло-\nкирована") == "заблокирована"
    assert ocr.clean_ocr_text("sberbank-help. ru") == "sberbank-help.ru"


def test_bright_variant_rejects_bomb_and_garbage():
    pytest.importorskip("PIL")
    from PIL import Image

    assert ocr._bright_text_variant(b"not an image") is None
    buf = io.BytesIO()
    Image.new("L", (5000, 5000)).save(buf, format="PNG")  # 25 Мп > лимита 12 Мп
    assert ocr._bright_text_variant(buf.getvalue()) is None


def test_ocr_report_shows_recognized_text():
    report = handler.report_for_ocr_text("Срочно сообщите\nкод из смс", OcrJob(1, "f", "", ()))
    assert "«Срочно сообщите код из смс»" in report
