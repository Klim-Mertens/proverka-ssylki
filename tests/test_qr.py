"""
QR-коды на картинках. Картинки с QR создаются прямо в тесте библиотекой
qrcode (если её нет — тесты чтения пропускаются). Сеть не используется.
"""

import io

import pytest

from proverka_bot import handler, ocr, qr
from proverka_bot.handler import OCR_FAIL_TEXT, OcrJob
from proverka_bot.server import _run_ocr

needs_zbar = pytest.mark.skipif(not qr.is_available(), reason="pyzbar/libzbar не установлены")


def qr_png(payload, with_text_area=False):
    qrcode = pytest.importorskip("qrcode")
    from PIL import Image

    img = qrcode.make(payload).convert("RGB")
    if with_text_area:  # QR внизу «скриншота» с белым полем сверху
        canvas = Image.new("RGB", (img.width, img.height + 300), "white")
        canvas.paste(img, (0, 300))
        img = canvas
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


@needs_zbar
def test_decode_qr_finds_link():
    assert qr.decode_qr(qr_png("https://sber-bonus.xyz/pay")) == ["https://sber-bonus.xyz/pay"]
    assert qr.decode_qr(qr_png("https://parking-oplata.top/", with_text_area=True)) == ["https://parking-oplata.top/"]


def test_links_filter_ignores_payment_and_text():
    codes = ["ST00012|Name=ООО Ромашка|PersonalAcc=40702810000000000000", "Привет", "https://a.xyz/x", "www.b.top"]
    assert qr.links_from_codes(codes) == ["https://a.xyz/x", "www.b.top"]


@pytest.mark.parametrize("data", [b"", b"not an image", b"\x89PNG\r\n\x1a\n" + b"\x00" * 50])
def test_decode_qr_garbage_is_empty(data):
    assert qr.decode_qr(data) == []


def test_decode_qr_rejects_huge_dimensions():
    pytest.importorskip("PIL")
    from PIL import Image

    out = io.BytesIO()
    Image.new("L", (ocr.MAX_SIDE + 10, 10)).save(out, format="PNG")
    assert qr.decode_qr(out.getvalue()) == []


def test_report_with_qr_link_only():
    job = OcrJob(1, "f", "", ())
    report = handler.report_for_ocr_text("", job, qr_links=["https://sberbank-oplata.xyz/pay"])
    assert "QR-код на картинке ведёт на сайт: sberbank-oplata[.]xyz" in report
    assert "sberbank-oplata.xyz" not in report  # адрес «обезврежен»
    assert int(report.split("Риск: ")[1].split()[0]) >= 50
    assert handler.report_for_ocr_text("", job, qr_links=[]) == OCR_FAIL_TEXT


class FakeAPI:
    def __init__(self, data):
        self.sent, self.data = [], data

    def send_message(self, chat_id, text, reply_markup=None):
        self.sent.append(text)

    def download_file(self, file_id, max_bytes):
        return self.data


def test_run_ocr_uses_qr_when_text_unreadable(monkeypatch):
    def no_text(data):
        raise ocr.OcrError("пусто")

    monkeypatch.setattr(ocr, "image_to_text", no_text)
    monkeypatch.setattr(qr, "decode_qr", lambda data: ["https://gosuslugi-oplata.top/x"])
    api = FakeAPI(b"img")
    _run_ocr(OcrJob(1, "f", "", ()), api)
    assert "gosuslugi-oplata[.]top" in api.sent[-1] and "Риск:" in api.sent[-1]


def test_run_ocr_without_qr_and_text_fails_gracefully(monkeypatch):
    def no_text(data):
        raise ocr.OcrError("пусто")

    monkeypatch.setattr(ocr, "image_to_text", no_text)
    monkeypatch.setattr(qr, "decode_qr", lambda data: [])
    api = FakeAPI(b"img")
    _run_ocr(OcrJob(1, "f", "", ()), api)
    assert api.sent[-1] == OCR_FAIL_TEXT
