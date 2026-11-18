# Образ для запуска бота на хостинге.
FROM python:3.12-slim

# Tesseract — программа для чтения текста со скриншотов (русский + английский).
# libzbar0 — чтение QR-кодов (через pyzbar; файл картинки разбирает Pillow).
# Ставим без «рекомендуемых» пакетов и чистим кэш: меньше образ, меньше
# лишних программ (меньше поверхность атаки).
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-rus libzbar0 \
    && rm -rf /var/lib/apt/lists/*

# Не запускаем от root: если в боте найдут уязвимость, у взломщика будет
# меньше прав.
# Pillow (обработка картинок) — версия закреплена в requirements.txt.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

RUN useradd --create-home --shell /usr/sbin/nologin bot
WORKDIR /app
COPY src/ /app/src/
ENV PYTHONPATH=/app/src PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER bot

# BOT_TOKEN и WEBHOOK_SECRET задаются в настройках хостинга, НЕ здесь.
# Порт хостинг передаёт сам через переменную PORT.
CMD ["python", "-m", "proverka_bot", "serve"]
