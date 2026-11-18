"""
Отчёт в виде интерактивного виджета Telegram (Bot API 10.4, ноябрь 2026):
шкала риска 0–100 и главные причины прямо в сообщении.

Включается переменной TG_WIDGETS=1. Если виджет не отправился (старая версия
Telegram, ошибка API), бот отвечает обычным текстом, как раньше.

Безопасность:
  * виджету НЕ разрешены запросы к боту (allow_queries не передаём);
  * текст в виджете выводится только через textContent — HTML-инъекция невозможна;
  * в состояние (chat_data, лимит 1024 байта) кладём только оценку и причины,
    без текста исходного сообщения.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from proverka.models import CheckResult

ENABLED = os.environ.get("TG_WIDGETS", "").strip() == "1"
HTML = (Path(__file__).with_name("widget_report.html")).read_text("utf-8")
MAX_STATE = 1024


def widget_state(result: CheckResult, max_reasons: int = 5) -> str:
    reasons = [s.text[:120] for s in result.signals[:max_reasons]]
    state: dict[str, Any] = {"s": result.score, "l": result.level, "v": result.verdict[:100], "r": reasons}
    while len(json.dumps(state, ensure_ascii=False).encode()) > MAX_STATE and state["r"]:
        state["r"].pop()
    return json.dumps(state, ensure_ascii=False, separators=(",", ":"))


def advice_text(result: CheckResult) -> str:
    """Короткое продолжение под виджетом: что делать (виджет показывает «почему»)."""
    lines = [f"Риск: {result.score} из 100. {result.verdict}"]
    if result.notes:
        lines += [""] + [f"ℹ️ {n}" for n in result.notes]
    if result.advice:
        lines += ["", "Что делать:"] + [f"✅ {a}" for a in result.advice]
    return "\n".join(lines)
