"""Общие структуры данных: найденный признак и итог проверки."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Signal:
    """Один найденный признак риска (или, при weight == 0, — информация)."""

    rule_id: str      # короткий идентификатор правила
    weight: int       # вклад в риск, 0–100
    text: str         # объяснение простыми словами
    source: str       # 'text' — из текста сообщения, 'url' — из ссылки, 'combo' — сочетание, 'sender' — отправитель


@dataclass
class CheckResult:
    """Итог проверки сообщения."""

    score: int                      # итоговая оценка риска 0–100
    level: str                      # 'low' | 'medium' | 'high' | 'critical'
    verdict: str                    # короткий вывод для человека
    signals: list[Signal] = field(default_factory=list)   # признаки риска (weight > 0)
    notes: list[str] = field(default_factory=list)        # нейтральные пояснения
    advice: list[str] = field(default_factory=list)       # что делать
    urls: list[str] = field(default_factory=list)         # найденные адреса (обезвреженные)
    phones: list[str] = field(default_factory=list)       # найденные телефоны
    truncated: bool = False         # текст был слишком длинным и обрезан
