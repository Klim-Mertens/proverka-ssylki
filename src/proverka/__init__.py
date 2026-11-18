"""
«Проверь ссылку» — ядро анти-фишинговой проверки сообщений.

Пример:
    from proverka import analyze, format_report
    result = analyze("Ваша карта заблокирована! Срочно перейдите: sberbank-help.ru")
    print(result.score)            # оценка риска 0–100
    print(format_report(result))   # объяснение простым языком
"""

from .analyzer import analyze, format_report
from .models import CheckResult, Signal

__all__ = ["analyze", "format_report", "CheckResult", "Signal"]
__version__ = "0.1.0"
