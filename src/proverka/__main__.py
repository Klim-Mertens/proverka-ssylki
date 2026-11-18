"""
Запуск из командной строки:
    python -m proverka "текст сообщения"
    echo "текст" | python -m proverka
"""

import sys

from . import analyze, format_report


def main() -> None:
    if len(sys.argv) > 1:
        text = " ".join(sys.argv[1:])
    else:
        text = sys.stdin.read()
    print(format_report(analyze(text)))


if __name__ == "__main__":
    main()
