"""
Ограничитель частоты: не более N проверок в минуту на человека.

Хранит в памяти только числа и время (id пользователя → моменты запросов),
а НЕ тексты сообщений. После перезапуска всё забывается. Старые записи
удаляются, а общее число записей ограничено, чтобы память не росла бесконечно.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque


class RateLimiter:
    def __init__(self, per_minute: int, max_users: int = 10_000) -> None:
        self.per_minute = per_minute
        self.max_users = max_users
        self._hits: OrderedDict[int, deque[float]] = OrderedDict()

    def allow(self, user_id: int, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        hits = self._hits.get(user_id)
        if hits is None:
            hits = self._hits[user_id] = deque()
            # Если людей слишком много — забываем самого давнего.
            while len(self._hits) > self.max_users:
                self._hits.popitem(last=False)
        else:
            self._hits.move_to_end(user_id)
        while hits and now - hits[0] > 60:
            hits.popleft()
        if len(hits) >= self.per_minute:
            return False
        hits.append(now)
        return True
