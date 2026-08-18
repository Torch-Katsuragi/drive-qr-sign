"""同じことを何度も外へ聞かないための、寿命つきの覚え書き。

署名ページを1枚出すあいだに、同じ書類を Drive から2回落として、同じ共有設定を
2回問い合わせていた（実測: `fetch` 1.1秒 / `permissions.list` 0.3秒）。
待ち時間のほとんどがこの往復で、描画側の重さではなかった。

⚠**寿命は短く保つ**。ここに置くのは「1回の画面表示のあいだ持てばよい」もので、
長く持つと、他の人が押した直後に古い状態を見せることになる。署名そのものは
この覚え書きを通さない（`fresh=True`）——古い版を土台に署名すると、
あいだに押された人の署名を落とすため。
"""

from __future__ import annotations

import threading
import time
from typing import Any


class TimedCache:
    """寿命つきの辞書。Cloud Run は同期エンドポイントを別スレッドで回すので鍵をかける。"""

    def __init__(self, ttl: float, *, clock=time.monotonic):
        self.ttl = ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[Any, tuple[float, Any]] = {}

    def get(self, key: Any, default: Any = None) -> Any:
        with self._lock:
            found = self._entries.get(key)
            if found is None:
                return default
            expires_at, value = found
            if expires_at <= self._clock():
                del self._entries[key]
                return default
            return value

    def put(self, key: Any, value: Any) -> Any:
        with self._lock:
            self._entries[key] = (self._clock() + self.ttl, value)
        return value

    def forget(self, key: Any) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
