# speed_limit.py
# ══════════════════════════════════════════════════════════════════════════════
# محدودیت سرعت (Token Bucket) + دروازه‌ی کوتای batch شده (QuotaGate)
#
# نسخه‌ی بازنویسی‌شده:
#   • رفع باگ جدی: قبلاً اگر اندازه‌ی یک چانک از ظرفیت باکت بیشتر بود
#     (مثلاً چانک ۵۱۲KB روی کانفیگ ۱Mbps → ظرفیت ۱۲۸KB)، حلقه‌ی consume
#     هیچ‌وقت شرط tokens >= n را برآورده نمی‌کرد و اتصال برای همیشه قفل می‌شد.
#     حالا مصرف به برش‌های حداکثر به‌اندازه‌ی ظرفیت شکسته می‌شود.
#   • خواب تطبیقی دقیق‌تر (کف ۲ms، سقف ۲۵۰ms) → jitter کمتر و سرعت واقعی نزدیک‌تر
#     به مقدار تنظیم‌شده.
#   • QuotaGate: به‌جای گرفتن قفل سراسری LINKS برای هر چانک، مصرف را batch می‌کند
#     و نرخ هر سشن را با EWMA می‌سنجد. این بزرگ‌ترین عامل افزایش throughput است.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import time

from main import LINKS

# هر uuid یک Bucket جدا دارد؛ نرخ صفر (نامحدود) اصلاً Bucket نمی‌سازد.
_buckets: dict = {}

MIN_RATE = 1024          # حداقل نرخ (۱ KB/s) برای جلوگیری از تقسیم بر صفر
MIN_BURST = 64 * 1024    # حداقل ظرفیت burst تا چانک‌های معمولی بی‌دلیل صف نکشند
MAX_SLEEP = 0.25
MIN_SLEEP = 0.002


class _Bucket:
    __slots__ = ("rate", "capacity", "tokens", "last")

    def __init__(self, rate_bytes_per_sec: float):
        self.rate = float(max(rate_bytes_per_sec, MIN_RATE))
        # ظرفیت burst: معادل ۱ ثانیه از نرخ مجاز (حداقل ۶۴ کیلوبایت)
        self.capacity = max(self.rate, float(MIN_BURST))
        self.tokens = self.capacity
        self.last = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last
        if elapsed > 0:
            self.last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

    async def _consume_slice(self, n: float) -> None:
        while True:
            self._refill()
            if self.tokens >= n:
                self.tokens -= n
                return
            wait = (n - self.tokens) / self.rate
            # سقف کوتاه است تا تغییر نرخ از پنل سریع اعمال شود
            await asyncio.sleep(min(max(wait, MIN_SLEEP), MAX_SLEEP))

    async def consume(self, n: int) -> None:
        """n بایت را مصرف می‌کند؛ چانک‌های بزرگ‌تر از ظرفیت به برش‌های امن شکسته می‌شوند."""
        remaining = float(n)
        cap = self.capacity
        while remaining > 0:
            take = remaining if remaining <= cap else cap
            await self._consume_slice(take)
            remaining -= take


def _get_bucket(uuid: str, rate: int) -> _Bucket:
    target = max(float(rate), float(MIN_RATE))
    b = _buckets.get(uuid)
    if b is None or b.rate != target:
        b = _Bucket(rate)
        _buckets[uuid] = b
    return b


async def throttle(uuid: str, nbytes: int) -> None:
    """اگر کانفیگ محدودیت سرعت داشته باشد (speed_limit_bytes > 0) تا نوبت ارسال
    این تعداد بایت صبر می‌کند؛ در غیر این صورت فوراً و بدون سربار برمی‌گردد."""
    if nbytes <= 0:
        return
    link = LINKS.get(uuid)
    if not link:
        return
    rate = int(link.get("speed_limit_bytes", 0) or 0)
    if rate <= 0:
        return
    await _get_bucket(uuid, rate).consume(nbytes)


def reset_bucket(uuid: str) -> None:
    """با تغییر محدودیت سرعت یا حذف کانفیگ صدا زده می‌شود تا باکت قدیمی پاک شود."""
    _buckets.pop(uuid, None)


def prune_buckets() -> int:
    """باکت کانفیگ‌های حذف‌شده یا بدون محدودیت را پاک می‌کند (جلوگیری از رشد حافظه)."""
    removed = 0
    for uid in list(_buckets.keys()):
        link = LINKS.get(uid)
        if not link or int(link.get("speed_limit_bytes", 0) or 0) <= 0:
            _buckets.pop(uid, None)
            removed += 1
    return removed


# ══════════════════════════════════════════════════════════════════════════════
# QuotaGate — شمارش/کسر کوتا به‌صورت batch و تطبیقی
# ══════════════════════════════════════════════════════════════════════════════
QUOTA_MIN_BATCH = 32 * 1024
QUOTA_MAX_BATCH = 1 * 1024 * 1024
QUOTA_START_BATCH = 64 * 1024
QUOTA_CHECK_INTERVAL = 0.2   # سقف زمانی؛ حتی اگر batch پر نشود بعد از این مدت چک می‌شود


class QuotaGate:
    """
    به‌جای یک await روی قفل سراسری LINKS به‌ازای هر چانک، مصرف را جمع می‌زند و
    اندازه‌ی batch را بر اساس نرخ واقعی همان سشن (EWMA) زنده تنظیم می‌کند:
      • سشن پرسرعت → batch بزرگ → قفل/await کمتر → throughput بیشتر.
      • سشن کم‌ترافیک/تعاملی → batch کوچک → کوتا دقیق‌تر و قطع سریع‌تر.
    هیچ داده‌ای نگه داشته نمی‌شود؛ فقط لحظه‌ی «حسابرسی» تطبیقی است.
    حداکثر خطای موقت شمارش = اندازه‌ی batch جاری، که با flush() صفر می‌شود.
    """

    __slots__ = ("uuid", "pending", "last_check", "ok", "batch_bytes", "rate_ewma", "_consume")

    def __init__(self, uuid: str, consume):
        self.uuid = uuid
        self.pending = 0
        self.last_check = time.monotonic()
        self.ok = True
        self.batch_bytes = QUOTA_START_BATCH
        self.rate_ewma = 0.0
        self._consume = consume   # async (uuid, nbytes) -> bool

    async def add(self, nbytes: int) -> bool:
        if not self.ok:
            return False
        if nbytes <= 0:
            return True
        self.pending += nbytes
        now = time.monotonic()
        elapsed = now - self.last_check
        if self.pending >= self.batch_bytes or elapsed >= QUOTA_CHECK_INTERVAL:
            flush, self.pending = self.pending, 0
            if elapsed > 0:
                inst_rate = flush / elapsed
                self.rate_ewma = inst_rate if self.rate_ewma == 0 else (0.7 * self.rate_ewma + 0.3 * inst_rate)
                target = int(self.rate_ewma * QUOTA_CHECK_INTERVAL)
                self.batch_bytes = max(QUOTA_MIN_BATCH, min(QUOTA_MAX_BATCH, target or QUOTA_MIN_BATCH))
            self.last_check = now
            self.ok = await self._consume(self.uuid, flush)
            return self.ok
        return True

    async def flush(self) -> bool:
        """باقی‌مانده‌ی شمارش‌نشده را قطعی می‌کند (در پایان هر سشن حتماً صدا زده شود)."""
        if self.pending:
            flush, self.pending = self.pending, 0
            result = await self._consume(self.uuid, flush)
            self.ok = self.ok and result
        return self.ok
