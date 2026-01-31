using System.Collections.Concurrent;

namespace Biosphere3;

public static class RateLimitStore
{
    private static readonly ConcurrentDictionary<string, FixedWindowLimiter> Limiters = new();

    public static FixedWindowLimiter GetLimiter(string key)
    {
        return Limiters.GetOrAdd(key, _ => new FixedWindowLimiter(2000, TimeSpan.FromSeconds(60)));
    }
}

public class FixedWindowLimiter
{
    private readonly int _limit;
    private readonly TimeSpan _window;
    private int _count;
    private DateTime _windowStart;
    private readonly object _lock = new();

    public FixedWindowLimiter(int limit, TimeSpan window)
    {
        _limit = limit;
        _window = window;
        _windowStart = DateTime.UtcNow;
        _count = 0;
    }

    public bool AllowRequest()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            if (now - _windowStart >= _window)
            {
                _windowStart = now;
                _count = 0;
            }

            if (_count >= _limit)
            {
                return false;
            }

            _count++;
            return true;
        }
    }

    public int GetRetryAfterSeconds()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var remaining = _window - (now - _windowStart);
            return Math.Max(1, (int)Math.Ceiling(remaining.TotalSeconds));
        }
    }

    public int GetRemaining()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            if (now - _windowStart >= _window)
            {
                return _limit;
            }

            return Math.Max(0, _limit - _count);
        }
    }

    public int GetResetSeconds()
    {
        return GetRetryAfterSeconds();
    }
}
