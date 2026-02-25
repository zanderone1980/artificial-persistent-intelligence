/**
 * VIGIL Rate Limiter — DoS Protection
 *
 * Prevents resource exhaustion from rapid-fire scanning attacks.
 * Token bucket algorithm with per-session and global limits.
 *
 * Zero external dependencies.
 */

const EventEmitter = require('events');

const DEFAULTS = {
  // Token bucket config
  bucketSize: 100,        // Max tokens per bucket
  refillRate: 10,         // Tokens added per second
  refillInterval: 1000,   // Refill every 1s

  // Per-session limits
  sessionLimit: 50,       // Max scans per session per minute
  sessionWindow: 60000,   // 1 minute window

  // Global limits
  globalLimit: 500,       // Max scans globally per minute
  globalWindow: 60000,    // 1 minute window

  // Cooldown on limit hit
  cooldownMs: 30000,      // 30s cooldown after limit hit
};

/**
 * Token Bucket implementation for rate limiting.
 */
class TokenBucket {
  constructor(capacity, refillRate) {
    this.capacity = capacity;
    this.tokens = capacity;
    this.refillRate = refillRate; // tokens per ms
    this.lastRefill = Date.now();
  }

  refill() {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    const tokensToAdd = elapsed * this.refillRate;
    this.tokens = Math.min(this.capacity, this.tokens + tokensToAdd);
    this.lastRefill = now;
  }

  consume(count = 1) {
    this.refill();
    if (this.tokens >= count) {
      this.tokens -= count;
      return true;
    }
    return false;
  }

  getTokens() {
    this.refill();
    return Math.floor(this.tokens);
  }
}

/**
 * Sliding window counter for rate tracking.
 */
class SlidingWindow {
  constructor(limit, windowMs) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.requests = [];
  }

  record() {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    this.requests = this.requests.filter(t => t > cutoff);
    this.requests.push(now);
    return this.requests.length;
  }

  getCount() {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    this.requests = this.requests.filter(t => t > cutoff);
    return this.requests.length;
  }

  isExceeded() {
    return this.getCount() >= this.limit;
  }

  reset() {
    this.requests = [];
  }
}

/**
 * Rate Limiter with token bucket + sliding window.
 */
class RateLimiter extends EventEmitter {
  constructor(options = {}) {
    super();
    this.config = { ...DEFAULTS, ...options };

    // Global rate limit
    this.globalBucket = new TokenBucket(
      this.config.bucketSize,
      this.config.refillRate / 1000
    );
    this.globalWindow = new SlidingWindow(
      this.config.globalLimit,
      this.config.globalWindow
    );

    // Per-session rate limits
    this.sessionBuckets = new Map();
    this.sessionWindows = new Map();

    // Cooldown tracking
    this.cooldowns = new Map(); // sessionId -> cooldownEnd

    // Stats
    this.stats = {
      totalRequests: 0,
      allowed: 0,
      rejected: 0,
      cooldowns: 0,
    };

    // Start global refill timer
    this.refillTimer = setInterval(() => {
      this.globalBucket.refill();
    }, this.config.refillInterval);
    this.refillTimer.unref();
  }

  /**
   * Check if a request should be allowed.
   * @param {string} sessionId - Session identifier (or 'global')
   * @returns {{ allowed, reason, retryAfter, remaining }}
   */
  check(sessionId = 'global') {
    this.stats.totalRequests++;
    const now = Date.now();

    // Check cooldown first
    const cooldownEnd = this.cooldowns.get(sessionId);
    if (cooldownEnd && now < cooldownEnd) {
      this.stats.rejected++;
      this.stats.cooldowns++;
      return {
        allowed: false,
        reason: 'cooldown',
        retryAfter: Math.ceil((cooldownEnd - now) / 1000),
        remaining: 0,
      };
    }

    // Clear expired cooldown
    if (cooldownEnd && now >= cooldownEnd) {
      this.cooldowns.delete(sessionId);
    }

    // Check global window
    const globalCount = this.globalWindow.record();
    if (globalCount > this.config.globalLimit) {
      this._enterCooldown('global');
      this.stats.rejected++;
      return {
        allowed: false,
        reason: 'global_limit',
        retryAfter: Math.ceil(this.config.cooldownMs / 1000),
        remaining: 0,
      };
    }

    // Check global bucket
    if (!this.globalBucket.consume()) {
      this.stats.rejected++;
      return {
        allowed: false,
        reason: 'global_bucket',
        retryAfter: Math.ceil(1000 / this.config.refillRate),
        remaining: this.globalBucket.getTokens(),
      };
    }

    // Per-session checks (skip for 'global')
    if (sessionId !== 'global') {
      // Get or create session bucket
      if (!this.sessionBuckets.has(sessionId)) {
        this.sessionBuckets.set(
          sessionId,
          new TokenBucket(this.config.bucketSize, this.config.refillRate / 1000)
        );
        this.sessionWindows.set(
          sessionId,
          new SlidingWindow(this.config.sessionLimit, this.config.sessionWindow)
        );
      }

      const sessionBucket = this.sessionBuckets.get(sessionId);
      const sessionWindow = this.sessionWindows.get(sessionId);

      // Check session window
      const sessionCount = sessionWindow.record();
      if (sessionCount > this.config.sessionLimit) {
        this._enterCooldown(sessionId);
        this.stats.rejected++;
        this.emit('session_limit', { sessionId, count: sessionCount });
        return {
          allowed: false,
          reason: 'session_limit',
          retryAfter: Math.ceil(this.config.cooldownMs / 1000),
          remaining: 0,
        };
      }

      // Check session bucket
      if (!sessionBucket.consume()) {
        this.stats.rejected++;
        return {
          allowed: false,
          reason: 'session_bucket',
          retryAfter: Math.ceil(1000 / this.config.refillRate),
          remaining: sessionBucket.getTokens(),
        };
      }
    }

    this.stats.allowed++;
    return {
      allowed: true,
      reason: null,
      retryAfter: 0,
      remaining: sessionId === 'global'
        ? this.globalBucket.getTokens()
        : this.sessionBuckets.get(sessionId)?.getTokens() || 0,
    };
  }

  /**
   * Enter cooldown after limit hit.
   * @private
   */
  _enterCooldown(sessionId) {
    const cooldownEnd = Date.now() + this.config.cooldownMs;
    this.cooldowns.set(sessionId, cooldownEnd);
    this.emit('cooldown', { sessionId, cooldownEnd });
  }

  /**
   * Reset rate limits for a session.
   * @param {string} sessionId
   */
  resetSession(sessionId) {
    this.sessionBuckets.delete(sessionId);
    this.sessionWindows.delete(sessionId);
    this.cooldowns.delete(sessionId);
    this.emit('session_reset', sessionId);
  }

  /**
   * Clear all rate limiting state.
   */
  clear() {
    this.globalBucket = new TokenBucket(
      this.config.bucketSize,
      this.config.refillRate / 1000
    );
    this.globalWindow.reset();
    this.sessionBuckets.clear();
    this.sessionWindows.clear();
    this.cooldowns.clear();
    this.emit('cleared');
  }

  /**
   * Stop the rate limiter.
   */
  stop() {
    if (this.refillTimer) {
      clearInterval(this.refillTimer);
      this.refillTimer = null;
    }
  }

  /**
   * Get current stats.
   */
  getStats() {
    return {
      ...this.stats,
      globalTokens: this.globalBucket.getTokens(),
      globalWindowCount: this.globalWindow.getCount(),
      activeSessions: this.sessionBuckets.size,
      activeCooldowns: this.cooldowns.size,
    };
  }
}

// Singleton
const rateLimiter = new RateLimiter();

module.exports = {
  RateLimiter,
  rateLimiter,
  TokenBucket,
  SlidingWindow,
};
