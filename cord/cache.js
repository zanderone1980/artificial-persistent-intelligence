/**
 * CORD Evaluation Cache — LRU with TTL.
 *
 * Caches evaluateProposal() results by text hash to avoid
 * recomputing identical proposals within a time window.
 *
 * Usage:
 *   const { EvalCache } = require("./cache");
 *   const cache = new EvalCache({ ttlMs: 60000, maxSize: 1000 });
 *   const cached = cache.get("some proposal text");
 *   if (!cached) { result = evaluate(...); cache.set("some proposal text", result); }
 */

const crypto = require("crypto");

class EvalCache {
  constructor(options = {}) {
    this.maxSize = options.maxSize || 1000;
    this.ttlMs = options.ttlMs || 60000; // 60s default
    this.cache = new Map();
    this.hits = 0;
    this.misses = 0;
  }

  /**
   * Generate a cache key from proposal text.
   */
  _key(text) {
    return crypto.createHash("sha256").update(text || "").digest("hex");
  }

  /**
   * Get a cached result. Returns null on miss or expiry.
   */
  get(text) {
    const key = this._key(text);
    const entry = this.cache.get(key);

    if (!entry) {
      this.misses++;
      return null;
    }

    // Check TTL
    if (Date.now() - entry.timestamp > this.ttlMs) {
      this.cache.delete(key);
      this.misses++;
      return null;
    }

    this.hits++;
    return { ...entry.result, cached: true };
  }

  /**
   * Cache an evaluation result.
   */
  set(text, result) {
    const key = this._key(text);

    // Evict oldest if at capacity
    if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
      const oldest = this.cache.keys().next().value;
      this.cache.delete(oldest);
    }

    this.cache.set(key, {
      result: { ...result },
      timestamp: Date.now(),
    });
  }

  /**
   * Clear the entire cache.
   */
  clear() {
    this.cache.clear();
    this.hits = 0;
    this.misses = 0;
  }

  /**
   * Get cache statistics.
   */
  stats() {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      ttlMs: this.ttlMs,
      hits: this.hits,
      misses: this.misses,
      hitRate: this.hits + this.misses > 0
        ? (this.hits / (this.hits + this.misses) * 100).toFixed(1) + "%"
        : "0.0%",
    };
  }
}

module.exports = { EvalCache };
