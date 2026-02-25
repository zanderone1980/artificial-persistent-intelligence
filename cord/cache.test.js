/**
 * Tests for EvalCache (v4.1)
 * Verifies LRU cache behavior, TTL expiry, stats, and eviction.
 */

const { EvalCache } = require("./cache");

describe("EvalCache", () => {
  let cache;

  beforeEach(() => {
    cache = new EvalCache({ maxSize: 5, ttlMs: 1000 });
  });

  test("cache miss returns null", () => {
    expect(cache.get("hello")).toBeNull();
    expect(cache.stats().misses).toBe(1);
  });

  test("cache set + get returns same result", () => {
    const result = { decision: "ALLOW", score: 0, reasons: [] };
    cache.set("hello world", result);
    const cached = cache.get("hello world");
    expect(cached).not.toBeNull();
    expect(cached.decision).toBe("ALLOW");
    expect(cached.cached).toBe(true);
    expect(cache.stats().hits).toBe(1);
  });

  test("different texts produce different keys", () => {
    cache.set("text A", { decision: "ALLOW" });
    cache.set("text B", { decision: "BLOCK" });
    expect(cache.get("text A").decision).toBe("ALLOW");
    expect(cache.get("text B").decision).toBe("BLOCK");
  });

  test("TTL expiry clears stale entries", async () => {
    const shortTTL = new EvalCache({ ttlMs: 50 });
    shortTTL.set("expiring", { decision: "ALLOW" });
    expect(shortTTL.get("expiring")).not.toBeNull();

    // Wait for TTL
    await new Promise((r) => setTimeout(r, 100));
    expect(shortTTL.get("expiring")).toBeNull();
    expect(shortTTL.stats().misses).toBe(1);
  });

  test("max size eviction drops oldest entry", () => {
    for (let i = 0; i < 6; i++) {
      cache.set(`key-${i}`, { decision: "ALLOW", index: i });
    }
    // key-0 should be evicted (oldest)
    expect(cache.get("key-0")).toBeNull();
    // key-5 should still be there
    expect(cache.get("key-5")).not.toBeNull();
    expect(cache.stats().size).toBe(5);
  });

  test("clear() resets everything", () => {
    cache.set("a", { decision: "ALLOW" });
    cache.set("b", { decision: "BLOCK" });
    cache.clear();
    expect(cache.get("a")).toBeNull();
    expect(cache.get("b")).toBeNull();
    expect(cache.stats().size).toBe(0);
  });

  test("stats() tracks hits, misses, size", () => {
    cache.set("x", { decision: "ALLOW" });
    cache.get("x"); // hit
    cache.get("y"); // miss
    cache.get("z"); // miss

    const stats = cache.stats();
    expect(stats.size).toBe(1);
    expect(stats.hits).toBe(1);
    expect(stats.misses).toBe(2);
    expect(stats.hitRate).toBe("33.3%");
  });

  test("null/empty text is handled", () => {
    cache.set("", { decision: "ALLOW" });
    expect(cache.get("")).not.toBeNull();
    cache.set(null, { decision: "BLOCK" });
    expect(cache.get(null)).not.toBeNull();
  });

  test("cached results are copies (not references)", () => {
    const original = { decision: "ALLOW", score: 0, reasons: ["test"] };
    cache.set("copy-test", original);
    const cached = cache.get("copy-test");

    // Modifying cached result shouldn't affect stored version
    cached.score = 999;
    const fresh = cache.get("copy-test");
    expect(fresh.score).toBe(0);
  });

  test("default options are reasonable", () => {
    const defaultCache = new EvalCache();
    expect(defaultCache.maxSize).toBe(1000);
    expect(defaultCache.ttlMs).toBe(60000);
  });
});
