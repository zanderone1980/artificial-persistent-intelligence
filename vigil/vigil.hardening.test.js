/**
 * VIGIL Hardening Tests
 * Rate limiting, log rotation, semantic analysis, circuit breakers
 */

const fs = require('fs');
const path = require('path');
const { RateLimiter, TokenBucket, SlidingWindow } = require('./ratelimit');
const { LogRotator } = require('./logrotate');
const { CircuitBreaker, CircuitOpenError, CircuitRegistry, circuits, STATES } = require('./circuit');
const { SemanticAnalyzer, GRAY_ZONE_MIN, GRAY_ZONE_MAX } = require('./semantic');

// ── Rate Limiter Tests ───────────────────────────────────────────────────────

describe('TokenBucket', () => {
  test('starts with full capacity', () => {
    const bucket = new TokenBucket(10, 1);
    expect(bucket.getTokens()).toBe(10);
  });

  test('consume reduces tokens', () => {
    const bucket = new TokenBucket(10, 1);
    expect(bucket.consume(5)).toBe(true);
    expect(bucket.getTokens()).toBe(5);
  });

  test('consume fails when insufficient tokens', () => {
    const bucket = new TokenBucket(5, 1);
    expect(bucket.consume(10)).toBe(false);
    expect(bucket.getTokens()).toBe(5); // Unchanged
  });

  test('refill adds tokens over time', (done) => {
    const bucket = new TokenBucket(10, 10); // 10 tokens/sec
    bucket.consume(10); // Empty it
    setTimeout(() => {
      expect(bucket.getTokens()).toBeGreaterThan(0);
      done();
    }, 150);
  });
});

describe('SlidingWindow', () => {
  test('tracks request count within window', () => {
    const window = new SlidingWindow(100, 60000);
    window.record();
    window.record();
    expect(window.getCount()).toBe(2);
  });

  test('isExceeded when limit reached', () => {
    const window = new SlidingWindow(3, 60000);
    window.record();
    window.record();
    window.record();
    expect(window.isExceeded()).toBe(true);
  });

  test('reset clears all requests', () => {
    const window = new SlidingWindow(100, 60000);
    window.record();
    window.record();
    window.reset();
    expect(window.getCount()).toBe(0);
  });
});

describe('RateLimiter', () => {
  let limiter;

  beforeEach(() => {
    limiter = new RateLimiter({
      bucketSize: 10,
      refillRate: 10,
      sessionLimit: 5,
      sessionWindow: 60000,
      globalLimit: 100,
      globalWindow: 60000,
      cooldownMs: 1000,
    });
  });

  afterEach(() => {
    limiter.stop();
  });

  test('allows requests under limit', () => {
    const result = limiter.check('test-session');
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBeGreaterThan(0);
  });

  test('rejects when session limit exceeded', () => {
    for (let i = 0; i < 5; i++) {
      limiter.check('test-session');
    }
    const result = limiter.check('test-session');
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('session_limit');
  });

  test('cooldown after limit hit', () => {
    const limiter = new RateLimiter({
      bucketSize: 100,
      refillRate: 100,
      sessionLimit: 3,
      sessionWindow: 60000,
      globalLimit: 1000,
      cooldownMs: 100,
    });

    // Hit the session limit
    for (let i = 0; i < 3; i++) {
      limiter.check('cooldown-test');
    }
    limiter.check('cooldown-test'); // Triggers cooldown

    const result = limiter.check('cooldown-test');
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('cooldown');
    expect(result.retryAfter).toBeGreaterThan(0);

    // Check stats show cooldown was triggered
    const stats = limiter.getStats();
    expect(stats.cooldowns).toBeGreaterThan(0);

    limiter.stop();
  });

  test('resetSession clears session limits', () => {
    for (let i = 0; i < 5; i++) {
      limiter.check('reset-test');
    }
    limiter.resetSession('reset-test');
    const result = limiter.check('reset-test');
    expect(result.allowed).toBe(true);
  });

  test('tracks stats correctly', () => {
    limiter.check('stats-test');
    limiter.check('stats-test');
    const stats = limiter.getStats();
    expect(stats.totalRequests).toBe(2);
    expect(stats.allowed).toBe(2);
  });
});

// ── Log Rotation Tests ───────────────────────────────────────────────────────

describe('LogRotator', () => {
  const testDir = path.join(__dirname, 'test-logs');
  const testLog = path.join(testDir, 'test.log');

  beforeEach(() => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
    if (fs.existsSync(testLog)) {
      fs.unlinkSync(testLog);
    }
  });

  afterEach(() => {
    // Cleanup
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  test('creates log file on write', () => {
    const rotator = new LogRotator(testLog, { maxSizeBytes: 1000 });
    rotator.write('test line 1');
    expect(fs.existsSync(testLog)).toBe(true);
  });

  test('rotates when size exceeded', () => {
    const rotator = new LogRotator(testLog, {
      maxSizeBytes: 50,
      maxFiles: 3,
      compress: false,
    });

    // Write enough to exceed limit
    rotator.write('This is a longer line that will exceed the size limit quickly');
    rotator.write('Another long line to push it over the edge');

    const archives = rotator.listArchives();
    expect(archives.length).toBeGreaterThan(0);
  });

  test('compresses rotated files when enabled', () => {
    const rotator = new LogRotator(testLog, {
      maxSizeBytes: 50,
      compress: true,
    });

    rotator.write('Line 1: ' + 'x'.repeat(100));
    rotator.write('Line 2: ' + 'y'.repeat(100));

    const archives = rotator.listArchives();
    const compressed = archives.filter(a => a.compressed);
    expect(compressed.length).toBeGreaterThan(0);
  });

  test('enforces retention policy', () => {
    const rotator = new LogRotator(testLog, {
      maxSizeBytes: 30,
      maxFiles: 2,
      compress: false,
    });

    // Create multiple rotations
    for (let i = 0; i < 5; i++) {
      rotator.write('Batch ' + i + ': ' + 'x'.repeat(100));
    }

    const archives = rotator.listArchives();
    expect(archives.length).toBeLessThanOrEqual(2);
  });

  test('tracks stats', () => {
    const rotator = new LogRotator(testLog, { maxSizeBytes: 1000 });
    rotator.write('test');
    const stats = rotator.getStats();
    expect(stats.bytesWritten).toBeGreaterThan(0);
  });
});

// ── Circuit Breaker Tests ────────────────────────────────────────────────────

describe('CircuitBreaker', () => {
  let breaker;

  beforeEach(() => {
    breaker = new CircuitBreaker('test', {
      failureThreshold: 3,
      successThreshold: 2,
      timeout: 500,
      resetTimeout: 1000,
    });
  });

  test('starts closed', () => {
    expect(breaker.state).toBe(STATES.CLOSED);
  });

  test('opens after failure threshold', async () => {
    const failingFn = async () => { throw new Error('fail'); };

    for (let i = 0; i < 3; i++) {
      try { await breaker.execute(failingFn); } catch (e) {}
    }

    expect(breaker.state).toBe(STATES.OPEN);
  });

  test('rejects calls when open', async () => {
    const failingFn = async () => { throw new Error('fail'); };

    // Open the circuit
    for (let i = 0; i < 3; i++) {
      try { await breaker.execute(failingFn); } catch (e) {}
    }

    // Try to execute - should reject immediately
    await expect(breaker.execute(async () => 'success'))
      .rejects.toThrow(CircuitOpenError);
  });

  test('transitions to half-open after timeout', (done) => {
    const failingFn = async () => { throw new Error('fail'); };

    // Open the circuit
    (async () => {
      for (let i = 0; i < 3; i++) {
        try { await breaker.execute(failingFn); } catch (e) {}
      }

      expect(breaker.state).toBe(STATES.OPEN);

      // Wait for timeout
      setTimeout(() => {
        breaker.allowsRequests(); // Triggers transition check
        expect(breaker.state).toBe(STATES.HALF_OPEN);
        done();
      }, 600);
    })();
  });

  test('closes after successes in half-open', async () => {
    const failingFn = async () => { throw new Error('fail'); };
    const successFn = async () => 'success';

    // Open the circuit
    for (let i = 0; i < 3; i++) {
      try { await breaker.execute(failingFn); } catch (e) {}
    }

    // Wait for half-open
    await new Promise(r => setTimeout(r, 600));
    breaker.allowsRequests();

    // Succeed twice
    await breaker.execute(successFn);
    await breaker.execute(successFn);

    expect(breaker.state).toBe(STATES.CLOSED);
  });

  test('tracks stats', async () => {
    const successFn = async () => 'success';
    await breaker.execute(successFn);
    await breaker.execute(successFn);

    const status = breaker.getStatus();
    expect(status.stats.totalCalls).toBe(2);
    expect(status.stats.successes).toBe(2);
  });

  test('reset clears failure count', async () => {
    const failingFn = async () => { throw new Error('fail'); };

    for (let i = 0; i < 2; i++) {
      try { await breaker.execute(failingFn); } catch (e) {}
    }

    expect(breaker.failures).toBe(2);
    breaker.reset();
    expect(breaker.failures).toBe(0);
    expect(breaker.state).toBe(STATES.CLOSED);
  });
});

describe('CircuitRegistry', () => {
  let registry;

  beforeEach(() => {
    registry = new CircuitRegistry();
  });

  afterEach(() => {
    registry.stop();
  });

  test('creates breakers on demand', () => {
    const breaker1 = registry.get('api');
    const breaker2 = registry.get('api');
    expect(breaker1).toBe(breaker2); // Same instance
  });

  test('tracks multiple breakers', () => {
    registry.get('breaker1');
    registry.get('breaker2');
    const statuses = registry.getAllStatuses();
    expect(Object.keys(statuses)).toHaveLength(2);
  });

  test('resetAll resets all breakers', () => {
    const b1 = registry.get('b1');
    const b2 = registry.get('b2');
    b1.forceOpen();
    b2.forceOpen();

    registry.resetAll();
    expect(b1.state).toBe(STATES.CLOSED);
    expect(b2.state).toBe(STATES.CLOSED);
  });
});

// ── Semantic Analyzer Tests ──────────────────────────────────────────────────

describe('SemanticAnalyzer', () => {
  let analyzer;

  beforeEach(() => {
    // Don't use real API key in tests
    delete process.env.ANTHROPIC_API_KEY;
    analyzer = new SemanticAnalyzer({
      timeout: 1000,
      cacheTTL: 5000,
    });
  });

  afterEach(() => {
    analyzer.clearCache();
  });

  test('isGrayZone detects correct range', () => {
    expect(SemanticAnalyzer.isGrayZone(2)).toBe(false);
    expect(SemanticAnalyzer.isGrayZone(3)).toBe(true);
    expect(SemanticAnalyzer.isGrayZone(4)).toBe(true);
    expect(SemanticAnalyzer.isGrayZone(5)).toBe(true);
    expect(SemanticAnalyzer.isGrayZone(6)).toBe(true);
    expect(SemanticAnalyzer.isGrayZone(7)).toBe(false);
  });

  test('skips analysis for non-gray scores', async () => {
    const result = await analyzer.analyze('test', 1);
    expect(result.source).toBe('score_heuristic');
    expect(result.action).toBe('ALLOW');
  });

  test('uses fallback when API key not set', async () => {
    const result = await analyzer.analyze('suspicious text', 4);
    expect(result.source).toBe('fallback');
    expect(['ALLOW', 'CHALLENGE', 'BLOCK']).toContain(result.action);
  });

  test('caches results', async () => {
    const text = 'cached test text';
    const result1 = await analyzer.analyze(text, 4);
    const result2 = await analyzer.analyze(text, 4);

    expect(result1.source).toBe('fallback');
    expect(result2.source).toBe('cache');
  });

  test('tracks stats', async () => {
    await analyzer.analyze('test1', 4);
    await analyzer.analyze('test2', 4);
    const stats = analyzer.getStats();
    expect(stats.totalRequests).toBe(2);
    expect(stats.fallbacks).toBe(2);
  });

  test('clearCache empties cache', async () => {
    await analyzer.analyze('test', 4);
    expect(analyzer.getStats().cacheSize).toBe(1);
    analyzer.clearCache();
    expect(analyzer.getStats().cacheSize).toBe(0);
  });
});

// ── Integration: Rate Limiter + Circuit Breaker ──────────────────────────────

describe('Hardening Integration', () => {
  test('rate limiter protects circuit breaker from DoS', () => {
    const limiter = new RateLimiter({
      bucketSize: 5,
      refillRate: 1,
      sessionLimit: 5,
      sessionWindow: 60000,
      globalLimit: 100,
      cooldownMs: 500,
    });

    const breaker = new CircuitBreaker('protected', {
      failureThreshold: 3,
      timeout: 1000,
    });

    // Simulate rapid requests that would trip the breaker
    let allowed = 0;
    let rejected = 0;

    for (let i = 0; i < 10; i++) {
      const rateResult = limiter.check('integration-test');
      if (rateResult.allowed) {
        allowed++;
      } else {
        rejected++;
      }
    }

    // Rate limiter should have rejected some
    expect(rejected).toBeGreaterThan(0);
    expect(allowed).toBeLessThan(10);

    limiter.stop();
  });
});
