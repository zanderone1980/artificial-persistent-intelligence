/**
 * VIGIL Circuit Breaker — Failure Recovery
 *
 * Prevents cascade failures when components (LLM, file I/O, etc.) fail.
 * Implements the circuit breaker pattern:
 *   CLOSED → OPEN → HALF_OPEN → CLOSED
 *
 * Zero external dependencies.
 */

const { EventEmitter } = require('events');

const DEFAULTS = {
  failureThreshold: 5,      // Failures before opening circuit
  successThreshold: 3,      // Successes in half-open to close
  timeout: 30000,           // Time in open state before half-open (30s)
  resetTimeout: 300000,     // Full reset after 5 min of no activity
};

const STATES = {
  CLOSED: 'closed',      // Normal operation
  OPEN: 'open',          // Failing fast, not attempting operations
  HALF_OPEN: 'half_open', // Testing if service recovered
};

class CircuitBreaker extends EventEmitter {
  constructor(name, options = {}) {
    super();
    this.name = name;
    this.config = { ...DEFAULTS, ...options };
    this.state = STATES.CLOSED;
    this.failures = 0;
    this.successes = 0;
    this.lastFailure = null;
    this.lastActivity = Date.now();
    this.stateChangedAt = Date.now();

    // Stats
    this.stats = {
      totalCalls: 0,
      successes: 0,
      failures: 0,
      rejects: 0, // Calls rejected due to open circuit
      stateChanges: 0,
    };
  }

  /**
   * Execute a function with circuit breaker protection.
   * @param {Function} fn - Async function to execute
   * @returns {Promise<any>} Result of fn
   * @throws {CircuitOpenError} If circuit is open
   */
  async execute(fn) {
    this.stats.totalCalls++;
    this.lastActivity = Date.now();

    // Check if we should transition from OPEN to HALF_OPEN
    if (this.state === STATES.OPEN) {
      const timeInOpen = Date.now() - this.stateChangedAt;
      if (timeInOpen >= this.config.timeout) {
        this._transitionTo(STATES.HALF_OPEN);
      }
    }

    // Reject if circuit is open
    if (this.state === STATES.OPEN) {
      this.stats.rejects++;
      const error = new CircuitOpenError(
        `Circuit breaker '${this.name}' is open`,
        this.stateChangedAt + this.config.timeout - Date.now()
      );
      this.emit('reject', { error });
      throw error;
    }

    // Execute the function
    try {
      const result = await fn();
      this._onSuccess();
      return result;
    } catch (error) {
      this._onFailure();
      throw error;
    }
  }

  /**
   * Record a successful operation.
   * @private
   */
  _onSuccess() {
    this.stats.successes++;
    this.failures = 0;

    if (this.state === STATES.HALF_OPEN) {
      this.successes++;
      if (this.successes >= this.config.successThreshold) {
        this._transitionTo(STATES.CLOSED);
      }
    }
  }

  /**
   * Record a failed operation.
   * @private
   */
  _onFailure() {
    this.stats.failures++;
    this.failures++;
    this.lastFailure = Date.now();

    if (this.state === STATES.CLOSED && this.failures >= this.config.failureThreshold) {
      this._transitionTo(STATES.OPEN);
    } else if (this.state === STATES.HALF_OPEN) {
      // Any failure in half-open immediately opens the circuit
      this._transitionTo(STATES.OPEN);
    }
  }

  /**
   * Transition to a new state.
   * @private
   */
  _transitionTo(newState) {
    if (this.state === newState) return;

    const oldState = this.state;
    this.state = newState;
    this.stateChangedAt = Date.now();
    this.stats.stateChanges++;

    if (newState === STATES.HALF_OPEN) {
      this.successes = 0;
    }

    this.emit('state_change', { from: oldState, to: newState });
    console.log(`Circuit '${this.name}': ${oldState} → ${newState}`);
  }

  /**
   * Manually reset the circuit breaker.
   */
  reset() {
    this._transitionTo(STATES.CLOSED);
    this.failures = 0;
    this.successes = 0;
    this.emit('reset');
  }

  /**
   * Force the circuit open.
   */
  forceOpen() {
    this._transitionTo(STATES.OPEN);
  }

  /**
   * Check if circuit allows requests.
   * @returns {boolean}
   */
  allowsRequests() {
    // Auto-transition from OPEN to HALF_OPEN if timeout elapsed
    if (this.state === STATES.OPEN) {
      const timeInOpen = Date.now() - this.stateChangedAt;
      if (timeInOpen >= this.config.timeout) {
        this._transitionTo(STATES.HALF_OPEN);
        return true;
      }
      return false;
    }
    return true;
  }

  /**
   * Get current state and stats.
   */
  getStatus() {
    return {
      name: this.name,
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      lastFailure: this.lastFailure,
      lastActivity: this.lastActivity,
      timeInState: Date.now() - this.stateChangedAt,
      stats: this.stats,
    };
  }

  /**
   * Check if circuit should be reset due to inactivity.
   */
  checkReset() {
    const inactiveTime = Date.now() - this.lastActivity;
    if (inactiveTime >= this.config.resetTimeout && this.state !== STATES.CLOSED) {
      this.reset();
      return true;
    }
    return false;
  }
}

/**
 * Error thrown when circuit is open.
 */
class CircuitOpenError extends Error {
  constructor(message, retryAfterMs) {
    super(message);
    this.name = 'CircuitOpenError';
    this.retryAfter = retryAfterMs;
    this.code = 'CIRCUIT_OPEN';
  }
}

/**
 * Circuit Breaker Registry — manage multiple breakers.
 */
class CircuitRegistry extends EventEmitter {
  constructor() {
    super();
    this.breakers = new Map();
    this.checkInterval = null;
  }

  /**
   * Get or create a circuit breaker.
   * @param {string} name
   * @param {object} options
   * @returns {CircuitBreaker}
   */
  get(name, options = {}) {
    if (!this.breakers.has(name)) {
      const breaker = new CircuitBreaker(name, options);
      breaker.on('state_change', (data) => {
        this.emit('state_change', { name, ...data });
      });
      this.breakers.set(name, breaker);
    }
    return this.breakers.get(name);
  }

  /**
   * Start periodic reset checks.
   */
  start() {
    if (this.checkInterval) return;
    this.checkInterval = setInterval(() => {
      for (const breaker of this.breakers.values()) {
        breaker.checkReset();
      }
    }, 60000); // Check every minute
    this.checkInterval.unref();
  }

  /**
   * Stop periodic checks.
   */
  stop() {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
  }

  /**
   * Get all breaker statuses.
   */
  getAllStatuses() {
    const statuses = {};
    for (const [name, breaker] of this.breakers.entries()) {
      statuses[name] = breaker.getStatus();
    }
    return statuses;
  }

  /**
   * Reset all breakers.
   */
  resetAll() {
    for (const breaker of this.breakers.values()) {
      breaker.reset();
    }
  }
}

// Singleton registry
const circuits = new CircuitRegistry();

module.exports = {
  CircuitBreaker,
  CircuitOpenError,
  CircuitRegistry,
  circuits,
  STATES,
};
