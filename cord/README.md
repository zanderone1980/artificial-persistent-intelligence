# CORD v4.1 — Counter-Operations & Risk Detection

CORD is the constitutional AI governance engine. It scores proposals against 14 safety checks covering 11 protocol articles, applies zero-trust validation, and records tamper-evident audit entries with PII redaction.

## Quick Start

```bash
npx cord-engine demo        # Watch it block 40 attacks
npx cord-engine eval "rm -rf /"   # Evaluate a single proposal
```

```javascript
const cord = require('cord-engine');

const result = cord.evaluate({ text: "rm -rf /" });
console.log(result.decision);         // "BLOCK"
console.log(result.explanation.summary);
```

## API Surface

| Function | Description |
|----------|-------------|
| `cord.evaluate(input)` | Evaluate a proposal, return verdict + explanation |
| `cord.validatePlan(tasks, goal)` | Validate aggregate task plan for cross-task threats |
| `cord.evaluateBatch(proposals)` | Evaluate multiple proposals in bulk |
| `cord.session.start(goal, scope)` | Start a scoped session with intent lock |
| `cord.session.end()` | End the current session |
| `cord.wrapOpenAI(client)` | Wrap OpenAI SDK with CORD enforcement |
| `cord.wrapAnthropic(client)` | Wrap Anthropic SDK with CORD enforcement |

## Framework Adapters

| Function | Framework |
|----------|-----------|
| `cord.frameworks.wrapLangChain(model)` | LangChain LLM/ChatModel |
| `cord.frameworks.wrapChain(chain)` | LangChain Chain/Runnable |
| `cord.frameworks.wrapTool(tool)` | LangChain Tool |
| `cord.frameworks.wrapCrewAgent(agent)` | CrewAI Agent |
| `cord.frameworks.wrapAutoGenAgent(agent)` | AutoGen Agent |

Python equivalents: `cord_engine.frameworks.wrap_langchain_llm()`, `wrap_crewai_agent()`, `wrap_llamaindex_llm()`, `CORDCallbackHandler`.

## Runtime Sandbox

```javascript
const { SandboxedExecutor } = require('cord-engine');
const sandbox = new SandboxedExecutor({
  repoRoot: '/my/project',
  maxOutputBytes: 1024 * 1024,
  maxNetworkBytes: 10 * 1024 * 1024,
});
```

## Evaluation Cache

Built-in LRU cache (1000 entries, 60s TTL) for repeated proposals:
```javascript
console.log(cord.cache.stats());
// { size: 42, hits: 150, misses: 58, hitRate: "72.1%" }
```

## Configuration

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `CORD_LOG_REDACTION` | `"pii"` | Audit log redaction: `"none"`, `"pii"`, `"full"` |
| `CORD_LOG_KEY` | — | 64-char hex key enables AES-256-GCM log encryption |
| `CORD_LOG_PATH` | `cord/cord.log.jsonl` | Audit log file path |

## Decision Flow

```
INPUT → VIGIL PRE-SCAN → HARD-BLOCK CHECKS → SCORED RISKS → SCOPE CHECK → LOG → VERDICT
```

Decisions: `ALLOW` | `CONTAIN` | `CHALLENGE` | `BLOCK`

## Tuning

- Edit `policies.js` to adjust weights, thresholds, regex patterns, and high-impact verbs
- `cord.js` uses these settings to compute a weighted score and map to a decision
- Logs are appended to `cord.log.jsonl` with hash-chaining for tamper detection

## Outputs

`evaluate(input)` returns:
```javascript
{
  decision,      // "ALLOW" | "CONTAIN" | "CHALLENGE" | "BLOCK"
  score,         // 0-99
  risks,         // { injection, exfil, privilege, ... }
  reasons,       // ["promptInjection", "exfil", ...]
  hardBlock,     // true if constitutional violation
  explanation,   // { summary, details, ... }
  log_id,        // SHA-256 hash of the audit entry
}
```
