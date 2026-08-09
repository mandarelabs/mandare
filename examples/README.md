# Examples

Five runnable scenarios, one per acceptance demo. Each is self-contained:
its README tells the whole story, its `run.sh` runs the exact script CI
asserts on every push — these are not staged walkthroughs, they are the
acceptance tests wearing their explanations.

| # | Scenario | The claim it proves | Run |
|---|---|---|---|
| 1 | [Runaway budget cap](01-runaway-budget-cap/) | A runaway agent loop dies at €20, with proof | `./run.sh` |
| 2 | [Stolen token is dead paper](02-stolen-token-dead-paper/) | Theft, replay, and a mid-task kill all fail closed | `./run.sh` |
| 3 | [One mandate, zero prompts](03-one-mandate-40-prompts/) | One signed mandate replaces 40 permission prompts | `./run.sh` |
| 4 | [The card declines at the network](04-card-declines-at-network/) | One cap governs LLM spend AND card spend | `./run.sh` |
| 5 | [The rewrite that can't hide](05-the-rewrite-that-cant-hide/) | Truncation/rewrite by a key-holding attacker is convicted | `./run.sh` |

No API keys, no accounts, no network calls to real providers — every scenario
runs against a mock provider (and, in #4, a simulated card network). Setup
once from the repo root:

```bash
./install.sh
```

Then any `examples/*/run.sh`, or the equivalent `pnpm demo*` script directly.
