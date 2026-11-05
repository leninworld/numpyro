# NumPyro #2384 — recorded review validation
Summary of retained Docker results; not a fresh terminal capture.
Source base: 0407e2d315868b7b0ffc78ba66e7b8786f3fdd37
Test-only feedback patch SHA256:
84f709c07fb83d83d30e532a175078b94ea22cf1dd27b11219c3179b318dc51e
Production initializer code is byte-identical to the reviewed base.
Linux ARM64 CPU; Python 3.12.16; JAX/JAXlib 0.10.2; locked dependencies.
Agent-controlled hosted Docker: 3 CPUs, 13 GiB limit per container.

Retained regressions: 8 source passes; 8 installed-wheel passes; no skips.
Installed-wheel NUTS smoke: 2 passes; no skips.
All three affected inference CI bundles passed with exact collected/executed IDs.
Affected bundle case executions: 818 passed, 5 skipped,
0 xfailed and 0 xpassed; no failures or errors.
Full Ruff/format/header/ty checks, configured hooks, docs and doctests passed.
README doctests and source-distribution/wheel builds passed.
Synthetic checkout/source-hash/status controls passed before the dependency payload.
Current run: https://github.com/leninworld/numpyro/actions/runs/42111886022

Production-wide scientific evidence is retained from the earlier 23-command run:
https://github.com/leninworld/numpyro/actions/runs/42003958097
That earlier run failed only formatting; the final lint/wheel run then passed:
https://github.com/leninworld/numpyro/actions/runs/42008388598
New validation covers the test-only trimming; production code did not change.
Limits: CPU only; coverage upload omitted; upstream multi-Python CI is separate.
