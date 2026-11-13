# NumPyro #2384 — recorded feedback validation
Summary of retained hosted Docker results; not a fresh terminal capture.
Review: 5888051951. Source base: 4fc1aa404da930f8fb8ee7f2effc01637e08d6fb
Candidate util Git blob: 6b0417b3ab6f8b0420654c274a814722aba4c4cc
Linux ARM64 CPU; Python 3.14.10 and 3.12.16; frozen JAX/JAXlib 0.10.2.
23 hosted jobs completed successfully; exact source/blob checks retained.
23 Python 3.14 scientific commands: 14,256 passed; 95 XPASS;
5,724 skipped; 60 XFAIL; no reported failures or errors.
Counts are executions, including overlapping selections, not unique tests.
Python 3.12 inference/MCMC repeats: 966 passed, 44 skipped.
Focused source and installed wheel: 14 passes each on Python 3.14;
12 passes and 2 version skips each on Python 3.12.
Installed-wheel NUTS: 2 passes on each Python version, no skips.
Factory-value regression pair: 2 expected baseline failures, 2 candidate passes.
Plate/observed examples check compatible behavior, not new regression failures.
Lint, hooks, docs/doctests, README and package builds completed successfully.
All-skip commands: tracer-gompertz (2), chains-tfp (10), nested-x64 (10).
Gompertz variance and TFP chain skips come from upstream test markers. The nested-sampling skip message
covers both missing double precision and an unavailable jaxns import; which applied was not recorded.
Jaxns 2.6.9 and tfp-nightly 0.26.0.dev20261020 were installed.
These optional integrations were not exercised; skips are not passing coverage.
Upstream benchmark report uses JAX 0.12.0.1; no CI equivalence claimed.
CPU only; GPU and upstream multi-Python CI remain separate.
Run: https://github.com/leninworld/numpyro/actions/runs/43457969227
