# NumPyro #2384 — retained Docker validation

Summary of recorded results, not a fresh terminal capture.
Base: c4ee4145c253f0315359bd29d3114e2763a29227
Final patch SHA256:
2c6416878c2c8a124021076a17d8c2e85b039ed3d853de1478ea0f65c22dec5c
Environment: Linux ARM64 CPU, Python 3.12.16, JAX/JAXlib 0.10.2.
Non-root hosted Docker, 3 CPUs, 13 GiB memory limit.

Scientific case executions, including the required CI environment variants:
14,271 passed; 5,714 skipped; 60 xfailed; 95 xpassed; 0 failures or errors.
All 23 commands passed, with collected/executed test IDs checked.
Includes modeling, inference, examples, x64, tracer, two-device and typed-key lanes.
Previous PR head (c4ee414) control: exactly 5 expected failures and 14 passes.
Repair: 19/19 source cases, 19/19 installed-wheel cases, 2/2 real NUTS cases.
Regression assertions include auto_loc == [3, 7] for a lambda and x == 0 for a factory.
Across the two runs below: Ruff, formatting, license headers, ty, all hooks, docs and doctests passed.
README doctests and source-distribution/wheel builds passed.

Full science run: https://github.com/leninworld/numpyro/actions/runs/42003958097
That run failed only on a test decorator's formatting; its science jobs passed.
The final layout change preserves the test AST; production code is byte-identical.
Fresh final-patch lint, source/wheel tests and real NUTS verification passed:
https://github.com/leninworld/numpyro/actions/runs/42008388598

Limits: GPU unrun; upstream Python 3.11/3.14 x86 CI is separate.
Coverage upload omitted. TFP-chain and Gompertz-tracer selected cases all skipped here.
SteinVI name handling remains a separate follow-up, as requested in review.
