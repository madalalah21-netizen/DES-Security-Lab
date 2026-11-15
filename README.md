# DES Security Lab — Starter

A responsive English-language web UI prototype for the DES course project.

## Current status
This is **Phase 0: interface foundation only**. The dashboard is a visual prototype.
No encryption, decryption, brute-force, or analysis operation is implemented yet.

## Run the prototype
1. Extract the ZIP.
2. Open `web/index.html` in a browser, or open the project folder in VS Code.
3. No dependencies or internet connection are required for this prototype.

## Planned implementation
- Python DES implementation from scratch (not delegated to a DES library)
- Known-answer test vectors
- Encryption/decryption interface and 16-round trace
- Reduced-keyspace brute-force demonstration
- 8/12/16/20/24-bit timing experiments
- Weak/semi-weak key tests and avalanche-effect experiment
- Flask integration and evidence-backed report

## Important
DES is obsolete and must not be used to protect real data. Brute-force demonstrations will be restricted to controlled, reduced key spaces.
