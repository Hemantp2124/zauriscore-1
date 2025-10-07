## Quick orientation for code-writing agents

This repository analyzes EVM smart contracts (static and ML-based). The guidance below highlights the project's architecture, developer workflows, and concrete patterns an automated agent should follow when editing or adding code.

1) Big-picture architecture
- Core analysis entrypoints: `analyze_contract.py` (CLI) and `src/zauriscore/analyzers/comprehensive_contract_analysis.py` (main orchestrator).
- Modular analyzers live in `src/zauriscore/analyzers/` (Slither wrapper: `slither_utils.py`, Mythril wrapper: `mythril_analyzer.py`, gas analyzer, ML code in `comprehensive_contract_analysis.py`).
- Reporting/exports are in `src/zauriscore/utils/report_generator.py`.
- ML models & tokenizers: CodeBERT is used (`transformers`), loaded in `_load_codebert()` within the comprehensive analyzer.

2) Key developer workflows and commands
- Create virtualenv and run from project root (Windows PowerShell):
  & .\.venv\Scripts\Activate.ps1
  python -m pip install -r requirements/base.txt
  python analyze_contract.py <address> --api-key "<ETHERSCAN_API_KEY>"
- Tests: there are pytest files under `tests/`. Run with the venv python: `pytest -q`.
- Tools required for full static analysis: `solc` (Solidity compiler), `slither` and `mythril`. These are often best installed in WSL or Docker - the analyzer will log helpful errors when missing.

3) Environment & configuration
- API keys expected in environment or `.env` at repo root: `ETHERSCAN_API_KEY`, `POLYGONSCAN_API_KEY`, `OPTIMISM_ETHERSCAN_API_KEY`.
- The repository uses `python-dotenv` (see `load_dotenv()` calls). If keys are missing, the code may set fallbacks (or log warnings).

4) Project-specific conventions
- Temp contract files are written to `src/zauriscore/analyzers/temp_contracts`. When adding code that writes files, reuse this directory.
- Etherscan responses are sometimes double-wrapped JSON (starts with `{{...}}`). Parsing logic expects this and tries to recover; when adding parsing code, follow that pattern (see `prepare source code` section in `comprehensive_contract_analysis.py`).
- When concatenating multi-file sources into a single file (for Slither), SPDX license lines are stripped to avoid "Multiple SPDX license identifiers" errors.

5) ML-specific cautions
- CodeBERT has a token limit (~512). The code truncates very long source inputs before tokenization. If you change ML behavior, ensure inputs are chunked/truncated to avoid indexing errors.
- Tokenizer/model objects may be None if loading failed; guard calls and cast to `Any` locally before invoking to satisfy static checkers.

6) Slither/Mythril integration notes
- `slither` is initialized via `SlitherUtils.init_slither(contract_path)`; this method temporarily changes cwd to the contract path so `solc` resolves relative imports.
- If `solc` cannot find imports (e.g., `@openzeppelin/...`), that is expected unless node modules or full source tree are available. Use Docker/WSL to install dependencies or provide include paths.
- Mythril execution runs the `myth` CLI from the active environment; missing Python packages (e.g., `persistent`) should be installed in the same venv as the analyzer.

7) Logging and errors
- The project uses the module-level logger and writes `zauriscore.log`. Keep new logs structured and avoid printing secrets (mask API keys when logging).
- When adding network calls, use `requests` with timeouts and retries; the code already adds network diagnostics for Etherscan calls.

8) Tests and safety
- `test_api_keys.py` is a helpful local check for env variables and shows expected `.env` keys and basic validation logic.
- When modifying analyzer behavior, run `analyze_contract.py` for a verified contract address and review `zauriscore.log` for runtime diagnostics.

9) Files to inspect for patterns & examples
- `analyze_contract.py` — CLI, prints stages and uses `ComprehensiveContractAnalyzer`.
- `src/zauriscore/analyzers/comprehensive_contract_analysis.py` — main orchestration of fetching source, preparing files, invoking Slither/Mythril, ML scoring, and report generation.
- `src/zauriscore/analyzers/slither_utils.py` — Slither init, detector runner, CFG helpers.
- `src/zauriscore/utils/report_generator.py` — Etherscan V2/V1 source fetch fallback, report templates, exporters.
- `test_api_keys.py` — shows required env var names and expected formats.

If anything here is unclear or you want this to include more examples (e.g., exact CLI Docker commands for running Slither/Mythril against temp files), tell me which area to expand and I will iterate.
