"""CLI and import shim for the deployable portfolio selector."""

from pathlib import Path
import importlib.util


_source = Path(__file__).resolve().parents[1] / "bundle/portfolio/portfolio_catalog.py"
_spec = importlib.util.spec_from_file_location("vpn_portfolio_selector", _source)
if _spec is None or _spec.loader is None:
    raise ImportError("Portfolio selector is unavailable")
_selector = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_selector)

EGRESS_MODES = _selector.EGRESS_MODES
PROFILE_SETS = _selector.PROFILE_SETS
TOP10_STEMS = _selector.TOP10_STEMS
load_catalog = _selector.load_catalog
main = _selector.main
profile_name = _selector.profile_name
select_profiles = _selector.select_profiles
select_top10 = _selector.select_top10
select_numbers = _selector.select_numbers


if __name__ == "__main__":
    raise SystemExit(main())
