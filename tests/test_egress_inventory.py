import ast
from pathlib import Path

# Documented allowed network modules and their approved egress call sites
KNOWN_EGRESS_MODULES = {
    "app.services.headers": {"httpx"},
    "app.services.technology": {"httpx"},
    "app.services.subdomain": {"httpx"},
    "app.services.ssl": {"socket", "ssl"},
    "app.services.ports": {"socket", "asyncio"},
    "app.core.target_validation": {"socket"},
    "app.core.outbound": {"socket", "ssl", "httpx", "asyncio"},
}

NETWORK_MODULE_NAMES = {"httpx", "socket", "ssl", "urllib.request", "requests", "aiohttp"}


def test_egress_call_site_inventory():
    """Verify that all network-capable imports in app/ are strictly inventoried and approved."""
    app_dir = Path(__file__).resolve().parent.parent / "app"
    found_egress: dict[str, set[str]] = {}

    for py_file in app_dir.rglob("*.py"):
        rel_mod = "app." + ".".join(py_file.relative_to(app_dir).with_suffix("").parts)
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_name = alias.name.split(".")[0]
                    if root_name in NETWORK_MODULE_NAMES:
                        found_egress.setdefault(rel_mod, set()).add(root_name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                root_name = node.module.split(".")[0]
                if root_name in NETWORK_MODULE_NAMES:
                    found_egress.setdefault(rel_mod, set()).add(root_name)

    # Assert that no unapproved modules import network libraries
    for mod, imports in found_egress.items():
        assert mod in KNOWN_EGRESS_MODULES, f"Uninventoried network module: {mod} importing {imports}"
        for imp in imports:
            assert imp in KNOWN_EGRESS_MODULES[mod], f"Unexpected network import '{imp}' in {mod}"


def test_baseline_known_egress_coverage():
    """Verify that every documented egress module still exists in the codebase."""
    app_dir = Path(__file__).resolve().parent.parent / "app"
    for mod in KNOWN_EGRESS_MODULES:
        if mod == "app.core.outbound":
            continue  # Implemented in Step 1.2
        mod_parts = mod.split(".")[1:]
        mod_path = app_dir.joinpath(*mod_parts).with_suffix(".py")
        assert mod_path.exists(), f"Documented egress module missing: {mod_path}"
