"""Rule package. Every non-underscore module here is imported automatically; Rule subclasses self-register.

To add a rule: create a new module (or add a class to an existing one) subclassing Rule / WorkflowRule with a
unique `id`. No change to the engine is required.
"""
from __future__ import annotations

import importlib
import pkgutil

from ..model import Rule

_loaded = False


def load_rules() -> dict[str, type[Rule]]:
    global _loaded
    if not _loaded:
        for mod in pkgutil.iter_modules(__path__):
            if not mod.name.startswith("_"):
                importlib.import_module(f"{__name__}.{mod.name}")
        _loaded = True
    return dict(sorted(Rule.registry.items(), key=lambda kv: (int(kv[1].category.split("-")[-1]) if kv[1].category else 99, kv[0])))
