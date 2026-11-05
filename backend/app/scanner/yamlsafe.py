"""Safe YAML loading that keeps source line numbers.

* Uses PyYAML's SafeLoader only (no arbitrary object construction).
* Mappings become LineDict, which remembers the 1-based line of every key.
* GitHub's `on:` key is preserved (YAML 1.1 would otherwise turn it into True).
* Guards against alias-expansion abuse ("billion laughs") and oversized documents.
"""
from __future__ import annotations

import yaml
from yaml.nodes import MappingNode, ScalarNode

MAX_YAML_BYTES = 2 * 1024 * 1024
MAX_ALIASES = 200


class YamlError(Exception):
    def __init__(self, message: str, line: int | None = None):
        super().__init__(message)
        self.line = line


class LineDict(dict):
    """dict that also records the source line of each key (`key_lines`) and of itself (`line`)."""

    __slots__ = ("key_lines", "line")

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.key_lines: dict = {}
        self.line: int = 0

    def line_of(self, key, default: int | None = None) -> int | None:
        return self.key_lines.get(key, default if default is not None else (self.line or None))


class LineList(list):
    __slots__ = ("item_lines", "line")

    def __init__(self, *a):
        super().__init__(*a)
        self.item_lines: list[int] = []
        self.line: int = 0


class _Loader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _Loader, node: MappingNode):
    loader.flatten_mapping(node)
    result = LineDict()
    result.line = node.start_mark.line + 1
    for key_node, value_node in node.value:
        if isinstance(key_node, ScalarNode) and key_node.tag == "tag:yaml.org,2002:bool" and key_node.value.lower() in ("on", "off", "yes", "no", "y", "n"):
            key = key_node.value  # keep `on:` as the string "on"
        else:
            key = loader.construct_object(key_node, deep=True)
        try:
            hash(key)
        except TypeError:
            key = str(key)
        result[key] = loader.construct_object(value_node, deep=True)
        result.key_lines[key] = key_node.start_mark.line + 1
    return result


def _construct_sequence(loader: _Loader, node):
    result = LineList(loader.construct_object(child, deep=True) for child in node.value)
    result.item_lines = [child.start_mark.line + 1 for child in node.value]
    result.line = node.start_mark.line + 1
    return result


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_sequence)


def load_yaml(text: str):
    """Parse one YAML document. Raises YamlError on malformed or abusive input."""
    if len(text.encode("utf-8", errors="ignore")) > MAX_YAML_BYTES:
        raise YamlError("file exceeds 2 MiB YAML size limit")
    try:
        aliases = sum(1 for ev in yaml.parse(text, Loader=yaml.SafeLoader) if isinstance(ev, yaml.AliasEvent))
        if aliases > MAX_ALIASES:
            raise YamlError(f"too many YAML aliases ({aliases}); refusing to expand")
        docs = list(yaml.load_all(text, Loader=_Loader))
    except YamlError:
        raise
    except yaml.MarkedYAMLError as exc:
        line = exc.problem_mark.line + 1 if exc.problem_mark else None
        raise YamlError(f"{exc.problem or exc}", line) from None
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        raise YamlError(str(exc)) from None
    docs = [d for d in docs if d is not None]
    if not docs:
        return None
    return docs[0]
