"""Extract typed MCP argument specifications from NetScan argparse source.

Scanner parsers currently live inside their ``main`` functions, which makes
runtime parser introspection execute heavyweight protocol imports. Reading the
static ``add_argument`` declarations keeps MCP startup fast and dependency-free
while retaining argparse as the source of truth.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


COMMA_LIST_TYPES = frozenset({"str_comma", "str_ports"})


class ArgumentSchemaError(ValueError):
    """Raised when an argparse declaration cannot be represented safely."""


@dataclass(frozen=True)
class ArgumentSpec:
    dest: str
    option_strings: tuple[str, ...]
    action: str
    value_type: str
    nargs: str | int | None
    choices: tuple[Any, ...]
    help: str
    required: bool
    default: Any
    has_default: bool
    lineno: int

    @property
    def positional(self) -> bool:
        return not self.option_strings

    @property
    def takes_many(self) -> bool:
        return self.nargs in ("*", "+") or isinstance(self.nargs, int)

    @property
    def cli_option(self) -> str:
        if self.positional:
            return self.dest
        long_options = [item for item in self.option_strings if item.startswith("--")]
        return long_options[0] if long_options else self.option_strings[0]

    @property
    def description(self) -> str:
        cli = (
            "Positional argument."
            if self.positional
            else f"CLI option: {', '.join(self.option_strings)}."
        )
        details = [cli]
        if self.help:
            details.append(self.help)
        if self.value_type == "str_ports":
            details.append("Provide ports as an integer array; MCP converts it to comma-separated CLI syntax.")
        elif self.value_type == "str_comma":
            details.append("Provide values as an array; MCP converts it to comma-separated CLI syntax.")
        if self.has_default and self.default is not None:
            details.append(f"Native CLI default: {self.default!r}.")
        return " ".join(details)

    @property
    def typed_default(self) -> Any:
        """Return argparse's effective default in the MCP field's native type."""
        if not self.has_default:
            if self.action == "store_true":
                return False
            if self.action == "store_false":
                return True
            return None
        if self.default is None:
            return None
        if self.value_type == "int":
            return int(self.default)
        if self.value_type == "float":
            return float(self.default)
        if self.value_type == "str_ports" and isinstance(self.default, str):
            ports: list[int] = []
            for value in self.default.split(","):
                if "-" in value:
                    start, end = value.split("-", 1)
                    ports.extend(range(int(start), int(end) + 1))
                else:
                    ports.append(int(value))
            return ports
        if self.value_type == "str_comma" and isinstance(self.default, str):
            return list(dict.fromkeys(self.default.split(",")))
        return self.default


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    description: str
    source: Path


def extract_module_specs(modules_path: Path) -> tuple[ModuleSpec, ...]:
    """Extract static Module.name and Module.description declarations."""
    if not modules_path.is_dir():
        return ()

    modules: list[ModuleSpec] = []
    seen_names: set[str] = set()
    for source in sorted(modules_path.glob("*.py")):
        if source.name == "__init__.py":
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        values: dict[str, Any] = {}
        for node in tree.body:
            if not isinstance(node, ast.ClassDef) or node.name != "Module":
                continue
            for statement in node.body:
                if isinstance(statement, ast.Assign):
                    targets = statement.targets
                    value = statement.value
                elif isinstance(statement, ast.AnnAssign):
                    targets = [statement.target]
                    value = statement.value
                else:
                    continue
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in {"name", "description"}:
                        values[target.id] = _literal(
                            value,
                            field=f"Module.{target.id}",
                            path=source,
                            lineno=statement.lineno,
                        )

        if not isinstance(values.get("name"), str) or not isinstance(values.get("description"), str):
            raise ArgumentSchemaError(
                f"{source}: Module must declare literal string name and description attributes"
            )
        normalized_name = values["name"].lower()
        if normalized_name in seen_names:
            raise ArgumentSchemaError(
                f"{source}: duplicate module name: {values['name']}"
            )
        seen_names.add(normalized_name)
        modules.append(ModuleSpec(values["name"], values["description"], source))

    return tuple(sorted(modules, key=lambda module: module.name.lower()))


def _literal(node: ast.AST, *, field: str, path: Path, lineno: int) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError) as exc:
        raise ArgumentSchemaError(
            f"{path}:{lineno}: {field} must be a literal for MCP schema generation"
        ) from exc


def _type_name(node: ast.AST | None, path: Path, lineno: int) -> str:
    if node is None:
        return "str"
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    raise ArgumentSchemaError(
        f"{path}:{lineno}: unsupported argparse type expression: {ast.unparse(node)}"
    )


def _derive_dest(argument_names: Sequence[str], explicit_dest: str | None) -> str:
    if explicit_dest:
        return explicit_dest
    option_strings = [item for item in argument_names if item.startswith("-")]
    if not option_strings:
        return argument_names[0]
    long_options = [item for item in option_strings if item.startswith("--")]
    source = long_options[0] if long_options else option_strings[0]
    return source.lstrip("-").replace("-", "_")


def extract_argument_specs(script_path: Path) -> tuple[ArgumentSpec, ...]:
    """Return argparse actions declared by a NetScan command, in source order."""
    tree = ast.parse(script_path.read_text(encoding="utf-8"), filename=str(script_path))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_argument"
    ]
    calls.sort(key=lambda node: (node.lineno, node.col_offset))

    specs: list[ArgumentSpec] = []
    seen_destinations: set[str] = set()
    for call in calls:
        argument_names = tuple(
            _literal(arg, field="argument name", path=script_path, lineno=call.lineno)
            for arg in call.args
        )
        if not argument_names or not all(isinstance(item, str) for item in argument_names):
            raise ArgumentSchemaError(
                f"{script_path}:{call.lineno}: add_argument requires literal string names"
            )

        keywords = {item.arg: item.value for item in call.keywords if item.arg is not None}

        def keyword(name: str, fallback: Any) -> Any:
            node = keywords.get(name)
            if node is None:
                return fallback
            return _literal(node, field=name, path=script_path, lineno=call.lineno)

        explicit_dest = keyword("dest", None)
        dest = _derive_dest(argument_names, explicit_dest)
        if not dest.isidentifier():
            raise ArgumentSchemaError(
                f"{script_path}:{call.lineno}: argparse destination is not a Python identifier: {dest}"
            )
        if dest in seen_destinations:
            raise ArgumentSchemaError(
                f"{script_path}:{call.lineno}: duplicate argparse destination: {dest}"
            )
        seen_destinations.add(dest)

        option_strings = tuple(item for item in argument_names if item.startswith("-"))
        action = keyword("action", "store")
        nargs = keyword("nargs", None)
        choices_value = keyword("choices", ())
        choices = tuple(sorted(choices_value)) if isinstance(choices_value, set) else tuple(choices_value)
        help_text = keyword("help", "") or ""
        has_default = "default" in keywords
        default = keyword("default", None)
        explicit_required = bool(keyword("required", False))
        positional_required = not option_strings and nargs not in ("?", "*") and not has_default

        specs.append(
            ArgumentSpec(
                dest=dest,
                option_strings=option_strings,
                action=action,
                value_type=_type_name(keywords.get("type"), script_path, call.lineno),
                nargs=nargs,
                choices=choices,
                help=help_text,
                required=explicit_required or positional_required,
                default=default,
                has_default=has_default,
                lineno=call.lineno,
            )
        )

    return tuple(specs)


def values_to_argv(
    specs: Sequence[ArgumentSpec],
    values: Mapping[str, Any],
    *,
    module_args: Sequence[str] | None = None,
) -> list[str]:
    """Convert validated typed MCP values back to the scanner's native argv."""
    argv: list[str] = []
    positionals = [spec for spec in specs if spec.positional]
    optionals = [spec for spec in specs if not spec.positional]
    has_modules = any(spec.dest == "modules" and values.get(spec.dest) for spec in specs)
    if module_args and not has_modules:
        raise ArgumentSchemaError("module_args requires at least one selected module")

    for spec in (*positionals, *optionals):
        value = values.get(spec.dest)
        if value is None:
            continue

        if spec.action == "store_true":
            if value:
                argv.append(spec.cli_option)
            continue
        if spec.action == "store_false":
            if value is False:
                argv.append(spec.cli_option)
            continue

        if spec.dest == "modules":
            if not spec.positional:
                argv.append(spec.cli_option)
            if isinstance(value, list):
                argv.append(",".join(str(item) for item in value))
            else:
                argv.append(str(value))
            if module_args:
                argv.extend(str(item) for item in module_args)
            continue

        if not spec.positional:
            argv.append(spec.cli_option)

        if spec.value_type in COMMA_LIST_TYPES and isinstance(value, list):
            argv.append(",".join(str(item) for item in value))
        elif spec.takes_many and isinstance(value, list):
            argv.extend(str(item) for item in value)
        else:
            argv.append(str(value))

    return argv
