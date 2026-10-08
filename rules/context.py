"""
Gathers context about the scanned project, by reading its Python code:
  - which packages the code imports
  - which functions are web routes (reachable from the internet)
"""

import ast
from pathlib import Path

# Some packages are installed under one name but imported under another
IMPORT_NAMES = {
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "pillow": "pil",
    "scikit-learn": "sklearn",
    "python-dateutil": "dateutil",
}

WEB_ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}


def import_name(package):
    """'pyyaml' -> 'yaml', 'flask' -> 'flask'"""
    package = package.lower()
    return IMPORT_NAMES.get(package, package.replace("-", "_"))


def resolve_path(file, target):
    """Turn a file path from any scanner into one full, comparable path."""
    inside_target = Path(target) / file
    if inside_target.exists():
        return inside_target.resolve()
    return Path(file).resolve()


def find_route(function):
    """If a function has a decorator like @app.route("/ping"), return "/ping"."""
    for decorator in function.decorator_list:
        if (isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr in WEB_ROUTE_DECORATORS):
            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                return str(decorator.args[0].value)
            return "(web route)"
    return None


def collect_context(target):
    """Read every .py file in the target and collect imports and web routes."""
    imported = set()
    routes = {}   # full file path -> list of (start line, end line, route path)

    for py_file in Path(target).rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue   # skip files Python can't read

        file_routes = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".")[0].lower())
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0].lower())
            elif isinstance(node, ast.FunctionDef):
                route = find_route(node)
                if route:
                    file_routes.append((node.lineno, node.end_lineno, route))

        routes[py_file.resolve()] = file_routes

    return {"imported": imported, "routes": routes}


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "../argus-test-target"
    context = collect_context(target)
    print("Packages imported by the code:", sorted(context["imported"]))
    for path, file_routes in context["routes"].items():
        for start, end, route in file_routes:
            print(f"Web route {route:<10} {path.name} lines {start}-{end}")