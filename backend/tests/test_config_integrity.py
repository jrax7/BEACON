import ast
import inspect
import textwrap

from app.config import Settings


def test_settings_class_declares_each_field_only_once():
    source = textwrap.dedent(
        inspect.getsource(Settings)
    )

    tree = ast.parse(source)

    class_node = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "Settings"
    )

    names = [
        statement.target.id
        for statement in class_node.body
        if isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
    ]

    duplicates = sorted(
        {
            name
            for name in names
            if names.count(name) > 1
        }
    )

    assert duplicates == [], (
        "Settings contains duplicate field declarations: "
        + ", ".join(duplicates)
    )
