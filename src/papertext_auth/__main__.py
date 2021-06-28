from pathlib import Path
from subprocess import call
from shlex import split

src_path = Path(__file__) / ".." / ".."
src_path = src_path.resolve()

source_path = src_path / ".."
source_path = source_path.resolve()

docs_path = source_path / "docs"
docs_path = docs_path.resolve()

pyproject_path = source_path / "pyproject.toml"
pyproject_path = pyproject_path.resolve()


class Scripts:
    @staticmethod
    def pretty_print(string):
        print("+-"+"-"*len(string)+"-+")
        print("| "+str(string)+" |")
        print("+-" + "-" * len(string) + "-+")

    @staticmethod
    def execute(cmd):
        return call(split(cmd))

    @staticmethod
    def lint_flake8():
        Scripts.pretty_print("flake8[9] linter")
        Scripts.execute(f"python -m flake8 {src_path}")

    @staticmethod
    def lint_mypy():
        Scripts.pretty_print("mypy linter")
        Scripts.execute(f"python -m mypy {src_path}")

    @staticmethod
    def lint():
        Scripts.lint_flake8()
        Scripts.lint_mypy()

    @staticmethod
    def fix_black():
        Scripts.pretty_print("black fixer")
        Scripts.execute(f"python -m black {src_path} --config {pyproject_path}")

    @staticmethod
    def fix_isort():
        Scripts.pretty_print("isort fixer")
        Scripts.execute(f"python -m isort {src_path}")

    @staticmethod
    def fix():
        Scripts.fix_black()
        Scripts.fix_isort()
