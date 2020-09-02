from pathlib import Path
from subprocess import call

src_path = Path(__file__) / ".." / ".."
src_path = src_path.resolve()

source_path = src_path / ".."
source_path = source_path.resolve()

pyproject_path = source_path / "pyproject.toml"
pyproject_path = pyproject_path.resolve()


class Scripts:
    @staticmethod
    def lint_flakehell():
        print("+--------------------+")
        print("| [flake]hell linter |")
        print("+--------------------+")
        call(f"python -m flakehell lint {src_path}".split(" "))

    @staticmethod
    def lint_mypy():
        print("+-------------+")
        print("| mypy linter |")
        print("+-------------+")
        call(f"python -m mypy {src_path}".split(" "))

    @staticmethod
    def lint():
        Scripts.lint_flakehell()
        Scripts.lint_mypy()

    @staticmethod
    def fix_black():
        call(
            f"python -m black {src_path} --config {pyproject_path}".split(" ")
        )

    @staticmethod
    def fix_isort():
        call(f"python -m isort {src_path}".split(" "))

    @staticmethod
    def fix():
        Scripts.fix_black()
        Scripts.fix_isort()
