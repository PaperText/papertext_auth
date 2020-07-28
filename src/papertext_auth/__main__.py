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
        call(f"python -m flakehell lint {src_path}".split(" "))

    @staticmethod
    def lint_mypy():
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
        call(f"python -m isort -rc {src_path}".split(" "))

    @staticmethod
    def fix():
        Scripts.fix_black()
        Scripts.fix_isort()

    @staticmethod
    def docs_build():
        call(
            f"sphinx-build -b html {src_path / 'paperback_docs'} {source_path / 'docs'}".split(
                " "
            )
        )

    @staticmethod
    def docs_clean():
        call(f"rm -rf {source_path / 'docs'}".split(" "))
