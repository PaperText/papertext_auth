#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from os import getenv
from subprocess import call
from typing import NoReturn


def call_container_manager(container_manager: str) -> NoReturn:
    call(f"{container_manager} stop postgresql".split(" "))
    call(f"{container_manager} rm postgresql".split(" "))
    call(f"mkdir -p {getenv('HOME')}/.papertext/postgresql".split(" "))
    call(
        f"{container_manager} run --name postgresql -d "
        "-e POSTGRES_PASSWORD=password "
        "-e POSTGRES_DB=papertext "
        "-p 5432:5432 "
        f"-v {getenv('HOME')}/.papertext/postgresql:/var/lib/postgresql/data:z "
        "postgres:13".split(" ")
    )


def start_db():
    try:
        call_container_manager("podman")
    except FileNotFoundError:
        call_container_manager("docker")


if __name__ == "__main__":
    start_db()
