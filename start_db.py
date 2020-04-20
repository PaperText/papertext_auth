#!/usr/cin/env python3
# -*- encoding: utf-8 -*-

from os import getenv
from subprocess import call
from typing import NoReturn


def call_container_manafer(container_manager: str) -> NoReturn:
    call(f"{container_manager} stop postgresql".split(" "))
    call(f"{container_manager} rm postgresql".split(" "))
    call(f"{container_manager} run --name postgresql "
         "-e POSTGRES_PASSWORD=password "
         "-p 5432:5432 "
         f"-v {getenv('HOME')}/.papertext/postgresql:/var/lib/postgresql/data "
         "-d postgres".split(" "))
    call(f"{container_manager} start postgresql".split(" "))


def start_db():
    try:
        container_manager = "podman"
        call_container_manafer(container_manager)
    except FileNotFoundError:
        container_manager = "docker"
        call_container_manafer(container_manager)


if __name__ == "__main__":
    start_db()