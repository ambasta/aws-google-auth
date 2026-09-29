import getpass
import os
import sys
from collections import OrderedDict
from collections.abc import Iterable, Sequence
from typing import overload


class Util:
    # A plain-text table: numbers are right-aligned, everything else is
    # left-aligned, with a dashed rule under the headers.
    @staticmethod
    def format_table(rows: Sequence[Sequence[object]], headers: Sequence[str]) -> str:
        columns = list(zip(headers, *rows, strict=True))
        widths = [max(len(str(cell)) for cell in column) for column in columns]
        numeric = [all(isinstance(cell, int) for cell in column[1:]) for column in columns]

        def line(cells: Iterable[object]) -> str:
            return "  ".join(
                str(cell).rjust(width) if right else str(cell).ljust(width)
                for cell, width, right in zip(cells, widths, numeric, strict=True)
            ).rstrip()

        return "\n".join([line(headers), line("-" * width for width in widths), *(line(row) for row in rows)])

    @staticmethod
    def get_input(prompt: str) -> str:
        return input(prompt).strip()

    @overload
    @staticmethod
    def strip_if_string(value: str) -> str: ...
    @overload
    @staticmethod
    def strip_if_string[T](value: T) -> T: ...
    @staticmethod
    def strip_if_string(value: object) -> object:
        if isinstance(value, str):
            return value.strip()
        return value

    @staticmethod
    def pick_a_role(
        roles: dict[str, str], aliases: dict[str, str] | None = None, account: str | None = None
    ) -> tuple[str, str]:
        filtered_roles = {role: principal for role, principal in roles.items() if account in role} if account else roles

        if aliases:
            enriched_roles: dict[str, list[str]] = {}
            for role, principal in filtered_roles.items():
                account_id = role.split(":")[4]
                enriched_roles[role] = [aliases.get(account_id, account_id), role.split("role/")[1], principal]
            enriched_roles = OrderedDict(sorted(enriched_roles.items(), key=lambda t: (t[1][0], t[1][1])))

            ordered_roles: OrderedDict[str, str] = OrderedDict()
            for role, role_property in enriched_roles.items():
                ordered_roles[role] = role_property[2]

            enriched_roles_tab: list[list[int | str]] = []
            for i, role_property in enumerate(enriched_roles.values()):
                enriched_roles_tab.append([i + 1, role_property[0], role_property[1]])

            while True:
                print(Util.format_table(enriched_roles_tab, headers=["No", "AWS account", "Role"]))
                prompt = f"Type the number (1 - {len(enriched_roles):d}) of the role to assume: "
                choice = Util.get_input(prompt)

                try:
                    return list(ordered_roles.items())[int(choice) - 1]
                except IndexError, ValueError:
                    print("Invalid choice, try again.")
        else:
            while True:
                for i, role in enumerate(filtered_roles):
                    print(f"[{i + 1:>3d}] {role}")

                prompt = f"Type the number (1 - {len(filtered_roles):d}) of the role to assume: "
                choice = Util.get_input(prompt)

                try:
                    return list(filtered_roles.items())[int(choice) - 1]
                except IndexError, ValueError:
                    print("Invalid choice, try again.")

    @staticmethod
    def touch(file_name: str, mode: int = 0o600) -> None:
        flags = os.O_CREAT | os.O_APPEND
        with os.fdopen(os.open(file_name, flags, mode)) as f:
            try:
                os.utime(file_name, None)
            finally:
                f.close()

    # This method returns the first non-None value in args. If all values are
    # None, None will be returned. If there are no arguments, None will be
    # returned.
    @overload
    @staticmethod
    def coalesce[T](first: T | None, second: T, /) -> T: ...
    @overload
    @staticmethod
    def coalesce[T](first: T | None, second: T | None, third: T, /) -> T: ...
    @overload
    @staticmethod
    def coalesce[T](*args: T | None) -> T | None: ...
    @staticmethod
    def coalesce[T](*args: T | None) -> T | None:
        for _, value in enumerate(args):
            if value is not None:
                return value
        return None

    @staticmethod
    def unicode_to_string_if_needed[T](object: T) -> T:
        return object

    @staticmethod
    def get_password(prompt: str) -> str:
        if sys.stdin.isatty():
            password = getpass.getpass(prompt)
        else:
            print(prompt, end="")
            sys.stdout.flush()
            password = sys.stdin.readline()
            print("")
        return password
