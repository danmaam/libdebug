#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#


def software_breakpoint_byte_size(arch: str) -> int:
    """Return the size of a software breakpoint instruction."""

    match arch:
        case "amd64":
            return 1
        case "i386":
            return 1
        case _:
            raise ValueError(f"Unsupported architecture: {arch}")
