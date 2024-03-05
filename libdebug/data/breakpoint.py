#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Breakpoint:
    """A breakpoint in the target process.

    Attributes:
        address (int): The address of the breakpoint in the target process.
        symbol (bytes): The symbol, if available, of the breakpoint in the target process.
        hit_count (int): The number of times this specific breakpoint has been hit.
        hardware (bool): Whether the breakpoint is a hardware breakpoint or not.
        condition (str): The breakpoint condition. Available values are "X", "W", "RW". Supported only for hardware breakpoints.
        length (int): The length of the breakpoint area. Supported only for hardware breakpoints.
        enabled (bool): Whether the breakpoint is enabled or not.
    """

    address: int = 0
    symbol: bytes = b""
    hit_count: int = 0
    hardware: bool = False
    callback: None | Callable[["Debugger", Breakpoint], None] = None
    condition: str = "X"
    length: int = 1
    enabled: bool = True

    _linked_thread_ids: list[int] = field(default_factory=list)
    # The thread ID that hit the breakpoint

    _disabled_for_step: bool = False

    def enable(self) -> None:
        """Enable the breakpoint."""
        self.enabled = True

    def disable(self) -> None:
        """Disable the breakpoint."""
        self.enabled = False

    def hit_on(self, thread_context: "ThreadContext") -> None:
        """Called when the breakpoint is hit."""
        return self.enabled and thread_context.instruction_pointer == self.address
