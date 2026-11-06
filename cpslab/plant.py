"""Физический процесс: резервуар с насосом подачи и потребителем.

Уровень меняется на (подача насоса − расход потребителя) за секунду, в процентах объёма.
При уровне 100 % вода переливается (авария «перелив»), при уровне 5 % и ниже резервуар считается
опустошённым: насос работает всухую, потребитель остаётся без воды (авария «резервуар опустошён»).
Аварии фиксируются до сброса процесса.
"""
from __future__ import annotations

from dataclasses import dataclass, field

HIGH_ALARM = 95.0
LOW_LIMIT = 5.0


@dataclass
class Tank:
    level: float = 50.0
    q_in: float = 2.0          # подача насоса, %/с
    q_out: float = 1.0         # расход потребителя, %/с
    capacity: float = 100.0
    low_limit: float = LOW_LIMIT    # ниже — «опустошён»: сухой ход насоса, потребитель без воды
    alarm_high: float = HIGH_ALARM  # аварийно высокий уровень (сигнализация)
    overflowed: bool = False
    emptied: bool = False
    spilled: float = 0.0
    max_level: float = field(default=None)
    min_level: float = field(default=None)
    time: float = 0.0

    def __post_init__(self):
        self.max_level = self.level if self.max_level is None else self.max_level
        self.min_level = self.level if self.min_level is None else self.min_level

    def step(self, pump: bool, dt: float) -> None:
        self.level += ((self.q_in if pump else 0.0) - self.q_out) * dt
        if self.level >= self.capacity:
            self.spilled += self.level - self.capacity
            self.level = self.capacity
            self.overflowed = True
        if self.level <= 0.0:
            self.level = 0.0
        if self.level <= self.low_limit:
            self.emptied = True
        self.max_level = max(self.max_level, self.level)
        self.min_level = min(self.min_level, self.level)
        self.time += dt

    @property
    def high_alarm(self) -> bool:
        return self.level >= self.alarm_high

    def outcome(self) -> str:
        if self.overflowed:
            return "overflow"
        if self.emptied:
            return "empty"
        return "normal"

    def alarms(self) -> list:
        out = []
        if self.overflowed:
            out.append("ПЕРЕЛИВ")
        if self.emptied:
            out.append("РЕЗЕРВУАР ОПУСТОШЁН")
        if self.high_alarm and not self.overflowed:
            out.append("аварийно высокий уровень")
        return out


def simulate(controller, tank: Tank, seconds: float, dt: float = 0.5, events=None) -> Tank:
    """Прогнать процесс в модельном времени. events — список (время, функция без аргументов)."""
    pending = sorted(events or [], key=lambda e: e[0])
    t, steps = 0.0, int(round(seconds / dt))
    for _ in range(steps):
        while pending and pending[0][0] <= t:
            pending.pop(0)[1]()
        pump = controller.scan(tank.level) if controller is not None else False
        tank.step(pump, dt)
        t += dt
    return tank
