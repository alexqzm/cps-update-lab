"""Минимальный Modbus/TCP: сервер для эмулятора ПЛК и клиент для нарушителя и тестов.

Поддерживаются функции 01 (чтение катушек), 02 (дискретные входы), 03 (регистры хранения),
04 (входные регистры), 06 (запись регистра) и 16 (запись нескольких регистров). Остальные
функции отвечают исключением 01. Аутентификации в Modbus нет — как и в реальных устройствах.
"""
from __future__ import annotations

import socket
import socketserver
import struct
import threading

ILLEGAL_FUNCTION, ILLEGAL_ADDRESS, ILLEGAL_VALUE, DEVICE_FAILURE = 1, 2, 3, 4
MAX_READ = 125


class ModbusError(Exception):
    def __init__(self, code: int):
        super().__init__(f"исключение Modbus {code}")
        self.code = code


def _pack_bits(bits) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def handle_pdu(device, pdu: bytes) -> bytes:
    """Обработать PDU; device предоставляет mb_read(kind, addr, count) и mb_write(addr, values)."""
    if not pdu:
        return bytes([0x80, ILLEGAL_FUNCTION])
    fc = pdu[0]
    try:
        if fc in (1, 2, 3, 4):
            if len(pdu) != 5:
                raise ModbusError(ILLEGAL_VALUE)
            addr, count = struct.unpack(">HH", pdu[1:5])
            if not 1 <= count <= (2000 if fc in (1, 2) else MAX_READ):
                raise ModbusError(ILLEGAL_VALUE)
            kind = {1: "coils", 2: "discrete", 3: "holding", 4: "input"}[fc]
            values = device.mb_read(kind, addr, count)
            if fc in (1, 2):
                data = _pack_bits(values)
            else:
                data = b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
            return bytes([fc, len(data)]) + data
        if fc == 6:
            if len(pdu) != 5:
                raise ModbusError(ILLEGAL_VALUE)
            addr, value = struct.unpack(">HH", pdu[1:5])
            device.mb_write(addr, [value])
            return pdu
        if fc == 16:
            if len(pdu) < 6:
                raise ModbusError(ILLEGAL_VALUE)
            addr, count, nbytes = struct.unpack(">HHB", pdu[1:6])
            if not 1 <= count <= 123 or nbytes != 2 * count or len(pdu) != 6 + nbytes:
                raise ModbusError(ILLEGAL_VALUE)
            values = list(struct.unpack(">%dH" % count, pdu[6:]))
            device.mb_write(addr, values)
            return pdu[:5]
        raise ModbusError(ILLEGAL_FUNCTION)
    except ModbusError as e:
        return bytes([fc | 0x80, e.code])


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(60)
        while True:
            head = _recv(sock, 7)
            if not head:
                return
            tid, proto, length, unit = struct.unpack(">HHHB", head)
            if proto != 0 or not 2 <= length <= 254:
                return
            pdu = _recv(sock, length - 1)
            if pdu is None:
                return
            resp = handle_pdu(self.server.device, pdu)
            sock.sendall(struct.pack(">HHHB", tid, 0, len(resp) + 1, unit) + resp)


def _recv(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


class ModbusServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, device, host="0.0.0.0", port=5020):
        super().__init__((host, port), _Handler)
        self.device = device

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, name="modbus", daemon=True)
        t.start()
        return t


class ModbusClient:
    """Клиент Modbus/TCP: по одному запросу на соединение."""

    def __init__(self, host: str, port: int = 502, unit: int = 1, timeout: float = 5.0):
        self.host, self.port, self.unit, self.timeout = host, port, unit, timeout
        self._tid = 0

    def _call(self, pdu: bytes) -> bytes:
        self._tid = (self._tid + 1) & 0xFFFF
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
            s.sendall(struct.pack(">HHHB", self._tid, 0, len(pdu) + 1, self.unit) + pdu)
            head = _recv(s, 7)
            if head is None:
                raise ConnectionError("нет ответа Modbus")
            _tid, _proto, length, _unit = struct.unpack(">HHHB", head)
            resp = _recv(s, length - 1)
        if resp is None:
            raise ConnectionError("ответ Modbus оборван")
        if resp[0] & 0x80:
            raise ModbusError(resp[1])
        return resp

    def read(self, fc: int, addr: int, count: int) -> list:
        resp = self._call(struct.pack(">BHH", fc, addr, count))
        data = resp[2:2 + resp[1]]
        if fc in (1, 2):
            return [bool(data[i // 8] >> (i % 8) & 1) for i in range(count)]
        return list(struct.unpack(">%dH" % count, data))

    def read_holding(self, addr: int, count: int = 1) -> list:
        return self.read(3, addr, count)

    def read_input(self, addr: int, count: int = 1) -> list:
        return self.read(4, addr, count)

    def write_register(self, addr: int, value: int) -> None:
        self._call(struct.pack(">BHH", 6, addr, value & 0xFFFF))

    def write_registers(self, addr: int, values: list) -> None:
        self._call(struct.pack(">BHHB", 16, addr, len(values), 2 * len(values))
                   + b"".join(struct.pack(">H", v & 0xFFFF) for v in values))
