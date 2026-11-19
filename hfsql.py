"""Small, read-only HFSQL Client/Server driver."""

from __future__ import annotations

import re
import secrets
import socket
import struct
from datetime import datetime, timedelta
from decimal import Decimal
from typing import NamedTuple


_MASK = 0xFFFFFFFF
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HELLO = bytes.fromhex(
    "0b00280000000100adde005433a2a930b2c7470f00000003000400"
    "fffffffffffffffff6ffff0100"
)
_LOGIN_START = bytes.fromhex(
    "1600db0000000100adde00633357a95bef61fb01000000c0000000040000005e0000000001"
    "707974686f6e2e657865202820202900013132372e302e302e3100"
)
_LOGIN_END = bytes.fromhex(
    "01303141333137303136200933312e372e3635362e3000000d000000010000b0000000a000000010000d"
    "00000002000000000200000009000000"
)
_CLIENT_HOST = "localhost"
_PROOF = bytes.fromhex(
    "1600ae0000000100adde00633324a9eaef4f640200000093000000020000001d0000000700"
    "000000140000006ec2e7dc49e4ac8b749fd033721646a81da695f76a000000060000000061"
    "000000774b9ca6082b4548fa71dbc1e53df1c0af13589da6357645f0fed253ac448949984a"
    "01019364454ec567983a0453a15f75b1b6f321ca1fa47dc3c82670834edea620898f6d988"
    "0c7dce4e34c5aaee60aa52700f824f7b08991939871b401cc14ae"
)
_AUTH_FINISH = bytes.fromhex(
    "ffff390000000100adde004833b0a907b3c1451e000000030000000c000000010000000100"
    "0000010000000100000000010000000002000000"
)
_VERSION = bytes.fromhex("3804170000000100000000fa3693a934b2c34502000000")
_TABLES = bytes.fromhex("2704170000000100000000e53693a936b2c34500000000")
_QUERY_SUFFIX = bytes.fromhex(
    "00000000000010000000100000000100000001000000100000000100000000"
)


class HFSQLDriverError(RuntimeError):
    pass


class _Column(NamedTuple):
    name: str
    size: int
    offset: int
    kind: int


def _sum32(data: bytes | bytearray) -> int:
    full = len(data) // 4 * 4
    return (sum(struct.unpack_from("<I", data, i)[0] for i in range(0, full, 4)) + sum(data[full:])) & _MASK


def _sign(frame: bytes | bytearray) -> bytes:
    frame = bytearray(frame)
    struct.pack_into("<I", frame, 11, _sum32(frame[:11]) ^ 0xA98B32C2)
    struct.pack_into("<I", frame, 15, _sum32(frame[19:]) ^ 0x45C3B236)
    return bytes(frame)


def _frame(opcode: int, handle: int = 0, payload: bytes = b"") -> bytes:
    frame = bytearray(23 + len(payload))
    struct.pack_into("<HI", frame, 0, opcode, len(frame))
    frame[6] = 1
    struct.pack_into("<I", frame, 19, handle)
    frame[23:] = payload
    return _sign(frame)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise HFSQLDriverError("Il server ha chiuso la connessione")
        data += chunk
    return bytes(data)


def _recv_frame(sock: socket.socket) -> bytes:
    head = _recv_exact(sock, 6)
    size = struct.unpack_from("<I", head, 2)[0]
    if not 6 <= size <= 16 * 1024 * 1024:
        raise HFSQLDriverError(f"Dimensione frame HFSQL non valida: {size}")
    return head + _recv_exact(sock, size - 6)


def _exchange(sock: socket.socket, request: bytes) -> bytes:
    sock.sendall(request)
    return _recv_frame(sock)


def _raise_server_error(frame: bytes, action: str) -> None:
    lowered = frame.lower()
    markers = (b"invalid password", b"internal error", b"unable to", b"not found")
    if any(marker in lowered for marker in markers):
        message = "".join(chr(byte) if 32 <= byte < 127 else " " for byte in frame)
        message = " ".join(message.split())
        raise HFSQLDriverError(f"Errore HFSQL durante {action}: {message[:300]}")


def _sha0(data: bytes) -> bytes:
    bit_length = len(data) * 8
    data += b"\x80" + b"\0" * ((55 - len(data)) % 64) + struct.pack(">Q", bit_length)
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for offset in range(0, len(data), 64):
        words = list(struct.unpack("<16I", data[offset:offset + 64]))
        for index in range(16, 80):
            words.append(words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
        a, b, c, d, e = state
        for index, word in enumerate(words):
            if index < 20:
                f, constant = (b & c) | (~b & d), 0x5A827999
            elif index < 40:
                f, constant = b ^ c ^ d, 0x6ED9EBA1
            elif index < 60:
                f, constant = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
            else:
                f, constant = b ^ c ^ d, 0xCA62C1D6
            a, b, c, d, e = ((a << 5 | a >> 27) + f + e + constant + word) & _MASK, a, (b << 30 | b >> 2) & _MASK, c, d
        state = [(value + add) & _MASK for value, add in zip(state, (a, b, c, d, e))]
    return struct.pack(">5I", *state)


def _hmac(key: bytes, message: bytes) -> bytes:
    key = (_sha0(key) if len(key) > 64 else key).ljust(64, b"\0")
    inner = _sha0(bytes(byte ^ 0x36 for byte in key) + message)
    return _sha0(bytes(byte ^ 0x5C for byte in key) + inner)


def _login_request(database: str, user: str) -> bytes:
    for label, value in (("database", database), ("user", user)):
        if not isinstance(value, str) or not value or "\0" in value:
            raise ValueError(f"{label} HFSQL non valido")
    database_bytes, user_bytes = database.encode(), user.encode()
    fields = (
        b"\x07\x01\0\0\0\x01" + database_bytes + b"\0\x01" + database_bytes + b"\0"
        + b"\0\x02\0\0\x01" + user_bytes + b"\0\x08\0\0\0"
        + secrets.token_bytes(8)
    )
    host_field = b"\x01" + _CLIENT_HOST.encode() + b"\0"
    packet = bytearray(_LOGIN_START + host_field + _LOGIN_END)
    packet += struct.pack("<I", len(fields)) + fields
    struct.pack_into("<I", packet, 2, len(packet))
    struct.pack_into("<I", packet, 23, len(packet) - 27)
    # This length includes the hostname inside the client metadata block.
    struct.pack_into("<I", packet, 31, 55 + len(_CLIENT_HOST.encode()))
    return _sign(packet)


def _schema_request(table: str, database: str) -> bytes:
    file_name = f"{table}.bst\0".encode()
    table_name = f"{table}\0".encode()
    database_name = f"{database}\0".encode()
    payload = (
        struct.pack("<I", len(file_name)) + file_name
        + struct.pack("<I", len(table_name)) + table_name
        + struct.pack("<I", 1) + b"\0"
        + struct.pack("<I", len(database_name)) + database_name
    )
    return _frame(0x03F6, 1, payload)


def _open_request(table: str) -> bytes:
    name = f"{table}\0".encode()
    payload = (
        struct.pack("<I", len(name)) + name
        + struct.pack("<IIII", 7, len(name) + 9, 1, len(name) + 1)
        + b"\x01" + name
    )
    return _frame(0x0439, 1, payload)


def _describe_request(table: str, database: str) -> bytes:
    name = f"{table}\0".encode()
    database_name = f"{database}\0".encode()
    payload = (
        struct.pack("<II", 1, len(name)) + name
        + struct.pack("<I", 2) + b"\0" * 8
        + struct.pack("<I", len(database_name)) + database_name
        + struct.pack("<I", 1)
    )
    return _frame(0x0475, 1, payload)


def _columns(schema: bytes, table: str) -> list[_Column]:
    escaped = re.escape(table.encode())
    pattern = (
        b"\x01([A-Za-z_][A-Za-z0-9_]*)\x00\x01[A-Z][A-Z0-9_]*\x00"
        b"[\x00\x01]?\x00{2}\x01" + escaped
        + b"\x00\x01([A-Za-z_][A-Za-z0-9_]*)\x00"
    )
    columns: list[_Column] = []
    for match in re.finditer(pattern, schema):
        if (
            match.start() < 32
            or match.group(1) != match.group(2)
            or match.group(1).startswith(b"OptimCompKey_")
        ):
            continue
        size, offset = struct.unpack_from("<II", schema, match.start() - 32)
        marker = schema.find(b"\x0f", match.end(), match.end() + 80)
        if (
            marker < 0
            or marker + 1 >= len(schema)
            or not 1 <= size <= 1024 * 1024
            or offset > 16 * 1024 * 1024
        ):
            continue
        columns.append(_Column(match.group(1).decode(), size, offset, schema[marker + 1]))
    if not columns:
        raise HFSQLDriverError(f"Nessuna colonna trovata per {table}")
    return columns


def _query_request(
    table: str,
    columns: list[_Column],
    limit: int,
    where: tuple[str, str | int] | None = None,
    after: tuple[str, int] | None = None,
) -> bytes:
    query_name = f"Requete_HyperFile{secrets.randbelow(10**13):013d}\0".encode()
    selected = " , ".join(f"{table}.{column.name}  AS {column.name}" for column in columns)
    conditions = []
    if where:
        column, value = where
        if type(value) is int:
            literal = str(value)
        elif isinstance(value, str) and "\0" not in value:
            literal = "'" + value.replace("'", "''") + "'"
        else:
            raise ValueError("Filtro HFSQL non valido")
        conditions.append(f"{table}.{column} = {literal}")
    if after:
        column, value = after
        if type(value) is not int:
            raise ValueError("Paginazione HFSQL non valida")
        conditions.append(f"{table}.{column} > {value}")
    condition = f" \r\nWHERE {' AND '.join(conditions)}" if conditions else ""
    order = f" \r\nORDER BY {table}.{after[0]}" if after else ""
    query = f"SELECT TOP {limit} {selected} \r\nFROM {table}{condition}{order} \0".encode()
    name = f"{table}\0".encode()
    third = len(name) + 12
    tail = struct.pack("<IIII", third + 33, 3, third, 1) + b"\0\x01" + name + _QUERY_SUFFIX
    payload = struct.pack("<I", len(query_name)) + query_name + b"\0" * 4 + struct.pack("<I", len(query)) + query + tail
    return _frame(0x04BD, 1, payload)


def _decode(column: _Column, raw: bytes):
    if column.kind == 0x12:
        value = raw.split(b"\0", 1)[0]
        for encoding in ("utf-8", "cp1252"):
            try:
                return value.decode(encoding)
            except UnicodeDecodeError:
                pass
        return value.decode("latin-1")
    if column.kind == 0x08:
        return int.from_bytes(raw, "little", signed=True)
    if column.kind == 0x09:
        return int.from_bytes(raw, "little", signed=True)
    if column.kind == 0x01:
        return bool(raw[0])
    if column.kind in (0x02, 0x06):
        return raw[0]
    if column.kind == 0x1A:
        if not any(raw):
            return ""
        day, month, year, milliseconds = raw[0], raw[1], struct.unpack_from("<H", raw, 2)[0], struct.unpack_from("<I", raw, 4)[0]
        value = datetime(year, month, day) + timedelta(milliseconds=milliseconds)
        return value.isoformat(sep=" ", timespec="milliseconds")
    if column.kind == 0x0A:
        value = int.from_bytes(raw, "little", signed=True)
        return Decimal((int(value < 0), tuple(map(int, str(abs(value)))), -6))
    if column.kind in (0x0B, 0x0D) and len(raw) == 4:
        return struct.unpack("<f", raw)[0]
    if column.kind == 0x6E:
        return raw[:len(raw) // 2 * 2].decode("utf-16-le").split("\0", 1)[0]
    return raw


def _memo_at(block: bytes, offset: int) -> tuple[bytes, int] | None:
    if offset + 4 > len(block):
        return None
    size = struct.unpack_from("<I", block, offset)[0]
    metadata = offset + 4 + size
    if metadata + 8 > len(block) or block[metadata:metadata + 4] != b"\0" * 4:
        return None
    subtype = struct.unpack_from("<I", block, metadata + 4)[0] & 0xFF
    if subtype == 12:
        end = metadata + 53
    elif subtype == 13 and metadata + 40 <= len(block):
        path_length = struct.unpack_from("<I", block, metadata + 36)[0]
        end = metadata + 85 + path_length
        if path_length > 1024 * 1024:
            return None
    else:
        return None
    if end > len(block):
        return None
    return block[offset + 4:metadata], end


def _decode_memo_rows(block: bytes, columns: list[_Column], width: int) -> list[dict[str, object]]:
    memo_columns = [column for column in columns if column.kind == 0x13]
    prefix = 50 + (len(columns) + 7) // 8
    rows = []
    row_start = 0
    while row_start < len(block):
        cursor = row_start + 25
        memos: dict[str, bytes | None] = {}
        has_value = False
        for column in memo_columns:
            parsed = _memo_at(block, cursor)
            if parsed is None:
                memos[column.name] = None
                cursor += 1
            else:
                memos[column.name], cursor = parsed
                has_value = True
        fixed = (
            cursor + (len(columns) + 7) // 8 - 1
            if has_value
            else row_start + prefix + len(memo_columns)
        )
        row_end = fixed + width + 16
        if row_end > len(block):
            raise HFSQLDriverError(
                f"Record HFSQL con memo non valido: offset={row_start}, fine={row_end}, blocco={len(block)}"
            )
        row: dict[str, object] = {}
        for column in columns:
            raw = block[fixed + column.offset:fixed + column.offset + column.size]
            if column.kind == 0x13:
                value = memos[column.name]
                is_null = raw == b"\xff" * column.size
                if (value is None) != is_null:
                    raise HFSQLDriverError(
                        f"Descrittore memo HFSQL non valido: {column.name}, record={row_start}, "
                        f"raw={raw.hex()}, memo={{{', '.join(f'{name}:{None if data is None else len(data)}' for name, data in memos.items())}}}"
                    )
                row[column.name] = value
            else:
                row[column.name] = _decode(column, raw)
        rows.append(row)
        row_start = row_end
    if row_start != len(block):
        raise HFSQLDriverError(f"Blocco memo HFSQL non allineato: {row_start}/{len(block)}")
    return rows


def _decode_row_frame(frame: bytes, columns: list[_Column]) -> tuple[list[dict[str, object]], bool]:
    if len(frame) < 54 or frame[:2] != b"\xf8\x03":
        raise HFSQLDriverError(f"Frame righe HFSQL non valido: {len(frame)} byte, {frame[:32].hex()}")
    width = max(column.offset + column.size for column in columns)
    record_bytes = struct.unpack_from("<I", frame, 31)[0]
    if len(frame) != 39 + record_bytes + 15:
        raise HFSQLDriverError(
            f"Dimensione blocco HFSQL inattesa: blocco={record_bytes}, frame={len(frame)}"
        )
    if not record_bytes:
        return [], bool(frame[-6])
    block = frame[39:39 + record_bytes]
    if any(column.kind == 0x13 for column in columns):
        return _decode_memo_rows(block, columns, width), bool(frame[-6])
    stride = width + 66 + (len(columns) + 7) // 8
    if record_bytes % stride:
        raise HFSQLDriverError(
            f"Dimensione record HFSQL inattesa: blocco={record_bytes}, dati={width}, stride={stride}, frame={len(frame)}"
        )
    rows = []
    for index in range(record_bytes // stride):
        start = 39 + (index + 1) * stride - 16 - width
        rows.append({
            column.name: _decode(column, frame[start + column.offset:start + column.offset + column.size])
            for column in columns
        })
    return rows, bool(frame[-6])


def _read_rows(
    sock: socket.socket, first: bytes, columns: list[_Column], limit: int
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    frame = first
    while len(rows) < limit:
        if len(frame) == 37 and frame[:2] == b"\xff\xff":
            frame = _recv_frame(sock)
            continue
        decoded, final = _decode_row_frame(frame, columns)
        rows.extend(decoded[:limit - len(rows)])
        if final or not decoded or len(rows) == limit:
            break
        frame = _recv_frame(sock)
    return rows


class Connection:
    def __init__(self, host: str, port: int, database: str, user: str, password: str, timeout: float) -> None:
        _login_request(database, user)
        if not isinstance(password, str):
            raise ValueError("password HFSQL non valida")
        self.host, self.port, self.database = host, port, database
        self.user, self.password, self.timeout = user, password, timeout

    def __enter__(self) -> Connection:
        return self

    def __exit__(self, *_args) -> None:
        return None

    def _session(self) -> socket.socket:
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        try:
            _exchange(sock, _HELLO)
            challenge = _exchange(sock, _login_request(self.database, self.user))
            if len(challenge) < 12:
                raise HFSQLDriverError("Challenge HFSQL non valido")
            proof = _hmac(_sha0(self.password.encode()), challenge[-12:-4] + self.user.encode())
            request = bytearray(_PROOF)
            request[44:64] = proof
            answer = _exchange(sock, _sign(request))
            if answer[:2] != b"\x07\0":
                raise HFSQLDriverError("Autenticazione HFSQL rifiutata")
            _exchange(sock, _AUTH_FINISH)
            _exchange(sock, _VERSION)
            return sock
        except Exception:
            sock.close()
            raise

    def _table_list(self, sock: socket.socket) -> list[str]:
        response = _exchange(sock, _TABLES)
        if len(response) < 23:
            raise HFSQLDriverError("Risposta elenco tabelle non valida")
        length = struct.unpack_from("<I", response, 19)[0]
        if not 1 <= length <= len(response) - 23:
            raise HFSQLDriverError("Lunghezza elenco tabelle non valida")
        return [name.removesuffix(".bst") for name in response[23:23 + length - 1].decode().split("\r\n")]

    def tables(self) -> list[str]:
        with self._session() as sock:
            return self._table_list(sock)

    def rows(
        self,
        table: str,
        limit: int = 10,
        where: tuple[str, str | int] | None = None,
        after: tuple[str, int] | None = None,
    ) -> list[dict[str, object]]:
        if not _IDENTIFIER.fullmatch(table):
            raise ValueError("Nome tabella non valido")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit deve essere tra 1 e 1000")
        if where is not None and (
            not isinstance(where, tuple)
            or len(where) != 2
            or not isinstance(where[0], str)
            or not _IDENTIFIER.fullmatch(where[0])
        ):
            raise ValueError("Filtro HFSQL non valido")
        if after is not None and (
            not isinstance(after, tuple)
            or len(after) != 2
            or not isinstance(after[0], str)
            or not _IDENTIFIER.fullmatch(after[0])
            or type(after[1]) is not int
        ):
            raise ValueError("Paginazione HFSQL non valida")
        with self._session() as sock:
            names = self._table_list(sock)
            table = next((name for name in names if name.casefold() == table.casefold()), "")
            if not table:
                raise ValueError("Tabella inesistente")
            schema = _exchange(sock, _schema_request(table, self.database))
            _raise_server_error(schema, f"lettura schema {table}")
            columns = _columns(schema, table)
            if where:
                column = next((item.name for item in columns if item.name.casefold() == where[0].casefold()), "")
                if not column:
                    raise ValueError("Colonna filtro inesistente")
                where = (column, where[1])
            if after:
                column = next((item.name for item in columns if item.name.casefold() == after[0].casefold()), "")
                if not column:
                    raise ValueError("Colonna paginazione inesistente")
                after = (column, after[1])
            opened = _exchange(sock, _open_request(table))
            _raise_server_error(opened, f"apertura {table}")
            described = _exchange(sock, _describe_request(table, self.database))
            _raise_server_error(described, f"descrizione {table}")
            ready = _exchange(sock, _frame(0x0427, 0x00200000))
            _raise_server_error(ready, f"preparazione {table}")
            query = _exchange(sock, _query_request(table, columns, limit, where, after))
            _raise_server_error(query, f"query {table}")
            if len(query) < 56 or query[23:27] != struct.pack("<I", 4):
                raise HFSQLDriverError("Risposta query HFSQL non valida")
            handle = struct.unpack_from("<I", query, 52)[0]
            first = _exchange(sock, _frame(0x04AE, handle, struct.pack("<I", 1000) + b"\0" * 9))
            return _read_rows(sock, first, columns, limit)


def connect(
    database: str,
    user: str,
    password: str,
    host: str = "localhost",
    port: int = 4900,
    timeout: float = 10,
) -> Connection:
    return Connection(host, port, database, user, password, timeout)
