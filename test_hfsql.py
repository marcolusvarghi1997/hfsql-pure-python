import struct
import unittest
from decimal import Decimal, localcontext

import hfsql


class DriverTests(unittest.TestCase):
    def test_password_hash(self):
        self.assertEqual(hfsql._sha0(b"").hex(), "9dd534c40da0329913748bb833058b5200ce3e29")

    def test_packet_signature(self):
        self.assertEqual(
            hfsql._frame(0x0427, 0x00200000).hex(),
            "2704170000000100000000e53693a936b2e34500002000",
        )

    def test_schema_column_with_automatic_id_flag(self):
        for flag in (b"", b"\0", b"\x01"):
            schema = bytearray(32)
            struct.pack_into("<II", schema, 0, 8, 0)
            schema += (
                b"\x01id\0\x01ID\0"
                + flag
                + b"\0\0\x01Table\0\x01id\0"
                + b"\0" * 5
                + b"\x0f\x09"
            )

            self.assertEqual(hfsql._columns(bytes(schema), "Table"), [hfsql._Column("id", 8, 0, 0x09)])

    def test_truncated_schema_is_rejected_as_driver_error(self):
        schema = bytearray(32)
        struct.pack_into("<II", schema, 0, 8, 0)
        schema += b"\x01id\0\x01ID\0\0\0\x01Table\0\x01id\0\0\0\0\0\0\x0f"

        with self.assertRaises(hfsql.HFSQLDriverError):
            hfsql._columns(bytes(schema), "Table")

    def test_public_validation(self):
        db = hfsql.connect(database="MYDB", user="reader", password="secret")
        for limit in (0, 1001, 1.5, True):
            with self.assertRaises(ValueError):
                db.rows("Products", limit)
        for table in ("", "1table", "x y", "x.y", "x;DROP"):
            with self.assertRaises(ValueError):
                db.rows(table, 1)
        with self.assertRaises(ValueError):
            hfsql.connect(database="", user="reader", password="secret")
        with self.assertRaises(ValueError):
            hfsql.connect(database="MYDB", user="", password="secret")
        with self.assertRaises(ValueError):
            hfsql.connect(database="MYDB\0other", user="reader", password="secret")
        with self.assertRaises(TypeError):
            hfsql.connect()

    def test_login_packet_uses_supplied_database_and_user(self):
        packet = hfsql._login_request("ExampleDB", "read_only")

        self.assertEqual(struct.unpack_from("<I", packet, 2)[0], len(packet))
        self.assertEqual(struct.unpack_from("<I", packet, 23)[0], len(packet) - 27)
        length_offset = len(
            hfsql._LOGIN_START + b"\x01" + hfsql._CLIENT_HOST.encode() + b"\0" + hfsql._LOGIN_END
        )
        self.assertEqual(
            struct.unpack_from("<I", packet, length_offset)[0],
            len(packet) - length_offset - 4,
        )
        # The client metadata is 64 bytes when the hostname is localhost.
        self.assertEqual(struct.unpack_from("<I", packet, 31)[0], 64)
        self.assertEqual(struct.unpack_from("<I", packet, length_offset)[0], 54)
        self.assertEqual(packet.count(b"ExampleDB\0"), 2)
        self.assertIn(b"read_only\0", packet)
        self.assertIn(b"\x01localhost\0", packet)
        self.assertEqual(
            packet[length_offset + 4:-8],
            b"\x07\x01\0\0\0\x01ExampleDB\0\x01ExampleDB\0\0\x02\0\0\x01read_only\0\x08\0\0\0",
        )
        for database, user in (("", "reader"), ("db\0other", "reader"), ("db", "")):
            with self.assertRaises(ValueError):
                hfsql._login_request(database, user)

    def test_exact_filter_escapes_text_and_accepts_integer(self):
        columns = [hfsql._Column("code", 40, 0, 0x12)]
        text = hfsql._query_request("Products", columns, 1, ("code", "x' OR 1=1"))
        number = hfsql._query_request("Products", columns, 1, ("TitleID", 229))

        self.assertIn(b"WHERE Products.code = 'x'' OR 1=1'", text)
        self.assertIn(b"WHERE Products.TitleID = 229", number)
        with self.assertRaises(ValueError):
            hfsql._query_request("Products", columns, 1, ("code", True))

    def test_numeric_pagination_is_ordered_and_validated(self):
        columns = [
            hfsql._Column("ProductCellID", 8, 0, 0x09),
            hfsql._Column("CategoryID", 8, 8, 0x09),
        ]
        request = hfsql._query_request(
            "ProductCells",
            columns,
            1000,
            where=("CategoryID", 229),
            after=("ProductCellID", 1000),
        )

        self.assertIn(
            b"WHERE ProductCells.CategoryID = 229 AND ProductCells.ProductCellID > 1000",
            request,
        )
        self.assertIn(b"ORDER BY ProductCells.ProductCellID", request)
        with self.assertRaises(ValueError):
            hfsql._query_request(
                "ProductCells", columns, 1000, after=("ProductCellID", True)
            )

    def test_value_decoding(self):
        self.assertEqual(hfsql._decode(hfsql._Column("n", 4, 0, 0x08), b"\xe5\0\0\0"), 229)
        self.assertEqual(hfsql._decode(hfsql._Column("s", 4, 0, 0x12), b"DVD\0"), "DVD")
        self.assertEqual(hfsql._decode(hfsql._Column("s", 2, 0, 0x12), b"\x9d\0"), "\x9d")
        self.assertEqual(
            hfsql._decode(hfsql._Column("d", 8, 0, 0x1A), bytes.fromhex("160aea07cc0d7802")),
            "2026-10-22 11:30:22.284",
        )

    def test_truncated_row_frame_is_rejected(self):
        frame = bytearray(54)
        frame[:2] = b"\xf8\x03"
        struct.pack_into("<I", frame, 31, 75)
        struct.pack_into("<I", frame, 35, 1)
        with self.assertRaises(hfsql.HFSQLDriverError):
            hfsql._decode_row_frame(bytes(frame), [hfsql._Column("id", 4, 0, 0x08)])

    def test_row_stride_comes_from_schema(self):
        frame = bytearray(39 + 142 + 15)
        frame[:2] = b"\xf8\x03"
        struct.pack_into("<I", frame, 2, len(frame))
        struct.pack_into("<II", frame, 31, 142, 1)
        struct.pack_into("<i", frame, 39 + 51, 229)
        struct.pack_into("<i", frame, 39 + 71 + 51, 232)

        rows, final = hfsql._decode_row_frame(
            bytes(frame), [hfsql._Column("id", 4, 0, 0x08)]
        )

        self.assertEqual(rows, [{"id": 229}, {"id": 232}])
        self.assertFalse(final)

    def test_empty_row_frame(self):
        frame = bytearray(54)
        frame[:2] = b"\xf8\x03"
        struct.pack_into("<I", frame, 2, len(frame))

        self.assertEqual(hfsql._decode_row_frame(bytes(frame), [hfsql._Column("id", 4, 0, 0x08)]), ([], False))

    def test_fetch_keeps_immediate_data_and_skips_initial_ack(self):
        column = hfsql._Column("id", 4, 0, 0x08)
        data = bytearray(39 + 71 + 15)
        data[:2] = b"\xf8\x03"
        struct.pack_into("<I", data, 2, len(data))
        struct.pack_into("<I", data, 31, 71)
        struct.pack_into("<i", data, 39 + 51, 229)
        ack = bytearray(37)
        ack[:2] = b"\xff\xff"
        struct.pack_into("<I", ack, 2, len(ack))

        class Socket:
            def __init__(self, frames):
                self.data = bytearray().join(frames)

            def recv(self, size):
                chunk = self.data[:size]
                del self.data[:size]
                return bytes(chunk)

        second = bytearray(data)
        struct.pack_into("<i", second, 39 + 51, 232)
        second[-6] = 1
        self.assertEqual(hfsql._read_rows(Socket([]), bytes(data), [column], 1), [{"id": 229}])
        self.assertEqual(hfsql._read_rows(Socket([data]), bytes(ack), [column], 1), [{"id": 229}])
        self.assertEqual(
            hfsql._read_rows(Socket([ack, second]), bytes(data), [column], 2),
            [{"id": 229}, {"id": 232}],
        )

    def test_memo_rows(self):
        columns = [
            hfsql._Column("id", 8, 0, 0x09),
            hfsql._Column("blob", 8, 8, 0x13),
        ] + [hfsql._Column(f"pad{index}", 1, 16 + index, 0x02) for index in range(7)]
        metadata = bytearray(53)
        struct.pack_into("<I", metadata, 4, 12)
        first = bytearray(25) + struct.pack("<I", 3) + b"abc" + metadata + b"\0" + bytearray(23) + bytearray(16)
        struct.pack_into("<q", first, 25 + 4 + 3 + 53 + 1, 7)
        struct.pack_into("<Q", first, 25 + 4 + 3 + 53 + 1 + 8, 1)
        second = bytearray(52) + b"\0" + bytearray(23) + bytearray(16)
        struct.pack_into("<q", second, 53, 8)
        second[61:69] = b"\xff" * 8
        block = first + second
        frame = bytearray(39) + block + bytearray(15)
        frame[:2] = b"\xf8\x03"
        struct.pack_into("<I", frame, 2, len(frame))
        struct.pack_into("<I", frame, 31, len(block))

        rows, _ = hfsql._decode_row_frame(bytes(frame), columns)

        self.assertEqual([(row["id"], row["blob"]) for row in rows], [(7, b"abc"), (8, None)])

    def test_numeric(self):
        raw = (18_600_000).to_bytes(10, "little", signed=True)
        negative = (-8_600_000).to_bytes(10, "little", signed=True)
        column = hfsql._Column("price", 10, 0, 0x0A)

        self.assertEqual(hfsql._decode(column, raw), Decimal("18.6"))
        self.assertEqual(hfsql._decode(column, negative), Decimal("-8.6"))
        precise = (18_654_321).to_bytes(10, "little", signed=True)
        with localcontext() as context:
            context.prec = 6
            self.assertEqual(hfsql._decode(column, precise), Decimal("18.654321"))


if __name__ == "__main__":
    unittest.main()
