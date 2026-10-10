"""Offline DNS parser regressions; malformed input must fail in bounded work."""

import random
import struct
import unittest

from scanner import decode_dns_name, encode_dns_name, parse_ptr_packet


def ptr_response(target=b"\x05phone\x05local\0", size=None, flags=0x8400):
    owner = encode_dns_name("50.100.168.192.in-addr.arpa")
    question = owner + struct.pack("!HH", 12, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 10, len(target) if size is None else size) + target
    return struct.pack("!HHHHHH", 0x1234, flags, 1, 1, 0, 0) + question + answer


class DNSNameTests(unittest.TestCase):
    def test_root_and_maximum_wire_name_roundtrip(self):
        for name in ("", ".", "phone.local", "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61):
            packet = encode_dns_name(name)
            self.assertLessEqual(len(packet), 255)
            self.assertEqual(decode_dns_name(packet, 0), (name.rstrip("."), len(packet)))

    def test_encoder_rejects_invalid_labels_and_oversized_names(self):
        for name in ("a..b", "phone..", "a" * 64, ".".join(["a" * 63] * 4), "设备.local", None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                encode_dns_name(name)

    def test_pointer_keeps_original_end_offset(self):
        packet = encode_dns_name("local") + b"\x05phone\xc0\x00"
        self.assertEqual(decode_dns_name(packet, 7), ("phone.local", len(packet)))

    def test_invalid_offsets_labels_and_cycles_are_rejected(self):
        for packet, offset in ((b"\0", -1), (b"\0", 1), (b"\xc0", 0), (b"\xc0\xff", 0),
                               (b"\xc0\x00", 0), (b"\xc0\x02\xc0\x00", 0),
                               (b"\x40" + b"x" * 64, 0), (b"\x80", 0), (b"\x05abc", 0)):
            with self.subTest(packet=packet, offset=offset), self.assertRaises(ValueError):
                decode_dns_name(packet, offset)

    def test_expanded_compressed_name_is_limited(self):
        suffix = b"".join(b"\x3f" + b"a" * 63 for _ in range(3)) + b"\0"
        packet = suffix + b"\x3f" + b"b" * 63 + b"\xc0\x00"
        with self.assertRaises(ValueError):
            decode_dns_name(packet, len(suffix))


class PTRPacketTests(unittest.TestCase):
    def test_valid_ptr_and_compressed_target(self):
        self.assertEqual(parse_ptr_packet(ptr_response()), [("50.100.168.192.in-addr.arpa", "phone.local")])
        self.assertEqual(parse_ptr_packet(ptr_response(b"\xc0\x0c")),
                         [("50.100.168.192.in-addr.arpa", "50.100.168.192.in-addr.arpa")])

    def test_ptr_cannot_read_past_its_declared_data(self):
        for size in (0, 1, 12, 14):
            with self.subTest(size=size), self.assertRaises(ValueError):
                parse_ptr_packet(ptr_response(size=size))
        with self.assertRaises(ValueError):
            parse_ptr_packet(ptr_response(b"\xc0\x0c", size=1))

    def test_question_and_record_headers_are_checked(self):
        for packet in (struct.pack("!HHHHHH", 0, 0x8000, 1, 0, 0, 0) + b"\0",
                       struct.pack("!HHHHHH", 0, 0x8000, 0, 1, 0, 0) + b"\0\0",
                       struct.pack("!HHHHHH", 0, 0x8000, 65535, 65535, 65535, 65535)):
            with self.subTest(packet=packet), self.assertRaises(ValueError):
                parse_ptr_packet(packet)

    def test_nonanswer_error_opcode_and_truncation_are_ignored(self):
        for flags in (0, 0x8403, 0x8C00, 0x8600):
            self.assertEqual(parse_ptr_packet(ptr_response(flags=flags)), [])
        with self.assertRaises(ValueError):
            parse_ptr_packet(ptr_response() + b"\0" * 65536)

    def test_seeded_malformed_packets_never_leak_index_or_struct_errors(self):
        randomizer = random.Random(1701)
        packets = [randomizer.randbytes(randomizer.randrange(300)) for _ in range(1000)]
        valid = ptr_response()
        for position in range(len(valid)):
            for byte in (0, 63, 127, 192, 255):
                packets.append(valid[:position] + bytes([byte]) + valid[position + 1:])
        for packet in packets:
            try:
                records = parse_ptr_packet(packet)
            except ValueError:
                continue
            self.assertLessEqual(len(records), len(packet) // 11)


if __name__ == "__main__":
    unittest.main()
