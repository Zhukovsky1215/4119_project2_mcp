import socket
import struct
import time
import argparse


def read_name(packet, offset):
    labels = []
    next_offset = None
    visited = set()
    name_length = 1  # Include the terminating zero byte.

    while True:
        if offset >= len(packet) or offset in visited:
            raise ValueError("Invalid DNS name offset or pointer loop")
        visited.add(offset)

        length = packet[offset]

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("Incomplete compression pointer")
            if next_offset is None:
                next_offset = offset + 2
            offset = ((length & 0x3F) << 8) | packet[offset + 1]
            continue

        offset += 1
        if length == 0:
            if next_offset is None:
                next_offset = offset
            return ".".join(labels) or ".", next_offset

        name_length += 1 + length
        if length > 63 or offset + length > len(packet) or name_length > 255:
            raise ValueError("Invalid DNS label or name length")

        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length




def parse_question(packet):
    if len(packet) < 12:
        raise ValueError("Incomplete DNS header")

    transaction_id, _, question_count, _, _, _ = struct.unpack_from(
        "!6H", packet
    )
    if question_count != 1:
        raise ValueError("Expected one DNS question")

    name, offset = read_name(packet, 12)
    if offset + 4 > len(packet):
        raise ValueError("Incomplete DNS question")

    qtype, qclass = struct.unpack_from("!HH", packet, offset)
    return transaction_id, name, qtype, qclass, offset + 4


def read_record(packet, offset):
    name, offset = read_name(packet, offset)
    if offset + 10 > len(packet):
        raise ValueError("Incomplete DNS record header")

    record_type, record_class, ttl, data_length = struct.unpack_from(
        "!HHIH", packet, offset
    )
    data_start = offset + 10
    data_end = data_start + data_length

    if data_end > len(packet):
        raise ValueError("Incomplete DNS record data")

    return name, record_type, record_class, ttl, data_start, data_end

def validate_client_query(packet):
    question = parse_question(packet)
    _, flags, _, answers, authority, additional = struct.unpack_from("!6H", packet)

    if flags & 0x8000:
        raise ValueError("Expected a DNS query, received a response")
    if flags & 0x7800:
        raise ValueError("Expected a standard DNS query")

    offset = question[-1]
    for _ in range(answers + authority + additional):
        *_, offset = read_record(packet, offset)

    if offset != len(packet):
        raise ValueError("Unexpected bytes after the declared DNS sections")

    return question


def referral_addresses(packet):
    _, _, _, _, question_end = parse_question(packet)
    answer_count, authority_count, additional_count = struct.unpack_from(
        "!3H", packet, 6
    )
    offset = question_end

    for _ in range(answer_count):
        *_, offset = read_record(packet, offset)

    nameservers = set()
    for _ in range(authority_count):
        _, record_type, record_class, _, start, offset = read_record(packet, offset)
        if record_type == 2 and record_class == 1:  # NS, IN
            target, end = read_name(packet, start)
            if end != offset:
                raise ValueError("Invalid NS record data length")
            nameservers.add(target.lower())

    addresses = []
    for _ in range(additional_count):
        name, record_type, record_class, _, start, offset = read_record(packet, offset)
        if (record_type, record_class) == (1, 1) and name.lower() in nameservers:
            if offset - start != 4:
                raise ValueError("Invalid A record data length")
            addresses.append(socket.inet_ntoa(packet[start:offset]))

    return nameservers, addresses

def lookup_nameserver_ipv4(name, transaction_id, depth):
    qname = bytearray()
    for label in name.split("."):
        label_bytes = label.encode("ascii")
        qname.append(len(label_bytes))
        qname.extend(label_bytes)
    qname.append(0)

    header = struct.pack("!6H", transaction_id, 0, 1, 0, 0, 0)
    question = bytes(qname) + struct.pack("!HH", 1, 1)  # A, IN
    response = resolve_iteratively(header + question, depth + 1)

    _, flags, _, answer_count, _, _ = struct.unpack_from("!6H", response)
    if flags & 0x000F:
        return []

    _, _, _, _, offset = parse_question(response)
    addresses = []
    for _ in range(answer_count):
        owner, record_type, record_class, _, start, offset = read_record(
            response, offset
        )
        if (
            owner.lower() == name.lower()
            and (record_type, record_class) == (1, 1)
            and offset - start == 4
        ):
            addresses.append(socket.inet_ntoa(response[start:offset]))

    return addresses

def encode_name(name):
    wire = bytearray()
    for label in name.rstrip(".").split(".") if name != "." else []:
        label_bytes = label.encode("ascii")
        wire.append(len(label_bytes))
        wire.extend(label_bytes)
    wire.append(0)
    return bytes(wire)


def read_a_answers(response, qclass):
    _, _, answer_count = struct.unpack_from("!3H", response, 2)
    _, _, _, _, offset = parse_question(response)
    records = []

    for _ in range(answer_count):
        owner, rtype, rclass, ttl, start, offset = read_record(response, offset)
        if rclass != qclass:
            continue
        if rtype == 1 and offset - start == 4:  # A
            records.append((owner, rtype, ttl, response[start:offset], None))
        elif rtype == 5:  # CNAME
            target, end = read_name(response, start)
            if end != offset:
                raise ValueError("Invalid CNAME record data length")
            records.append((owner, rtype, ttl, encode_name(target), target))

    return records


def follow_a_cname(packet, response, depth):
    transaction_id, name, _, qclass, question_end = parse_question(packet)
    flags = struct.unpack_from("!H", response, 2)[0]
    if flags & 0x000F:
        return response

    records = read_a_answers(response, qclass)
    aliases = {rr[0].lower(): rr for rr in records if rr[1] == 5}
    address_owners = {rr[0].lower() for rr in records if rr[1] == 1}
    chain = []
    seen = set()
    target = name

    while target.lower() in aliases:
        key = target.lower()
        if key in seen:
            raise ValueError("CNAME loop")
        seen.add(key)
        alias = aliases[key]
        chain.append(alias)
        target = alias[4]

    if not chain or target.lower() in address_owners:
        return response

    print(f"Following CNAME: {name} -> {target}")
    target_query = (
        struct.pack("!6H", transaction_id, 0, 1, 0, 0, 0)
        + encode_name(target)
        + struct.pack("!HH", 1, qclass)
    )
    target_reply = resolve_iteratively(target_query, depth + 1)
    target_flags = struct.unpack_from("!H", target_reply, 2)[0]
    answers = chain + read_a_answers(target_reply, qclass)

    reply_flags = 0x8000 | (target_flags & 0x000F)
    reply_flags |= struct.unpack_from("!H", packet, 2)[0] & 0x0100
    header = struct.pack("!6H", transaction_id, reply_flags, 1, len(answers), 0, 0)

    answer_bytes = bytearray()
    for owner, rtype, ttl, data, _ in answers:
        answer_bytes.extend(encode_name(owner))
        answer_bytes.extend(struct.pack("!HHIH", rtype, qclass, ttl, len(data)))
        answer_bytes.extend(data)

    return header + packet[12:question_end] + bytes(answer_bytes)

def resolve_iteratively(packet, depth=0):
    if depth >= 4:
        raise ValueError("Too many nested name-server lookups")

    transaction_id, name, qtype, qclass, question_end = parse_question(packet)
    header = struct.pack("!6H", transaction_id, 0, 1, 0, 0, 1)
    question = packet[12:question_end]
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    query = header + question + opt
    address = "198.41.0.4"
    visited = set()

    for _ in range(12):
        if address in visited:
            raise ValueError("DNS referral loop")
        visited.add(address)
        print(f"Querying {address} for {name}")



        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
            upstream.settimeout(2)
            upstream.connect((address, 53))
            upstream.send(query)
            response = upstream.recv(65535)

        reply_id, reply_name, reply_type, reply_class, _ = parse_question(response)
        flags = struct.unpack_from("!H", response, 2)[0]

        if (
            reply_id != int.from_bytes(query[:2], "big")
            or (reply_name.lower(), reply_type, reply_class)
            != (name.lower(), qtype, qclass)
            or not (flags & 0x8000)
        ):
            raise ValueError("Upstream response does not match the query")

        if flags & 0x0200:
            raise ValueError("Truncated upstream response")

        if flags & 0x0400:
            if qtype == 1:
                return follow_a_cname(packet, response, depth)
            return response

        nameservers, next_addresses = referral_addresses(response)
        print("Referral NS targets:", sorted(nameservers))



        if not next_addresses:
            for nameserver in sorted(nameservers):
                print(f"Looking up IPv4 address for {nameserver}")
                try:
                    next_addresses = lookup_nameserver_ipv4(
                        nameserver, transaction_id, depth
                    )
                except (OSError, ValueError) as error:
                    print(f"Name-server lookup failed: {error}")
                    continue
                if next_addresses:
                    break

        if not next_addresses:
            raise ValueError("Referral has no usable IPv4 address")

        address = next_addresses[0]

    raise ValueError("Too many DNS referrals")

cache = {}


def resolve_cached(packet):
    _, _, _, _, question_end = parse_question(packet)
    key = packet[12:question_end]
    print("Cache lookup:", key.hex(), "entries:", len(cache))

    entry = cache.get(key)
    if entry is not None:
        response, stored_at, ttl_fields = entry
        age = int(time.monotonic() - stored_at)

        if all(age < ttl for _, ttl in ttl_fields):
            print("Cache hit")
            reply = bytearray(response)
            reply[:2] = packet[:2]  # Use this client's transaction ID.
            for ttl_offset, ttl in ttl_fields:
                struct.pack_into("!I", reply, ttl_offset, ttl - age)
            return bytes(reply)

        del cache[key]

    print("Cache miss")
    response = resolve_iteratively(packet)
    stored_at = time.monotonic()

    _, flags, _, answers, authority, additional = struct.unpack_from(
        "!6H", response
    )
    if (flags & 0x000F) != 0 or answers == 0:
        return response

    _, _, _, _, offset = parse_question(response)
    ttl_fields = []

    for _ in range(answers + authority + additional):
        _, record_type, _, ttl, data_start, offset = read_record(response, offset)
        if record_type != 41:  # OPT has EDNS metadata in its TTL field.
            ttl_fields.append((data_start - 6, ttl))

    print("TTLs found:", ttl_fields)
    if ttl_fields and all(ttl > 0 for _, ttl in ttl_fields):
        cache[key] = response, stored_at, ttl_fields
        print("Cache stored:", key.hex())

    return response

def format_client_reply(packet, response):
    client_id, _, _, _, question_end = parse_question(packet)
    _, _, _, answers, authority, additional = struct.unpack_from("!6H", packet)

    client_size = None
    offset = question_end
    for index in range(answers + authority + additional):
        _, rtype, rclass, _, _, offset = read_record(packet, offset)
        if index >= answers + authority and rtype == 41:
            client_size = rclass
            break

    limit = 512
    opt = b""
    if client_size is not None:
        limit = min(1232, max(512, client_size))
        opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)

    _, flags, _, answers, authority, additional = struct.unpack_from("!6H", response)
    _, _, _, _, offset = parse_question(response)

    for _ in range(answers + authority):
        *_, offset = read_record(response, offset)
    required_end = offset

    kept_additional = 0
    for _ in range(additional):
        _, rtype, _, _, _, end = read_record(response, offset)
        if rtype == 41:
            break
        offset = end
        kept_additional += 1

    if offset + len(opt) > limit:
        offset = required_end
        kept_additional = 0

    if offset + len(opt) > limit:
        header = struct.pack("!6H", client_id, flags | 0x0200, 1, 0, 0, int(bool(opt)))
        return header + packet[12:question_end] + opt

    header = struct.pack(
        "!6H", client_id, flags, 1, answers, authority,
        kept_additional + int(bool(opt)),
    )
    return header + response[12:offset] + opt

parser = argparse.ArgumentParser(description="Iterative UDP DNS resolver")
parser.add_argument("port", nargs="?", type=int, default=53)
args = parser.parse_args()

if not 1 <= args.port <= 65535:
    parser.error("port must be between 1 and 65535")

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind(("0.0.0.0", args.port))
    print(f"Listening on UDP port {args.port}", flush=True)

    while True:
        packet, client = server.recvfrom(65535)
        print(f"Received {len(packet)} bytes from {client}")
        try:
            transaction_id, name, qtype, qclass, question_end = validate_client_query(packet)
        except ValueError as error:
            print(f"Dropped packet from {client}: {error}")
            continue

        print(f"ID={transaction_id} NAME={name} QTYPE={qtype} QCLASS={qclass}")
        try:
            response = resolve_cached(packet)
            response = format_client_reply(packet, response)
        except (OSError, ValueError) as error:
            print(f"Lookup failed: {error}")
            continue

        server.sendto(response, client)