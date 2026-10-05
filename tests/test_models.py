"""Tests de core/models.py : normalize_mac, PortResult, Host, ScanResult."""

import copy
import json
from datetime import date, datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

import pytest

from netscan.core.models import (
    VALID_PORT_STATES,
    VALID_PROTOCOLS,
    VALID_SCAN_STATUSES,
    VALID_SCAN_TYPES,
    Host,
    PortResult,
    ScanResult,
    normalize_mac,
)

TZ = timezone(timedelta(hours=2))
START = datetime(2026, 10, 3, 11, 20, 0, tzinfo=TZ)
NAN = float("nan")
INF = float("inf")


# --- Fabriques ------------------------------------------------------------


def make_port(**overrides):
    fields = {"port": 22, "protocol": "tcp", "state": "open"}
    fields.update(overrides)
    return PortResult(**fields)


def make_host(**overrides):
    fields = {"ip": "10.0.0.1"}
    fields.update(overrides)
    return Host(**fields)


def make_scan(**overrides):
    fields = {"target": "192.168.1.0/24"}
    fields.update(overrides)
    return ScanResult(**fields)


def sample_port_dict():
    return {
        "port": 22,
        "protocol": "tcp",
        "state": "open",
        "service": "ssh",
        "version": "OpenSSH 9.2",
        "banner": "SSH-2.0-OpenSSH_9.2",
    }


def sample_host_dict():
    return {
        "ip": "192.168.1.10",
        "mac": "aa:bb:cc:dd:ee:ff",
        "vendor": "Raspberry Pi",
        "rtt_ms": 1.8,
        "os_guess": None,
        "ports": [sample_port_dict()],
    }


def sample_scan_dict():
    """Le JSON cible du projet (sprint 1 : un hôte, un port ouvert)."""
    return {
        "scan": {
            "id": 12,
            "target": "192.168.1.0/24",
            "type": "syn",
            "ports": "1-1024",
            "started_at": "2026-10-03T11:20:00+02:00",
            "duration_s": 41.7,
            "status": "completed",
        },
        "hosts": [sample_host_dict()],
        "summary": {"hosts_up": 1, "open_ports": 1},
    }


def sample_scan():
    return ScanResult.from_dict(sample_scan_dict())


# --- Constantes -----------------------------------------------------------


def test_constants_have_the_expected_values():
    assert set(VALID_PROTOCOLS) == {"tcp", "udp"}
    assert set(VALID_PORT_STATES) == {"open", "closed", "filtered"}
    assert set(VALID_SCAN_TYPES) == {"connect", "syn", "udp"}
    assert set(VALID_SCAN_STATUSES) == {"pending", "running", "completed", "failed"}


# --- normalize_mac --------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("Aa:bB:Cc:dD:Ee:fF", "aa:bb:cc:dd:ee:ff"),
        ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
        ("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"),
        ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        ("AABB.CCDD.EEFF", "aa:bb:cc:dd:ee:ff"),
        ("aabbccddeeff", "aa:bb:cc:dd:ee:ff"),
        ("AABBCCDDEEFF", "aa:bb:cc:dd:ee:ff"),
        ("  aa:bb:cc:dd:ee:ff  ", "aa:bb:cc:dd:ee:ff"),
        ("\taa:bb:cc:dd:ee:ff\n", "aa:bb:cc:dd:ee:ff"),
        ("00:00:00:00:00:00", "00:00:00:00:00:00"),
        ("ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff"),
        ("a1:b2:c3:d4:e5:f6", "a1:b2:c3:d4:e5:f6"),
        ("0A-1B-2C-3D-4E-5F", "0a:1b:2c:3d:4e:5f"),
        ("0a1b.2c3d.4e5f", "0a:1b:2c:3d:4e:5f"),
    ],
)
def test_normalize_mac_accepts_all_common_formats(raw, expected):
    assert normalize_mac(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "aa:bb:cc:dd:ee",  # 5 octets
        "aa:bb:cc:dd:ee:ff:00",  # 7 octets
        "aa:bb:cc:dd:ee:f",  # dernier octet incomplet
        "a:bb:cc:dd:ee:ff",  # premier octet incomplet
        "gg:bb:cc:dd:ee:ff",  # caractère non hexadécimal
        "aa:bb:cc:dd:ee:fg",
        "aa:bb-cc:dd-ee:ff",  # séparateurs mélangés
        "aa-bb:cc-dd:ee-ff",
        "aa bb cc dd ee ff",  # espaces comme séparateurs
        "aa::bb:cc:dd:ee",
        "aabb.ccdd",  # format Cisco incomplet
        "aabb.ccdd.eeff.0011",
        "aa.bb.cc.dd.ee.ff",  # mauvais groupement
        "aabbcc:ddeeff",
        "aabbccddeef",  # 11 chiffres
        "aabbccddeeff0",  # 13 chiffres
        "aabbccddeeff00",
        "0xaabbccddeeff",
        "aa:bb:cc:dd:ee:ff\n00",
        ":aa:bb:cc:dd:ee:ff",
        "aa:bb:cc:dd:ee:ff:",
        "zzzzzzzzzzzz",
        "éé:bb:cc:dd:ee:ff",
    ],
)
def test_normalize_mac_rejects_invalid_values(raw):
    with pytest.raises(ValueError):
        normalize_mac(raw)


@pytest.mark.parametrize("raw", [None, 123, 1.5, b"aa:bb:cc:dd:ee:ff", ["aa"], True])
def test_normalize_mac_rejects_non_strings(raw):
    with pytest.raises(ValueError):
        normalize_mac(raw)


@pytest.mark.parametrize(
    "raw", ["AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "aabbccddeeff", "aa:bb:cc:dd:ee:ff"]
)
def test_normalize_mac_is_idempotent(raw):
    once = normalize_mac(raw)
    assert normalize_mac(once) == once


# --- PortResult : construction -------------------------------------------


def test_port_result_minimal():
    p = PortResult(port=22, protocol="tcp", state="open")
    assert p.port == 22
    assert p.protocol == "tcp"
    assert p.state == "open"
    assert p.service is None
    assert p.version is None
    assert p.banner is None


def test_port_result_full():
    p = PortResult(
        port=22,
        protocol="tcp",
        state="open",
        service="ssh",
        version="OpenSSH 9.2",
        banner="SSH-2.0-OpenSSH_9.2",
    )
    assert p.service == "ssh"
    assert p.version == "OpenSSH 9.2"
    assert p.banner == "SSH-2.0-OpenSSH_9.2"


def test_port_result_accepts_positional_arguments():
    p = PortResult(80, "tcp", "closed")
    assert (p.port, p.protocol, p.state) == (80, "tcp", "closed")


@pytest.mark.parametrize("port", [1, 22, 80, 443, 1024, 8080, 65534, 65535])
def test_port_result_accepts_valid_ports(port):
    assert make_port(port=port).port == port


@pytest.mark.parametrize(
    "port", [0, -1, -22, 65536, 65537, 100000, 10**9, "22", "", 22.0, 22.5, None, True, False, [22], (22,)]
)
def test_port_result_rejects_invalid_ports(port):
    with pytest.raises(ValueError):
        make_port(port=port)


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_port_result_accepts_valid_protocols(protocol):
    assert make_port(protocol=protocol).protocol == protocol


@pytest.mark.parametrize(
    "raw, expected",
    [("TCP", "tcp"), ("Udp", "udp"), (" tcp ", "tcp"), ("\tUDP\n", "udp")],
)
def test_port_result_normalizes_protocol(raw, expected):
    assert make_port(protocol=raw).protocol == expected


@pytest.mark.parametrize("protocol", ["icmp", "sctp", "", "   ", "tcp/udp", "t cp", None, 6, ["tcp"], b"tcp"])
def test_port_result_rejects_invalid_protocols(protocol):
    with pytest.raises(ValueError):
        make_port(protocol=protocol)


@pytest.mark.parametrize("state", ["open", "closed", "filtered"])
def test_port_result_accepts_valid_states(state):
    assert make_port(state=state).state == state


@pytest.mark.parametrize(
    "raw, expected",
    [("OPEN", "open"), ("Closed", "closed"), (" filtered ", "filtered")],
)
def test_port_result_normalizes_state(raw, expected):
    assert make_port(state=raw).state == expected


@pytest.mark.parametrize(
    "state", ["up", "down", "open|filtered", "closedd", "", "   ", None, 1, True, ["open"]]
)
def test_port_result_rejects_invalid_states(state):
    with pytest.raises(ValueError):
        make_port(state=state)


@pytest.mark.parametrize("field_name", ["service", "version", "banner"])
@pytest.mark.parametrize("value", [123, 1.5, True, b"ssh", ["ssh"], {"a": 1}])
def test_port_result_rejects_non_string_optional_fields(field_name, value):
    with pytest.raises(ValueError):
        make_port(**{field_name: value})


@pytest.mark.parametrize("field_name", ["service", "version", "banner"])
@pytest.mark.parametrize("value", [None, "", "x", "texte avec espaces", "é ü 日本"])
def test_port_result_accepts_string_or_none_optional_fields(field_name, value):
    assert getattr(make_port(**{field_name: value}), field_name) == value


def test_port_result_keeps_banner_untouched():
    banner = "SSH-2.0-OpenSSH_9.2\r\n"
    assert make_port(banner=banner).banner == banner


def test_port_result_keeps_service_and_version_untouched():
    p = make_port(service="  ssh  ", version=" 9.2 ")
    assert p.service == "  ssh  "
    assert p.version == " 9.2 "


def test_port_result_error_message_mentions_the_field():
    with pytest.raises(ValueError, match="(?i)port"):
        make_port(port=0)
    with pytest.raises(ValueError, match="(?i)protocol"):
        make_port(protocol="icmp")
    with pytest.raises(ValueError, match="(?i)state"):
        make_port(state="up")


# --- PortResult : égalité -------------------------------------------------


def test_port_result_equality():
    assert make_port() == make_port()
    assert make_port(service="ssh") == make_port(service="ssh")


@pytest.mark.parametrize(
    "overrides",
    [
        {"port": 23},
        {"protocol": "udp"},
        {"state": "closed"},
        {"service": "ssh"},
        {"version": "9.2"},
        {"banner": "SSH"},
    ],
)
def test_port_result_inequality(overrides):
    assert make_port() != make_port(**overrides)


def test_port_result_normalized_values_are_equal():
    assert make_port(protocol="TCP", state="OPEN") == make_port()


# --- PortResult : to_dict -------------------------------------------------


def test_port_result_to_dict_full():
    assert make_port(
        service="ssh", version="OpenSSH 9.2", banner="SSH-2.0-OpenSSH_9.2"
    ).to_dict() == sample_port_dict()


def test_port_result_to_dict_keeps_none_values():
    assert make_port().to_dict() == {
        "port": 22,
        "protocol": "tcp",
        "state": "open",
        "service": None,
        "version": None,
        "banner": None,
    }


def test_port_result_to_dict_key_order():
    assert list(make_port().to_dict()) == [
        "port",
        "protocol",
        "state",
        "service",
        "version",
        "banner",
    ]


def test_port_result_to_dict_is_json_serializable():
    data = make_port(service="ssh", banner="é\r\n").to_dict()
    assert json.loads(json.dumps(data)) == data


def test_port_result_to_dict_returns_a_new_dict_each_time():
    p = make_port()
    first = p.to_dict()
    first["port"] = 9999
    assert p.to_dict()["port"] == 22
    assert p.port == 22


def test_port_result_to_dict_uses_normalized_values():
    d = make_port(protocol="UDP", state=" Filtered ").to_dict()
    assert d["protocol"] == "udp"
    assert d["state"] == "filtered"


# --- PortResult : from_dict -----------------------------------------------


def test_port_result_from_dict_full():
    assert PortResult.from_dict(sample_port_dict()) == make_port(
        service="ssh", version="OpenSSH 9.2", banner="SSH-2.0-OpenSSH_9.2"
    )


def test_port_result_from_dict_minimal():
    p = PortResult.from_dict({"port": 80, "protocol": "tcp", "state": "closed"})
    assert p == PortResult(port=80, protocol="tcp", state="closed")
    assert p.service is None and p.version is None and p.banner is None


def test_port_result_roundtrip():
    original = make_port(service="http", version="nginx 1.25", banner="HTTP/1.1 200 OK")
    assert PortResult.from_dict(original.to_dict()) == original


def test_port_result_roundtrip_through_json():
    original = make_port(port=53, protocol="udp", state="filtered")
    restored = PortResult.from_dict(json.loads(json.dumps(original.to_dict())))
    assert restored == original


@pytest.mark.parametrize("missing", ["port", "protocol", "state"])
def test_port_result_from_dict_requires_mandatory_keys(missing):
    data = sample_port_dict()
    del data[missing]
    with pytest.raises(ValueError):
        PortResult.from_dict(data)


def test_port_result_from_dict_ignores_unknown_keys():
    data = sample_port_dict()
    data["extra"] = "ignored"
    assert PortResult.from_dict(data) == PortResult.from_dict(sample_port_dict())


@pytest.mark.parametrize("data", [None, [], "port", 22, (22, "tcp", "open")])
def test_port_result_from_dict_rejects_non_dict(data):
    with pytest.raises(ValueError):
        PortResult.from_dict(data)


@pytest.mark.parametrize(
    "overrides",
    [{"port": 0}, {"port": "22"}, {"protocol": "icmp"}, {"state": "up"}, {"service": 5}],
)
def test_port_result_from_dict_validates_values(overrides):
    data = sample_port_dict()
    data.update(overrides)
    with pytest.raises(ValueError):
        PortResult.from_dict(data)


def test_port_result_from_dict_does_not_mutate_input():
    data = sample_port_dict()
    snapshot = copy.deepcopy(data)
    PortResult.from_dict(data)
    assert data == snapshot


# --- Host : construction --------------------------------------------------


def test_host_minimal():
    h = Host(ip="10.0.0.1")
    assert h.ip == IPv4Address("10.0.0.1")
    assert h.mac is None
    assert h.vendor is None
    assert h.rtt_ms is None
    assert h.os_guess is None
    assert h.ports == []


def test_host_accepts_ipv4address_object():
    h = Host(ip=IPv4Address("192.168.1.10"))
    assert isinstance(h.ip, IPv4Address)
    assert h.ip == IPv4Address("192.168.1.10")


def test_host_converts_string_ip_to_ipv4address():
    h = Host(ip="192.168.1.10")
    assert isinstance(h.ip, IPv4Address)


@pytest.mark.parametrize("raw", [" 10.0.0.1", "10.0.0.1 ", "  10.0.0.1  ", "\t10.0.0.1\n"])
def test_host_ignores_spaces_around_ip(raw):
    assert make_host(ip=raw).ip == IPv4Address("10.0.0.1")


@pytest.mark.parametrize(
    "ip",
    ["0.0.0.0", "10.0.0.0", "10.0.0.255", "127.0.0.1", "255.255.255.255", "192.168.1.10"],
)
def test_host_accepts_any_ipv4_address(ip):
    assert make_host(ip=ip).ip == IPv4Address(ip)


@pytest.mark.parametrize(
    "ip",
    [
        "",
        "   ",
        "abc",
        "300.1.1.1",
        "10.0.0",
        "10.0.0.1.1",
        "10.0.0.1/24",
        "10.0.0.1,10.0.0.2",
        "10.0.0. 1",
        "::1",
        "2001:db8::1",
        IPv6Address("::1"),
        None,
        167772161,
        1.5,
        True,
        ["10.0.0.1"],
        b"10.0.0.1",
    ],
)
def test_host_rejects_invalid_ips(ip):
    with pytest.raises(ValueError):
        make_host(ip=ip)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
        ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        ("aabbccddeeff", "aa:bb:cc:dd:ee:ff"),
        (" aa:bb:cc:dd:ee:ff ", "aa:bb:cc:dd:ee:ff"),
    ],
)
def test_host_normalizes_mac(raw, expected):
    assert make_host(mac=raw).mac == expected


def test_host_mac_none_stays_none():
    assert make_host(mac=None).mac is None


@pytest.mark.parametrize("mac", ["", "   ", "zz:zz:zz:zz:zz:zz", "aa:bb:cc", 5, b"aabbccddeeff", ["aa"]])
def test_host_rejects_invalid_mac(mac):
    with pytest.raises(ValueError):
        make_host(mac=mac)


@pytest.mark.parametrize("field_name", ["vendor", "os_guess"])
@pytest.mark.parametrize("value", [None, "", "Raspberry Pi", "Linux 5.x", "日本"])
def test_host_accepts_string_or_none_for_text_fields(field_name, value):
    assert getattr(make_host(**{field_name: value}), field_name) == value


@pytest.mark.parametrize("field_name", ["vendor", "os_guess"])
@pytest.mark.parametrize("value", [123, 1.5, True, b"x", ["x"], {"a": 1}])
def test_host_rejects_non_string_text_fields(field_name, value):
    with pytest.raises(ValueError):
        make_host(**{field_name: value})


@pytest.mark.parametrize("rtt", [0, 0.0, 0.001, 1, 1.8, 3, 250.5, 1e6])
def test_host_accepts_valid_rtt(rtt):
    assert make_host(rtt_ms=rtt).rtt_ms == rtt


def test_host_rtt_is_stored_as_float():
    assert isinstance(make_host(rtt_ms=3).rtt_ms, float)
    assert make_host(rtt_ms=3).rtt_ms == 3.0


def test_host_rtt_none_stays_none():
    assert make_host(rtt_ms=None).rtt_ms is None


@pytest.mark.parametrize("rtt", [-0.1, -1, -1000, NAN, INF, float("-inf"), "1.8", "", True, False, [], (1,)])
def test_host_rejects_invalid_rtt(rtt):
    with pytest.raises(ValueError):
        make_host(rtt_ms=rtt)


def test_host_ports_default_is_empty_list():
    assert make_host().ports == []


def test_host_default_ports_lists_are_independent():
    a = make_host()
    b = make_host()
    a.ports.append(make_port())
    assert b.ports == []


def test_host_keeps_given_ports_in_order():
    ports = [make_port(port=80), make_port(port=22), make_port(port=443)]
    assert [p.port for p in make_host(ports=ports).ports] == [80, 22, 443]


def test_host_stores_a_copy_of_the_ports_list():
    ports = [make_port()]
    h = make_host(ports=ports)
    ports.append(make_port(port=80))
    assert len(h.ports) == 1


def test_host_accepts_empty_ports_list():
    assert make_host(ports=[]).ports == []


@pytest.mark.parametrize(
    "ports",
    [
        None,
        "22",
        22,
        (make_port(),),
        {make_port().port: make_port()},
        [1, 2],
        [None],
        [sample_port_dict()],
        [make_port(), "x"],
        [make_port(), None],
    ],
)
def test_host_rejects_invalid_ports_argument(ports):
    with pytest.raises(ValueError):
        make_host(ports=ports)


def test_host_error_message_mentions_the_field():
    with pytest.raises(ValueError, match="(?i)ip"):
        make_host(ip="abc")
    with pytest.raises(ValueError, match="(?i)mac"):
        make_host(mac="zz")
    with pytest.raises(ValueError, match="(?i)rtt_ms"):
        make_host(rtt_ms=-1)


# --- Host : égalité -------------------------------------------------------


def test_host_equality():
    assert make_host() == make_host()
    assert make_host(ip=IPv4Address("10.0.0.1")) == make_host(ip="10.0.0.1")


def test_host_equality_after_normalization():
    assert make_host(mac="AA-BB-CC-DD-EE-FF") == make_host(mac="aa:bb:cc:dd:ee:ff")


@pytest.mark.parametrize(
    "overrides",
    [
        {"ip": "10.0.0.2"},
        {"mac": "aa:bb:cc:dd:ee:ff"},
        {"vendor": "Dell"},
        {"rtt_ms": 1.0},
        {"os_guess": "Linux"},
        {"ports": [make_port()]},
    ],
)
def test_host_inequality(overrides):
    assert make_host() != make_host(**overrides)


# --- Host : open_ports ----------------------------------------------------


def test_open_ports_empty_when_no_ports():
    assert make_host().open_ports == []


def test_open_ports_returns_only_open_ports():
    open1 = make_port(port=22, state="open")
    closed = make_port(port=23, state="closed")
    filtered = make_port(port=25, state="filtered")
    open2 = make_port(port=80, state="open")
    h = make_host(ports=[open1, closed, filtered, open2])
    assert h.open_ports == [open1, open2]


def test_open_ports_keeps_original_order():
    h = make_host(ports=[make_port(port=443), make_port(port=22), make_port(port=80)])
    assert [p.port for p in h.open_ports] == [443, 22, 80]


def test_open_ports_empty_when_none_open():
    h = make_host(ports=[make_port(state="closed"), make_port(port=80, state="filtered")])
    assert h.open_ports == []


def test_open_ports_includes_tcp_and_udp():
    tcp = make_port(port=53, protocol="tcp")
    udp = make_port(port=53, protocol="udp")
    assert make_host(ports=[tcp, udp]).open_ports == [tcp, udp]


def test_open_ports_returns_a_new_list():
    h = make_host(ports=[make_port()])
    h.open_ports.clear()
    assert len(h.ports) == 1
    assert len(h.open_ports) == 1


def test_open_ports_follows_changes_to_ports():
    h = make_host()
    assert h.open_ports == []
    h.ports.append(make_port())
    assert len(h.open_ports) == 1


# --- Host : to_dict -------------------------------------------------------


def test_host_to_dict_full():
    h = Host(
        ip="192.168.1.10",
        mac="aa:bb:cc:dd:ee:ff",
        vendor="Raspberry Pi",
        rtt_ms=1.8,
        ports=[
            PortResult(
                port=22,
                protocol="tcp",
                state="open",
                service="ssh",
                version="OpenSSH 9.2",
                banner="SSH-2.0-OpenSSH_9.2",
            )
        ],
    )
    assert h.to_dict() == sample_host_dict()


def test_host_to_dict_minimal():
    assert make_host().to_dict() == {
        "ip": "10.0.0.1",
        "mac": None,
        "vendor": None,
        "rtt_ms": None,
        "os_guess": None,
        "ports": [],
    }


def test_host_to_dict_key_order():
    assert list(make_host().to_dict()) == [
        "ip",
        "mac",
        "vendor",
        "rtt_ms",
        "os_guess",
        "ports",
    ]


def test_host_to_dict_ip_is_a_string():
    assert make_host(ip=IPv4Address("10.0.0.1")).to_dict()["ip"] == "10.0.0.1"
    assert isinstance(make_host().to_dict()["ip"], str)


def test_host_to_dict_ports_are_dicts_in_order():
    h = make_host(ports=[make_port(port=80), make_port(port=22)])
    assert [p["port"] for p in h.to_dict()["ports"]] == [80, 22]
    assert all(isinstance(p, dict) for p in h.to_dict()["ports"])


def test_host_to_dict_is_json_serializable():
    data = sample_host_dict()
    host = Host.from_dict(data)
    assert json.loads(json.dumps(host.to_dict())) == data


def test_host_to_dict_does_not_share_state_with_host():
    h = make_host(ports=[make_port()])
    d = h.to_dict()
    d["ports"].clear()
    d["ip"] = "1.1.1.1"
    assert len(h.ports) == 1
    assert h.ip == IPv4Address("10.0.0.1")


def test_host_to_dict_nested_port_dicts_are_copies():
    h = make_host(ports=[make_port()])
    h.to_dict()["ports"][0]["port"] = 9999
    assert h.ports[0].port == 22


def test_host_to_dict_rtt_is_a_float():
    assert make_host(rtt_ms=3).to_dict()["rtt_ms"] == 3.0
    assert isinstance(make_host(rtt_ms=3).to_dict()["rtt_ms"], float)


# --- Host : from_dict -----------------------------------------------------


def test_host_from_dict_full():
    h = Host.from_dict(sample_host_dict())
    assert h.ip == IPv4Address("192.168.1.10")
    assert h.mac == "aa:bb:cc:dd:ee:ff"
    assert h.vendor == "Raspberry Pi"
    assert h.rtt_ms == 1.8
    assert h.os_guess is None
    assert h.ports == [PortResult.from_dict(sample_port_dict())]


def test_host_from_dict_minimal():
    h = Host.from_dict({"ip": "10.0.0.1"})
    assert h == Host(ip="10.0.0.1")
    assert h.ports == []


@pytest.mark.parametrize("ports", [None, []])
def test_host_from_dict_ports_none_or_empty(ports):
    assert Host.from_dict({"ip": "10.0.0.1", "ports": ports}).ports == []


def test_host_roundtrip():
    original = make_host(
        mac="aa:bb:cc:dd:ee:ff",
        vendor="Dell",
        rtt_ms=2.5,
        os_guess="Windows",
        ports=[make_port(), make_port(port=53, protocol="udp", state="filtered")],
    )
    assert Host.from_dict(original.to_dict()) == original


def test_host_roundtrip_through_json():
    original = Host.from_dict(sample_host_dict())
    restored = Host.from_dict(json.loads(json.dumps(original.to_dict())))
    assert restored == original


def test_host_from_dict_requires_ip():
    data = sample_host_dict()
    del data["ip"]
    with pytest.raises(ValueError):
        Host.from_dict(data)


def test_host_from_dict_ignores_unknown_keys():
    data = sample_host_dict()
    data["extra"] = 1
    assert Host.from_dict(data) == Host.from_dict(sample_host_dict())


@pytest.mark.parametrize("data", [None, [], "10.0.0.1", 5, ("10.0.0.1",)])
def test_host_from_dict_rejects_non_dict(data):
    with pytest.raises(ValueError):
        Host.from_dict(data)


@pytest.mark.parametrize("ports", ["x", 5, {}, {"port": 22}, (sample_port_dict(),), True])
def test_host_from_dict_rejects_non_list_ports(ports):
    with pytest.raises(ValueError):
        Host.from_dict({"ip": "10.0.0.1", "ports": ports})


@pytest.mark.parametrize("bad_port", [None, "x", 22, {"port": 0, "protocol": "tcp", "state": "open"}, {"port": 22}])
def test_host_from_dict_rejects_invalid_port_entries(bad_port):
    with pytest.raises(ValueError):
        Host.from_dict({"ip": "10.0.0.1", "ports": [sample_port_dict(), bad_port]})


@pytest.mark.parametrize(
    "overrides",
    [{"ip": "abc"}, {"mac": "zz"}, {"rtt_ms": -1}, {"rtt_ms": "1.8"}, {"vendor": 5}],
)
def test_host_from_dict_validates_values(overrides):
    data = sample_host_dict()
    data.update(overrides)
    with pytest.raises(ValueError):
        Host.from_dict(data)


def test_host_from_dict_does_not_mutate_input():
    data = sample_host_dict()
    snapshot = copy.deepcopy(data)
    Host.from_dict(data)
    assert data == snapshot


def test_host_from_dict_does_not_share_ports_with_input():
    data = sample_host_dict()
    h = Host.from_dict(data)
    data["ports"].clear()
    assert len(h.ports) == 1


# --- ScanResult : construction -------------------------------------------


def test_scan_result_minimal():
    s = ScanResult(target="192.168.1.0/24")
    assert s.target == "192.168.1.0/24"
    assert s.scan_type is None
    assert s.ports is None
    assert s.status == "pending"
    assert s.started_at is None
    assert s.duration_s is None
    assert s.id is None
    assert s.hosts == []


def test_scan_result_full():
    host = make_host()
    s = ScanResult(
        target="192.168.1.0/24",
        scan_type="syn",
        ports="1-1024",
        status="completed",
        started_at=START,
        duration_s=41.7,
        id=12,
        hosts=[host],
    )
    assert s.scan_type == "syn"
    assert s.ports == "1-1024"
    assert s.status == "completed"
    assert s.started_at == START
    assert s.duration_s == 41.7
    assert s.id == 12
    assert s.hosts == [host]


@pytest.mark.parametrize(
    "target", ["192.168.1.0/24", "10.0.0.1", "10.0.0.1,10.0.0.2", "10.0.0.0/30", "scanme.local"]
)
def test_scan_result_accepts_target_strings(target):
    assert make_scan(target=target).target == target


@pytest.mark.parametrize("raw", ["  10.0.0.1  ", "\t10.0.0.1\n", " 192.168.1.0/24"])
def test_scan_result_strips_target(raw):
    assert make_scan(target=raw).target == raw.strip()


@pytest.mark.parametrize("target", ["", "   ", "\t\n", None, 123, ["10.0.0.1"], b"10.0.0.1", True])
def test_scan_result_rejects_invalid_target(target):
    with pytest.raises(ValueError):
        make_scan(target=target)


def test_scan_result_target_is_required():
    with pytest.raises(TypeError):
        ScanResult()


@pytest.mark.parametrize("scan_type", ["connect", "syn", "udp"])
def test_scan_result_accepts_valid_scan_types(scan_type):
    assert make_scan(scan_type=scan_type).scan_type == scan_type


def test_scan_result_scan_type_none_is_allowed():
    assert make_scan(scan_type=None).scan_type is None


@pytest.mark.parametrize("raw, expected", [("SYN", "syn"), (" Connect ", "connect"), ("UDP", "udp")])
def test_scan_result_normalizes_scan_type(raw, expected):
    assert make_scan(scan_type=raw).scan_type == expected


@pytest.mark.parametrize("scan_type", ["discover", "icmp", "arp", "tcp", "", "   ", 1, True, ["syn"], b"syn"])
def test_scan_result_rejects_invalid_scan_types(scan_type):
    with pytest.raises(ValueError):
        make_scan(scan_type=scan_type)


@pytest.mark.parametrize("ports", [None, "22", "22,80,443", "1-1024", "top100", "top1000", "all", ""])
def test_scan_result_accepts_ports_strings(ports):
    assert make_scan(ports=ports).ports == ports


@pytest.mark.parametrize("ports", [22, 1.5, True, [22, 80], (1, 2), {"a": 1}, b"22"])
def test_scan_result_rejects_non_string_ports(ports):
    with pytest.raises(ValueError):
        make_scan(ports=ports)


@pytest.mark.parametrize("status", ["pending", "running", "completed", "failed"])
def test_scan_result_accepts_valid_statuses(status):
    assert make_scan(status=status).status == status


@pytest.mark.parametrize(
    "raw, expected",
    [("COMPLETED", "completed"), (" Running ", "running"), ("Failed", "failed")],
)
def test_scan_result_normalizes_status(raw, expected):
    assert make_scan(status=raw).status == expected


@pytest.mark.parametrize("status", ["done", "error", "cancelled", "", "   ", None, 1, True, ["pending"]])
def test_scan_result_rejects_invalid_statuses(status):
    with pytest.raises(ValueError):
        make_scan(status=status)


@pytest.mark.parametrize(
    "started_at",
    [
        START,
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 1, 12, 30, 15, 123456, tzinfo=timezone(timedelta(hours=-5, minutes=-30))),
        None,
    ],
)
def test_scan_result_accepts_aware_datetimes_and_none(started_at):
    assert make_scan(started_at=started_at).started_at == started_at


@pytest.mark.parametrize(
    "started_at",
    [
        datetime(2026, 10, 3, 11, 20, 0),  # naïf
        "2026-10-03T11:20:00+02:00",  # chaîne
        1759483200,  # timestamp
        1759483200.5,
        date(2026, 10, 3),
        True,
        [START],
    ],
)
def test_scan_result_rejects_invalid_started_at(started_at):
    with pytest.raises(ValueError):
        make_scan(started_at=started_at)


@pytest.mark.parametrize("duration", [0, 0.0, 0.5, 1, 41.7, 3600, 1e6])
def test_scan_result_accepts_valid_durations(duration):
    assert make_scan(duration_s=duration).duration_s == duration


def test_scan_result_duration_is_stored_as_float():
    assert isinstance(make_scan(duration_s=3).duration_s, float)


@pytest.mark.parametrize("duration", [-0.1, -1, NAN, INF, float("-inf"), "4", "", True, False, [1], (1,)])
def test_scan_result_rejects_invalid_durations(duration):
    with pytest.raises(ValueError):
        make_scan(duration_s=duration)


@pytest.mark.parametrize("scan_id", [1, 2, 12, 10**6])
def test_scan_result_accepts_valid_ids(scan_id):
    assert make_scan(id=scan_id).id == scan_id


@pytest.mark.parametrize("scan_id", [0, -1, -12, "12", "", 1.0, 1.5, True, False, [1], (1,)])
def test_scan_result_rejects_invalid_ids(scan_id):
    with pytest.raises(ValueError):
        make_scan(id=scan_id)


def test_scan_result_hosts_default_is_empty_and_independent():
    a = make_scan()
    b = make_scan()
    a.hosts.append(make_host())
    assert b.hosts == []


def test_scan_result_keeps_given_hosts_in_order():
    hosts = [make_host(ip="10.0.0.3"), make_host(ip="10.0.0.1"), make_host(ip="10.0.0.2")]
    s = make_scan(hosts=hosts)
    assert [str(h.ip) for h in s.hosts] == ["10.0.0.3", "10.0.0.1", "10.0.0.2"]


def test_scan_result_stores_a_copy_of_the_hosts_list():
    hosts = [make_host()]
    s = make_scan(hosts=hosts)
    hosts.append(make_host(ip="10.0.0.2"))
    assert len(s.hosts) == 1


@pytest.mark.parametrize(
    "hosts",
    [
        None,
        "10.0.0.1",
        5,
        (make_host(),),
        [make_host(), "10.0.0.2"],
        [make_host(), None],
        [sample_host_dict()],
        [1],
    ],
)
def test_scan_result_rejects_invalid_hosts_argument(hosts):
    with pytest.raises(ValueError):
        make_scan(hosts=hosts)


def test_scan_result_rejects_duplicate_host_ips():
    with pytest.raises(ValueError):
        make_scan(hosts=[make_host(ip="10.0.0.1"), make_host(ip="10.0.0.1", vendor="Dell")])


def test_scan_result_rejects_duplicate_ips_given_in_different_forms():
    with pytest.raises(ValueError):
        make_scan(hosts=[make_host(ip="10.0.0.1"), make_host(ip=IPv4Address("10.0.0.1"))])


def test_scan_result_error_message_mentions_the_field():
    with pytest.raises(ValueError, match="(?i)target"):
        make_scan(target="")
    with pytest.raises(ValueError, match="(?i)status"):
        make_scan(status="done")
    with pytest.raises(ValueError, match="(?i)duration_s"):
        make_scan(duration_s=-1)


# --- ScanResult : égalité -------------------------------------------------


def test_scan_result_equality():
    assert make_scan() == make_scan()
    assert sample_scan() == sample_scan()


@pytest.mark.parametrize(
    "overrides",
    [
        {"target": "10.0.0.1"},
        {"scan_type": "syn"},
        {"ports": "22"},
        {"status": "running"},
        {"started_at": START},
        {"duration_s": 1.0},
        {"id": 3},
        {"hosts": [make_host()]},
    ],
)
def test_scan_result_inequality(overrides):
    assert make_scan() != make_scan(**overrides)


# --- ScanResult : compteurs ----------------------------------------------


def test_counters_on_empty_scan():
    s = make_scan()
    assert s.hosts_up == 0
    assert s.open_ports_count == 0


def test_hosts_up_counts_hosts():
    s = make_scan(hosts=[make_host(ip="10.0.0.1"), make_host(ip="10.0.0.2"), make_host(ip="10.0.0.3")])
    assert s.hosts_up == 3


def test_hosts_up_counts_hosts_without_ports():
    assert make_scan(hosts=[make_host()]).hosts_up == 1


def test_open_ports_count_counts_only_open_ports():
    h1 = make_host(
        ip="10.0.0.1",
        ports=[make_port(port=22), make_port(port=80), make_port(port=23, state="closed")],
    )
    h2 = make_host(
        ip="10.0.0.2",
        ports=[make_port(port=443), make_port(port=8080, state="filtered")],
    )
    s = make_scan(hosts=[h1, h2])
    assert s.hosts_up == 2
    assert s.open_ports_count == 3


def test_open_ports_count_counts_tcp_and_udp():
    h = make_host(ports=[make_port(port=53, protocol="tcp"), make_port(port=53, protocol="udp")])
    assert make_scan(hosts=[h]).open_ports_count == 2


def test_open_ports_count_zero_when_nothing_is_open():
    h = make_host(ports=[make_port(state="closed"), make_port(port=80, state="filtered")])
    assert make_scan(hosts=[h]).open_ports_count == 0


def test_counters_follow_add_host():
    s = make_scan()
    s.add_host(make_host(ip="10.0.0.1", ports=[make_port()]))
    assert (s.hosts_up, s.open_ports_count) == (1, 1)
    s.add_host(make_host(ip="10.0.0.2", ports=[make_port(), make_port(port=80)]))
    assert (s.hosts_up, s.open_ports_count) == (2, 3)


def test_open_ports_count_follows_ports_added_later():
    h = make_host()
    s = make_scan(hosts=[h])
    assert s.open_ports_count == 0
    s.hosts[0].ports.append(make_port())
    assert s.open_ports_count == 1


# --- ScanResult : add_host ------------------------------------------------


def test_add_host_appends_in_order():
    s = make_scan()
    s.add_host(make_host(ip="10.0.0.2"))
    s.add_host(make_host(ip="10.0.0.1"))
    assert [str(h.ip) for h in s.hosts] == ["10.0.0.2", "10.0.0.1"]


def test_add_host_stores_the_given_host():
    s = make_scan()
    h = make_host()
    s.add_host(h)
    assert s.hosts[0] is h


def test_add_host_rejects_duplicate_ip():
    s = make_scan(hosts=[make_host(ip="10.0.0.1")])
    with pytest.raises(ValueError):
        s.add_host(make_host(ip="10.0.0.1", vendor="Dell"))


def test_add_host_duplicate_leaves_the_list_unchanged():
    first = make_host(ip="10.0.0.1")
    s = make_scan(hosts=[first])
    with pytest.raises(ValueError):
        s.add_host(make_host(ip="10.0.0.1"))
    assert s.hosts == [first]


def test_add_host_detects_duplicates_across_ip_forms():
    s = make_scan()
    s.add_host(make_host(ip="10.0.0.1"))
    with pytest.raises(ValueError):
        s.add_host(make_host(ip=IPv4Address("10.0.0.1")))


@pytest.mark.parametrize("bad", [None, "10.0.0.1", 5, {"ip": "10.0.0.1"}, make_port(), IPv4Address("10.0.0.1")])
def test_add_host_rejects_non_host(bad):
    s = make_scan()
    with pytest.raises(ValueError):
        s.add_host(bad)
    assert s.hosts == []


# --- ScanResult : to_dict -------------------------------------------------


def test_scan_result_to_dict_matches_the_target_json():
    s = ScanResult(
        id=12,
        target="192.168.1.0/24",
        scan_type="syn",
        ports="1-1024",
        started_at=START,
        duration_s=41.7,
        status="completed",
        hosts=[
            Host(
                ip="192.168.1.10",
                mac="aa:bb:cc:dd:ee:ff",
                vendor="Raspberry Pi",
                rtt_ms=1.8,
                ports=[
                    PortResult(
                        port=22,
                        protocol="tcp",
                        state="open",
                        service="ssh",
                        version="OpenSSH 9.2",
                        banner="SSH-2.0-OpenSSH_9.2",
                    )
                ],
            )
        ],
    )
    assert s.to_dict() == sample_scan_dict()


def test_scan_result_to_dict_minimal():
    assert make_scan().to_dict() == {
        "scan": {
            "id": None,
            "target": "192.168.1.0/24",
            "type": None,
            "ports": None,
            "started_at": None,
            "duration_s": None,
            "status": "pending",
        },
        "hosts": [],
        "summary": {"hosts_up": 0, "open_ports": 0},
    }


def test_scan_result_to_dict_top_level_key_order():
    assert list(make_scan().to_dict()) == ["scan", "hosts", "summary"]


def test_scan_result_to_dict_scan_key_order():
    assert list(make_scan().to_dict()["scan"]) == [
        "id",
        "target",
        "type",
        "ports",
        "started_at",
        "duration_s",
        "status",
    ]


def test_scan_result_to_dict_summary_key_order():
    assert list(make_scan().to_dict()["summary"]) == ["hosts_up", "open_ports"]


def test_scan_result_to_dict_uses_type_for_scan_type():
    d = make_scan(scan_type="udp").to_dict()
    assert d["scan"]["type"] == "udp"
    assert "scan_type" not in d["scan"]


def test_scan_result_to_dict_started_at_is_iso_with_offset():
    assert make_scan(started_at=START).to_dict()["scan"]["started_at"] == "2026-10-03T11:20:00+02:00"
    utc = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
    assert make_scan(started_at=utc).to_dict()["scan"]["started_at"] == "2026-01-01T08:00:00+00:00"


def test_scan_result_to_dict_started_at_none():
    assert make_scan().to_dict()["scan"]["started_at"] is None


def test_scan_result_to_dict_summary_matches_counters():
    h1 = make_host(
        ip="10.0.0.1",
        ports=[make_port(port=22), make_port(port=80), make_port(port=23, state="closed")],
    )
    h2 = make_host(ip="10.0.0.2", ports=[make_port(port=443), make_port(port=8080, state="filtered")])
    d = make_scan(hosts=[h1, h2]).to_dict()
    assert d["summary"] == {"hosts_up": 2, "open_ports": 3}


def test_scan_result_to_dict_summary_follows_add_host():
    s = make_scan()
    assert s.to_dict()["summary"] == {"hosts_up": 0, "open_ports": 0}
    s.add_host(make_host(ports=[make_port()]))
    assert s.to_dict()["summary"] == {"hosts_up": 1, "open_ports": 1}


def test_scan_result_to_dict_hosts_are_host_dicts_in_order():
    s = make_scan(hosts=[make_host(ip="10.0.0.2"), make_host(ip="10.0.0.1")])
    assert [h["ip"] for h in s.to_dict()["hosts"]] == ["10.0.0.2", "10.0.0.1"]


def test_scan_result_to_dict_is_json_serializable():
    data = sample_scan().to_dict()
    assert json.loads(json.dumps(data)) == data


def test_scan_result_to_dict_does_not_share_state():
    s = sample_scan()
    d = s.to_dict()
    d["hosts"].clear()
    d["scan"]["target"] = "changed"
    d["summary"]["hosts_up"] = 99
    assert len(s.hosts) == 1
    assert s.target == "192.168.1.0/24"
    assert s.hosts_up == 1


def test_scan_result_to_dict_nested_dicts_are_copies():
    s = sample_scan()
    s.to_dict()["hosts"][0]["ports"][0]["port"] = 9999
    assert s.hosts[0].ports[0].port == 22


# --- ScanResult : from_dict -----------------------------------------------


def test_scan_result_from_dict_full():
    s = ScanResult.from_dict(sample_scan_dict())
    assert s.id == 12
    assert s.target == "192.168.1.0/24"
    assert s.scan_type == "syn"
    assert s.ports == "1-1024"
    assert s.started_at == START
    assert s.duration_s == 41.7
    assert s.status == "completed"
    assert s.hosts == [Host.from_dict(sample_host_dict())]
    assert s.hosts_up == 1
    assert s.open_ports_count == 1


def test_scan_result_from_dict_started_at_keeps_its_timezone():
    s = ScanResult.from_dict(sample_scan_dict())
    assert s.started_at.utcoffset() == timedelta(hours=2)


def test_scan_result_from_dict_minimal():
    s = ScanResult.from_dict({"scan": {"target": "10.0.0.1"}})
    assert s == ScanResult(target="10.0.0.1")
    assert s.status == "pending"
    assert s.hosts == []


@pytest.mark.parametrize("hosts", [None, []])
def test_scan_result_from_dict_hosts_none_or_empty(hosts):
    data = {"scan": {"target": "10.0.0.1"}, "hosts": hosts}
    assert ScanResult.from_dict(data).hosts == []


def test_scan_result_roundtrip():
    original = make_scan(
        id=3,
        scan_type="connect",
        ports="22,80",
        status="completed",
        started_at=START,
        duration_s=2.5,
        hosts=[
            make_host(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:ff", ports=[make_port(), make_port(port=80, state="closed")]),
            make_host(ip="10.0.0.2", rtt_ms=0.4),
        ],
    )
    assert ScanResult.from_dict(original.to_dict()) == original


def test_scan_result_roundtrip_through_json():
    original = sample_scan()
    restored = ScanResult.from_dict(json.loads(json.dumps(original.to_dict())))
    assert restored == original


def test_scan_result_roundtrip_of_a_minimal_scan():
    original = make_scan()
    assert ScanResult.from_dict(original.to_dict()) == original


def test_scan_result_from_dict_ignores_summary():
    data = sample_scan_dict()
    data["summary"] = {"hosts_up": 99, "open_ports": 99}
    s = ScanResult.from_dict(data)
    assert s.hosts_up == 1
    assert s.open_ports_count == 1


def test_scan_result_from_dict_works_without_summary():
    data = sample_scan_dict()
    del data["summary"]
    assert ScanResult.from_dict(data) == sample_scan()


def test_scan_result_from_dict_ignores_unknown_keys():
    data = sample_scan_dict()
    data["extra"] = 1
    data["scan"]["extra"] = 2
    assert ScanResult.from_dict(data) == sample_scan()


@pytest.mark.parametrize("data", [None, [], "scan", 5, ({"target": "x"},)])
def test_scan_result_from_dict_rejects_non_dict(data):
    with pytest.raises(ValueError):
        ScanResult.from_dict(data)


@pytest.mark.parametrize("scan_section", [None, "x", 5, [], ["target"]])
def test_scan_result_from_dict_rejects_invalid_scan_section(scan_section):
    with pytest.raises(ValueError):
        ScanResult.from_dict({"scan": scan_section})


def test_scan_result_from_dict_requires_scan_section():
    with pytest.raises(ValueError):
        ScanResult.from_dict({"hosts": []})


def test_scan_result_from_dict_requires_target():
    data = sample_scan_dict()
    del data["scan"]["target"]
    with pytest.raises(ValueError):
        ScanResult.from_dict(data)


@pytest.mark.parametrize("hosts", ["x", 5, {}, {"ip": "10.0.0.1"}, (sample_host_dict(),), True])
def test_scan_result_from_dict_rejects_non_list_hosts(hosts):
    with pytest.raises(ValueError):
        ScanResult.from_dict({"scan": {"target": "10.0.0.1"}, "hosts": hosts})


@pytest.mark.parametrize("bad_host", [None, "10.0.0.1", 5, {}, {"ip": "abc"}, {"mac": "aa:bb:cc:dd:ee:ff"}])
def test_scan_result_from_dict_rejects_invalid_host_entries(bad_host):
    data = sample_scan_dict()
    data["hosts"].append(bad_host)
    with pytest.raises(ValueError):
        ScanResult.from_dict(data)


def test_scan_result_from_dict_rejects_duplicate_host_ips():
    data = sample_scan_dict()
    data["hosts"].append(copy.deepcopy(data["hosts"][0]))
    with pytest.raises(ValueError):
        ScanResult.from_dict(data)


@pytest.mark.parametrize(
    "started_at",
    [
        "hier",
        "",
        "2026-13-45T99:99:99+02:00",
        "2026-10-03T11:20:00",  # ISO valide mais sans fuseau
        "2026-10-03",  # date seule : sans fuseau
        12345,
        1.5,
        True,
        [],
    ],
)
def test_scan_result_from_dict_rejects_invalid_started_at(started_at):
    data = sample_scan_dict()
    data["scan"]["started_at"] = started_at
    with pytest.raises(ValueError):
        ScanResult.from_dict(data)


@pytest.mark.parametrize(
    "overrides",
    [
        {"target": ""},
        {"target": 5},
        {"type": "discover"},
        {"type": 5},
        {"ports": 22},
        {"status": "done"},
        {"status": None},
        {"duration_s": -1},
        {"duration_s": "41.7"},
        {"id": 0},
        {"id": "12"},
    ],
)
def test_scan_result_from_dict_validates_values(overrides):
    data = sample_scan_dict()
    data["scan"].update(overrides)
    with pytest.raises(ValueError):
        ScanResult.from_dict(data)


@pytest.mark.parametrize("missing", ["id", "type", "ports", "started_at", "duration_s"])
def test_scan_result_from_dict_optional_scan_keys_default_to_none(missing):
    data = sample_scan_dict()
    del data["scan"][missing]
    s = ScanResult.from_dict(data)
    attribute = "scan_type" if missing == "type" else missing
    assert getattr(s, attribute) is None


def test_scan_result_from_dict_missing_status_defaults_to_pending():
    data = sample_scan_dict()
    del data["scan"]["status"]
    assert ScanResult.from_dict(data).status == "pending"


def test_scan_result_from_dict_does_not_mutate_input():
    data = sample_scan_dict()
    snapshot = copy.deepcopy(data)
    ScanResult.from_dict(data)
    assert data == snapshot


def test_scan_result_from_dict_does_not_share_hosts_with_input():
    data = sample_scan_dict()
    s = ScanResult.from_dict(data)
    data["hosts"].clear()
    assert len(s.hosts) == 1


# --- Scénario de bout en bout ---------------------------------------------


def test_build_a_scan_incrementally_then_export_it():
    scan = ScanResult(target="192.168.1.0/30", scan_type="connect", ports="22,80", started_at=START)
    scan.status = "running"

    gateway = Host(ip="192.168.1.1", mac="AA-BB-CC-DD-EE-01", rtt_ms=1)
    gateway.ports.append(PortResult(port=80, protocol="TCP", state="OPEN", service="http"))
    gateway.ports.append(PortResult(port=22, protocol="tcp", state="closed"))
    scan.add_host(gateway)

    laptop = Host(ip="192.168.1.2", vendor="Dell")
    scan.add_host(laptop)

    scan.status = "completed"
    scan.duration_s = 2

    data = scan.to_dict()
    assert data["scan"]["status"] == "completed"
    assert data["scan"]["type"] == "connect"
    assert data["summary"] == {"hosts_up": 2, "open_ports": 1}
    assert data["hosts"][0]["mac"] == "aa:bb:cc:dd:ee:01"
    assert data["hosts"][0]["ports"][0]["protocol"] == "tcp"
    assert json.loads(json.dumps(data)) == data
    assert ScanResult.from_dict(data) == scan