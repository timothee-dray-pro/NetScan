"""Tests de core/targets.py : parsing des cibles (CIDR, IP unique, listes, exclusions)."""

from ipaddress import IPv4Address

import pytest

from netscan.core.errors import InvalidTargetError
from netscan.core.targets import _split_items, parse_targets


def ips(*args, **kwargs):
    """Appelle parse_targets et renvoie les adresses sous forme de chaînes."""
    return [str(ip) for ip in parse_targets(*args, **kwargs)]


# --- Cibles simples -------------------------------------------------------


def test_cidr_30_excludes_network_and_broadcast():
    assert ips("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]


def test_cidr_24_has_254_hosts():
    result = ips("192.168.1.0/24")
    assert len(result) == 254
    assert result[0] == "192.168.1.1"
    assert result[-1] == "192.168.1.254"
    assert "192.168.1.0" not in result
    assert "192.168.1.255" not in result


def test_single_ip():
    assert ips("10.0.0.5") == ["10.0.0.5"]


def test_cidr_32_is_single_host():
    assert ips("10.0.0.5/32") == ["10.0.0.5"]


def test_cidr_31_keeps_both_addresses():
    assert ips("10.0.0.4/31") == ["10.0.0.4", "10.0.0.5"]


def test_single_ip_that_looks_like_network_is_kept():
    assert ips("10.0.0.0") == ["10.0.0.0"]
    assert ips("10.0.0.255") == ["10.0.0.255"]


def test_cidr_with_host_bits_is_normalized():
    assert ips("192.168.1.5/24") == ips("192.168.1.0/24")


# --- Listes, espaces, doublons, ordre -------------------------------------


def test_mixed_list():
    assert ips("10.0.0.1,10.0.0.7,192.168.1.0/30") == [
        "10.0.0.1",
        "10.0.0.7",
        "192.168.1.1",
        "192.168.1.2",
    ]


def test_spaces_around_items_are_ignored():
    assert ips("10.0.0.1, 10.0.0.2 ,  10.0.0.3") == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    ]


def test_duplicates_are_removed():
    assert ips("10.0.0.1,10.0.0.1") == ["10.0.0.1"]


def test_overlapping_targets_are_deduplicated():
    assert ips("192.168.1.0/30,192.168.1.1") == ["192.168.1.1", "192.168.1.2"]


def test_result_is_in_numeric_order_not_alphabetical():
    assert ips("10.0.0.10,10.0.0.2") == ["10.0.0.2", "10.0.0.10"]


def test_result_is_sorted_across_items():
    # L'ordre ne dépend pas de l'ordre de saisie.
    assert ips("192.168.1.1,10.0.0.1") == ["10.0.0.1", "192.168.1.1"]


# --- Format du résultat ---------------------------------------------------


def test_returns_sorted_list_of_ipv4_addresses():
    result = parse_targets("10.0.0.10,10.0.0.2,192.168.1.1")
    assert isinstance(result, list)
    assert all(isinstance(ip, IPv4Address) for ip in result)
    assert result == sorted(result)


# --- Exclusions -----------------------------------------------------------


def test_exclude_single_ip():
    assert ips("192.168.1.0/30", exclude="192.168.1.1") == ["192.168.1.2"]


def test_exclude_cidr_follows_same_rules_as_targets():
    # Le /30 exclu couvre .1 et .2 (sans réseau ni broadcast), donc .3 reste.
    assert ips("192.168.1.0/29", exclude="192.168.1.0/30") == [
        "192.168.1.3",
        "192.168.1.4",
        "192.168.1.5",
        "192.168.1.6",
    ]


def test_exclude_list():
    assert ips("10.0.0.1,10.0.0.2,10.0.0.3", exclude="10.0.0.1,10.0.0.3") == [
        "10.0.0.2"
    ]


def test_exclude_list_with_spaces():
    assert ips("10.0.0.1,10.0.0.2,10.0.0.3", exclude="10.0.0.1, 10.0.0.3") == [
        "10.0.0.2"
    ]


def test_exclude_that_matches_nothing_is_not_an_error():
    assert ips("10.0.0.1,10.0.0.2", exclude="172.16.0.1") == [
        "10.0.0.1",
        "10.0.0.2",
    ]


def test_exclude_none_removes_nothing():
    assert ips("10.0.0.1", exclude=None) == ["10.0.0.1"]


@pytest.mark.parametrize("exclude", ["", "   "])
def test_exclude_empty_string_removes_nothing(exclude):
    assert ips("10.0.0.1", exclude=exclude) == ["10.0.0.1"]


def test_exclude_everything_gives_empty_list():
    assert ips("10.0.0.1", exclude="10.0.0.1") == []


# --- Plafond MAX_HOSTS ----------------------------------------------------


def test_cidr_16_is_accepted_at_the_limit():
    assert len(ips("10.0.0.0/16")) == 65_534


def test_total_over_the_limit_raises():
    # Chaque /16 est accepté seul, mais leur réunion dépasse le plafond.
    with pytest.raises(InvalidTargetError):
        parse_targets("10.0.0.0/16,10.1.0.0/16")


def test_limit_is_checked_after_exclusions():
    assert len(ips("10.0.0.0/16,10.1.0.0/16", exclude="10.1.0.0/16")) == 65_534


# --- Entrées invalides ----------------------------------------------------


@pytest.mark.parametrize(
    "spec",
    [
        "",  # chaîne vide
        "   ",  # espaces seulement
        ",",  # virgule seule
        "10.0.0.1,,10.0.0.2",  # élément vide dans la liste
        ",10.0.0.1",  # virgule initiale
        "10.0.0.1,",  # virgule finale
        "abc",  # pas une adresse
        "300.1.1.1",  # octet hors limites
        "10.0.0",  # adresse incomplète
        "1.2.3.4.5",  # trop d'octets
        "10.0.0.0/33",  # masque impossible
        "10.0.0.0/24/8",  # deux masques
        "::1",  # IPv6 refusé
        "2001:db8::/32",  # IPv6 refusé
        "10.0.0.0/15",  # plus de 65 536 adresses
        "10.0.0.0/8",  # plus de 65 536 adresses
    ],
)
def test_invalid_targets_raise(spec):
    with pytest.raises(InvalidTargetError):
        parse_targets(spec)


def test_spaces_inside_an_address_are_rejected():
    # Seuls les espaces autour d'un élément sont ignorés, pas ceux à l'intérieur.
    with pytest.raises(InvalidTargetError):
        parse_targets("10.0.0 .1")


@pytest.mark.parametrize("exclude", ["abc", "::1", "10.0.0.1,"])
def test_invalid_exclude_raises(exclude):
    with pytest.raises(InvalidTargetError):
        parse_targets("10.0.0.1", exclude=exclude)


@pytest.mark.parametrize("spec", ["300.1.1.1", "abc", "10.0.0.0/33", "10.0.0.0/8"])
def test_error_message_mentions_faulty_item(spec):
    with pytest.raises(InvalidTargetError, match=spec.replace(".", r"\.")):
        parse_targets(spec)


@pytest.mark.parametrize("spec", ["::1", "2001:db8::/32"])
def test_ipv6_error_message_is_explicit(spec):
    with pytest.raises(InvalidTargetError, match="IPv6"):
        parse_targets(spec)


# --- _split_items (fonction interne) --------------------------------------


def test_split_items_strips_spaces_around_items():
    assert _split_items("10.0.0.1, 10.0.0.2 ,192.168.1.0/30") == [
        "10.0.0.1",
        "10.0.0.2",
        "192.168.1.0/30",
    ]


def test_split_items_single_item():
    assert _split_items("10.0.0.1") == ["10.0.0.1"]


@pytest.mark.parametrize(
    "spec",
    ["", "   ", ",", ",10.0.0.1", "10.0.0.1,", "10.0.0.1,,10.0.0.2"],
)
def test_split_items_rejects_empty_items(spec):
    with pytest.raises(InvalidTargetError):
        _split_items(spec)