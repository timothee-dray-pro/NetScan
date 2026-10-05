"""
Parsing des cibles de scan : CIDR, IP unique, listes et exclusions.

Ce module ne fait aucun accès réseau. Il transforme une chaîne saisie par
l'utilisateur en une liste d'adresses IPv4 ordonnée et sans doublon.
"""

from ipaddress import IPv4Address, IPv4Network

from netscan.core.errors import InvalidTargetError

# Nombre maximum d'hôtes retournés (protège d'un scan trop large par erreur).
MAX_HOSTS = 65_536


def _split_items(spec: str) -> list[str]:
    items = [part.strip() for part in spec.split(",")]
    if any(item == "" for item in items):
        raise InvalidTargetError("Élément vide dans la liste de cibles (virgule en trop ?)")
    return items

def _expand_item(item: str) -> list[IPv4Address]:
    """
    Transforme un élément (CIDR ou IP unique) en liste d'adresses.
 
    À faire :
    - refuser l'IPv6 (message explicite) ;
    - IP unique : renvoyer cette adresse telle quelle, sans la filtrer ;
    - CIDR : normaliser les bits hôte (192.168.1.5/24 -> 192.168.1.0/24) ;
    - /32 : l'hôte unique ; /31 : les deux adresses ; sinon, hôtes utilisables
      sans adresse réseau ni broadcast ;
    - convertir toute ValueError d'ipaddress en InvalidTargetError dont le
      message cite l'élément fautif.
    """
    # IPv6 refusé : ARP n'existe pas en IPv6 et le projet cible l'IPv4.
    if ":" in item:
        raise InvalidTargetError(f"IPv6 non supporté : '{item}'")
 
    # IP unique : renvoyée telle quelle, même si elle ressemble à une adresse
    # réseau ou broadcast (10.0.0.0, 10.0.0.255).
    if "/" not in item:
        try:
            return [IPv4Address(item)]
        except ValueError:
            raise InvalidTargetError(f"Cible invalide : '{item}'") from None
 
    # CIDR : strict=False accepte les bits hôte et les normalise
    # (192.168.1.5/24 -> 192.168.1.0/24).
    try:
        network = IPv4Network(item, strict=False)
    except ValueError:
        raise InvalidTargetError(f"Cible invalide : '{item}'") from None
 
    # Plafond contrôlé AVANT d'énumérer : un /8 ne construit jamais 16 millions
    # d'adresses, on lit juste la taille du réseau.
    if network.num_addresses > MAX_HOSTS:
        raise InvalidTargetError(
            f"Plage trop grande : '{item}' ({network.num_addresses} adresses, "
            f"maximum {MAX_HOSTS})"
        )
 
    # /32 (1 hôte) et /31 (2 hôtes) : pas d'adresse réseau ni de broadcast.
    if network.prefixlen >= 31:
        return list(network)
 
    # Cas général : hôtes utilisables, sans adresse réseau ni broadcast.
    return list(network.hosts())


def _expand_spec(spec: str) -> set[IPv4Address]:
    """Développe une chaîne complète (liste d'éléments) en ensemble d'adresses.

    À faire :
    - appeler _split_items puis _expand_item sur chaque élément ;
    - fusionner les résultats dans un ensemble (supprime les doublons).
    """
    addresses: set[IPv4Address] = set()
    for item in _split_items(spec):
        addresses.update(_expand_item(item))
    return addresses


def parse_targets(spec: str, exclude: str | None = None) -> list[IPv4Address]:
    """Renvoie les adresses à scanner, triées dans l'ordre numérique.

    Args:
        spec: cible(s) : CIDR, IP unique, ou liste séparée par des virgules.
        exclude: cible(s) à retirer, même syntaxe que spec (None = aucune).

    Raises:
        InvalidTargetError: entrée invalide, IPv6, ou plus de MAX_HOSTS hôtes.

    À faire :
    - développer spec avec _expand_spec ;
    - si exclude est fourni, développer aussi et retirer ces adresses ;
    - lever InvalidTargetError si le résultat dépasse MAX_HOSTS ;
    - renvoyer une liste triée.

    Attention : le plafond doit être contrôlé sans construire d'abord 16
    millions d'adresses pour un /8 (calculer la taille du réseau avant de
    l'énumérer).
    """
    addresses = _expand_spec(spec)
 
    # Exclusions : même syntaxe et mêmes règles que les cibles.
    # None ou chaîne vide = rien à retirer.
    if exclude and exclude.strip():
        addresses -= _expand_spec(exclude)
 
    # Plafond sur le total : plusieurs plages valides (ex. des /17) peuvent
    # dépasser MAX_HOSTS une fois réunies.
    if len(addresses) > MAX_HOSTS:
        raise InvalidTargetError(
            f"Trop d'hôtes ciblés : {len(addresses)} (maximum {MAX_HOSTS})"
        )
 
    return sorted(addresses)