"""Modèles de données de NetScan : PortResult, Host et ScanResult.

Ce module est le pivot du projet : scanners, formatters, base SQLite et API
manipulent tous ces objets. Il ne fait aucun accès réseau ni aucune
entrée/sortie.

Règle commune de validation : toute valeur invalide, quel que soit son type,
lève ValueError (jamais TypeError ni AttributeError). Le message doit citer le
champ fautif.

Le format de to_dict() suit le JSON cible du projet :

    {
      "scan": {"id", "target", "type", "ports", "started_at", "duration_s",
               "status"},
      "hosts": [{"ip", "mac", "vendor", "rtt_ms", "os_guess",
                 "ports": [{"port", "protocol", "state", "service",
                            "version", "banner"}]}],
      "summary": {"hosts_up", "open_ports"}
    }
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address
from typing import Any

VALID_PROTOCOLS = ("tcp", "udp")
VALID_PORT_STATES = ("open", "closed", "filtered")
VALID_SCAN_TYPES = ("connect", "syn", "udp")
VALID_SCAN_STATUSES = ("pending", "running", "completed", "failed")


def normalize_mac(mac: str) -> str:
    """Normalise une adresse MAC au format "aa:bb:cc:dd:ee:ff" (minuscules).

    Sera réutilisée par discovery/vendor.py (étape 5).

    À faire :
    - lever ValueError si mac n'est pas une chaîne ;
    - ignorer les espaces au début et à la fin ;
    - accepter 4 formes, en majuscules ou minuscules :
        aa:bb:cc:dd:ee:ff   aa-bb-cc-dd-ee-ff   aabb.ccdd.eeff   aabbccddeeff
    - refuser les séparateurs mélangés (aa:bb-cc:dd-ee:ff), les groupes
      mal formés (aa.bb.cc.dd.ee.ff), les caractères non hexadécimaux, et tout
      ce qui n'a pas exactement 12 chiffres hexadécimaux (ValueError) ;
    - renvoyer toujours la forme "aa:bb:cc:dd:ee:ff".
    """
    if not isinstance(mac, str):
        raise ValueError(f"Adresse MAC invalide (chaîne attendue) : {mac!r}")

    cleaned = mac.strip().lower()

    # Les 3 formes acceptées. fullmatch impose que TOUTE la chaîne corresponde.
    formats = (
        # aa:bb:cc:dd:ee:ff ou aa-bb-cc-dd-ee-ff : \1 force le même séparateur
        # partout (refuse aa:bb-cc:dd-ee:ff).
        r"[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}",
        # aabb.ccdd.eeff (format Cisco) : 3 groupes de 4.
        r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}",
        # aabbccddeeff : 12 chiffres collés.
        r"[0-9a-f]{12}",
    )
    if not any(re.fullmatch(pattern, cleaned) for pattern in formats):
        raise ValueError(f"Adresse MAC invalide : {mac!r}")

    # Il reste exactement 12 chiffres hexadécimaux une fois les séparateurs
    # retirés : on les regroupe par 2.
    digits = re.sub(r"[^0-9a-f]", "", cleaned)
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def _normalize_choice(name: str, value: Any, choices: tuple[str, ...]) -> str:
    """Nettoie une chaîne (espaces, minuscules) et vérifie qu'elle est dans choices.

    Partagée par PortResult et ScanResult. `name` sert à citer le champ fautif
    dans le message d'erreur.
    """
    if not isinstance(value, str):
        raise ValueError(f"{name} invalide (chaîne attendue) : {value!r}")
    cleaned = value.strip().lower()
    if cleaned not in choices:
        raise ValueError(
            f"{name} invalide : {value!r} (valeurs possibles : {', '.join(choices)})"
        )
    return cleaned


def _check_optional_str(name: str, value: Any) -> None:
    """Lève ValueError si value n'est ni None ni une chaîne.

    Partagée par PortResult, Host et ScanResult.
    """
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{name} invalide (chaîne ou None attendu) : {value!r}")


def _normalize_optional_number(name: str, value: Any) -> float | None:
    """Renvoie None, ou la valeur convertie en float si c'est un nombre fini >= 0.

    Partagée par Host (rtt_ms) et ScanResult (duration_s).
    """
    if value is None:
        return None
    # bool est une sous-classe de int (True == 1) : à écarter explicitement.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} invalide (nombre attendu) : {value!r}")
    # NaN et l'infini ne sont pas des durées valides ; un temps ne peut pas
    # être négatif.
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} invalide (nombre fini >= 0 attendu) : {value!r}")
    return float(value)


@dataclass
class PortResult:
    """Résultat du scan d'un port sur un hôte.

    Champs obligatoires : port, protocol, state.
    Champs optionnels (None par défaut) : service, version, banner.
    """

    port: int
    protocol: str
    state: str
    service: str | None = None
    version: str | None = None
    banner: str | None = None

    def __post_init__(self) -> None:
        """Valide et normalise les champs (ValueError si invalide).

        À faire :
        - port : un int entre 1 et 65535 inclus ; refuser bool, float ("22",
          22.0, None, True...) ;
        - protocol : chaîne, nettoyée (espaces) et mise en minuscules, qui doit
          appartenir à VALID_PROTOCOLS ;
        - state : même traitement, avec VALID_PORT_STATES ;
        - service, version, banner : None ou chaîne (éventuellement vide),
          conservées telles quelles (pas de strip : une bannière peut finir
          par "\\r\\n").
        """
        # bool est une sous-classe de int en Python (True == 1) : il faut
        # l'écarter explicitement. Un float (22.0) ou une chaîne ("22") sont
        # refusés par le test isinstance(..., int).
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65535
        ):
            raise ValueError(
                f"port invalide (entier entre 1 et 65535 attendu) : {self.port!r}"
            )

        self.protocol = _normalize_choice("protocol", self.protocol, VALID_PROTOCOLS)
        self.state = _normalize_choice("state", self.state, VALID_PORT_STATES)

        # Pas de strip ici : une bannière peut légitimement finir par "\r\n".
        _check_optional_str("service", self.service)
        _check_optional_str("version", self.version)
        _check_optional_str("banner", self.banner)

    def to_dict(self) -> dict[str, Any]:
        """Renvoie un dict prêt pour json.dumps.

        À faire :
        - clés dans cet ordre : port, protocol, state, service, version,
          banner ;
        - les valeurs None sont conservées (clé présente, valeur None) ;
        - renvoyer un nouveau dict à chaque appel.
        """
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PortResult:
        """Reconstruit un PortResult depuis un dict (inverse de to_dict).

        À faire :
        - ValueError si data n'est pas un dict ;
        - ValueError si port, protocol ou state est absent ;
        - service, version, banner absents : None ;
        - ignorer les clés inconnues ;
        - ne pas modifier data ;
        - les valeurs invalides lèvent ValueError (via __post_init__).
        """
        if not isinstance(data, dict):
            raise ValueError(f"PortResult : un dict est attendu, reçu {data!r}")

        for key in ("port", "protocol", "state"):
            if key not in data:
                raise ValueError(f"PortResult : clé obligatoire '{key}' absente")

        # data.get(...) renvoie None quand la clé est absente, et on ne lit que
        # les clés connues : les clés inconnues sont ignorées, data n'est pas modifié.
        return cls(
            port=data["port"],
            protocol=data["protocol"],
            state=data["state"],
            service=data.get("service"),
            version=data.get("version"),
            banner=data.get("banner"),
        )


@dataclass
class Host:
    """Un hôte découvert, avec ses ports scannés.

    Champ obligatoire : ip. Tous les autres sont optionnels.
    """

    ip: IPv4Address
    mac: str | None = None
    vendor: str | None = None
    rtt_ms: float | None = None
    os_guess: str | None = None
    ports: list[PortResult] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Valide et normalise les champs (ValueError si invalide).

        À faire :
        - ip : accepter une IPv4Address ou une chaîne (espaces autour ignorés)
          et stocker une IPv4Address ; refuser tout le reste (IPv6, chaîne
          invalide, int, None, liste...) ;
        - mac : None ou chaîne normalisée avec normalize_mac ;
        - vendor, os_guess : None ou chaîne ;
        - rtt_ms : None ou nombre (int ou float) fini et >= 0 ; stocker un
          float ; refuser bool, NaN, infini, négatif, chaîne ;
        - ports : doit être une list dont tous les éléments sont des
          PortResult ; en stocker une COPIE (modifier la liste d'origine ne
          doit pas modifier l'hôte) ; refuser tuple, None, éléments d'un autre
          type.
        """
        # ip : une chaîne est convertie, une IPv4Address est gardée telle quelle.
        # Tout le reste (IPv6Address, int, None, liste...) est refusé.
        if isinstance(self.ip, str):
            try:
                self.ip = IPv4Address(self.ip.strip())
            except ValueError:
                raise ValueError(f"ip invalide : {self.ip!r}") from None
        elif not isinstance(self.ip, IPv4Address):
            raise ValueError(f"ip invalide (adresse IPv4 attendue) : {self.ip!r}")

        # normalize_mac vérifie le type et le format, et lève ValueError.
        if self.mac is not None:
            self.mac = normalize_mac(self.mac)

        _check_optional_str("vendor", self.vendor)
        _check_optional_str("os_guess", self.os_guess)
        self.rtt_ms = _normalize_optional_number("rtt_ms", self.rtt_ms)

        # list(...) crée une COPIE : modifier la liste d'origine après coup ne
        # change pas l'hôte. Un tuple est refusé volontairement.
        if not isinstance(self.ports, list) or not all(
            isinstance(p, PortResult) for p in self.ports
        ):
            raise ValueError(
                f"ports invalide (liste de PortResult attendue) : {self.ports!r}"
            )
        self.ports = list(self.ports)

    @property
    def open_ports(self) -> list[PortResult]:
        """Les ports dont l'état est "open", dans l'ordre d'origine.

        À faire :
        - renvoyer une nouvelle liste (la modifier ne change pas l'hôte) ;
        - inclure TCP et UDP ; liste vide s'il n'y en a aucun.
        """
        # Une liste en compréhension crée toujours une nouvelle liste, recalculée
        # à chaque lecture.
        return [p for p in self.ports if p.state == "open"]

    def to_dict(self) -> dict[str, Any]:
        """Renvoie un dict prêt pour json.dumps.

        À faire :
        - clés dans cet ordre : ip, mac, vendor, rtt_ms, os_guess, ports ;
        - ip sous forme de chaîne ; ports sous forme de liste de dicts
          (PortResult.to_dict) ;
        - les valeurs None sont conservées ;
        - rien ne doit être partagé avec l'objet : modifier le dict renvoyé ne
          change pas l'hôte.
        """
        # str(self.ip) : une IPv4Address n'est pas sérialisable en JSON.
        # La compréhension de liste crée une nouvelle liste, et chaque
        # PortResult.to_dict() un nouveau dict : rien n'est partagé.
        return {
            "ip": str(self.ip),
            "mac": self.mac,
            "vendor": self.vendor,
            "rtt_ms": self.rtt_ms,
            "os_guess": self.os_guess,
            "ports": [p.to_dict() for p in self.ports],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Host:
        """Reconstruit un Host depuis un dict (inverse de to_dict).

        À faire :
        - ValueError si data n'est pas un dict ou si "ip" est absent ;
        - mac, vendor, rtt_ms, os_guess absents : None ;
        - "ports" absent ou None : liste vide ; si présent mais pas une liste :
          ValueError ; sinon construire chaque élément avec PortResult.from_dict ;
        - ignorer les clés inconnues ; ne pas modifier data.
        """
        if not isinstance(data, dict):
            raise ValueError(f"Host : un dict est attendu, reçu {data!r}")
        if "ip" not in data:
            raise ValueError("Host : clé obligatoire 'ip' absente")

        raw_ports = data.get("ports")
        if raw_ports is None:
            ports = []
        elif isinstance(raw_ports, list):
            ports = [PortResult.from_dict(p) for p in raw_ports]
        else:
            raise ValueError(f"Host : 'ports' doit être une liste, reçu {raw_ports!r}")

        return cls(
            ip=data["ip"],
            mac=data.get("mac"),
            vendor=data.get("vendor"),
            rtt_ms=data.get("rtt_ms"),
            os_guess=data.get("os_guess"),
            ports=ports,
        )


@dataclass
class ScanResult:
    """Résultat d'un scan : paramètres, hôtes trouvés, statut.

    Champ obligatoire : target. Début de modèle : il sera complété aux
    sprints suivants (sorties, persistance SQLite).
    """

    target: str
    scan_type: str | None = None
    ports: str | None = None
    status: str = "pending"
    started_at: datetime | None = None
    duration_s: float | None = None
    id: int | None = None
    hosts: list[Host] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Valide et normalise les champs (ValueError si invalide).

        À faire :
        - target : chaîne non vide après nettoyage des espaces (stocker la
          version nettoyée) ;
        - scan_type : None, ou chaîne en minuscules appartenant à
          VALID_SCAN_TYPES (None = pas de scan de ports, ex. discover) ;
        - ports : None ou chaîne (la plage telle que saisie, ex. "1-1024") ;
        - status : chaîne nettoyée, en minuscules, dans VALID_SCAN_STATUSES ;
        - started_at : None ou datetime AVEC fuseau horaire ; refuser un
          datetime naïf, une chaîne, un int, un date ;
        - duration_s : None ou nombre fini >= 0 (stocker un float) ; refuser
          bool, NaN, infini, négatif, chaîne ;
        - id : None ou int >= 1 ; refuser bool, float, chaîne, 0, négatif ;
        - hosts : list de Host, sans doublon d'adresse IP ; en stocker une
          COPIE ; refuser tuple, None, éléments d'un autre type.
        """
        # target : chaîne non vide une fois les espaces retirés.
        if not isinstance(self.target, str) or not self.target.strip():
            raise ValueError(
                f"target invalide (chaîne non vide attendue) : {self.target!r}"
            )
        self.target = self.target.strip()

        if self.scan_type is not None:
            self.scan_type = _normalize_choice(
                "scan_type", self.scan_type, VALID_SCAN_TYPES
            )

        _check_optional_str("ports", self.ports)
        self.status = _normalize_choice("status", self.status, VALID_SCAN_STATUSES)

        # started_at : un datetime AVEC fuseau. isinstance écarte les chaînes,
        # les int et les date ; utcoffset() vaut None pour un datetime naïf.
        if self.started_at is not None and (
            not isinstance(self.started_at, datetime)
            or self.started_at.utcoffset() is None
        ):
            raise ValueError(
                "started_at invalide (datetime avec fuseau horaire attendu) : "
                f"{self.started_at!r}"
            )

        self.duration_s = _normalize_optional_number("duration_s", self.duration_s)

        # id : entier >= 1 (bool écarté : True == 1 en Python).
        if self.id is not None and (
            isinstance(self.id, bool) or not isinstance(self.id, int) or self.id < 1
        ):
            raise ValueError(f"id invalide (entier >= 1 attendu) : {self.id!r}")

        # hosts : liste de Host, sans IP en double, stockée en COPIE.
        if not isinstance(self.hosts, list) or not all(
            isinstance(h, Host) for h in self.hosts
        ):
            raise ValueError(
                f"hosts invalide (liste de Host attendue) : {self.hosts!r}"
            )
        seen: set[IPv4Address] = set()
        for h in self.hosts:
            if h.ip in seen:
                raise ValueError(f"hosts invalide : adresse {h.ip} en double")
            seen.add(h.ip)
        self.hosts = list(self.hosts)

    @property
    def hosts_up(self) -> int:
        """Nombre d'hôtes actifs (= nombre de Host du scan)."""
        return len(self.hosts)

    @property
    def open_ports_count(self) -> int:
        """Nombre total de ports ouverts, tous hôtes confondus.

        À faire : ne compter que l'état "open" ; la valeur doit suivre les
        modifications (add_host, ports ajoutés), donc pas de cache.
        """
        # Recalculé à chaque lecture : Host.open_ports ne garde que l'état "open".
        return sum(len(h.open_ports) for h in self.hosts)

    def add_host(self, host: Host) -> None:
        """Ajoute un hôte au scan.

        À faire :
        - ValueError si host n'est pas un Host ;
        - ValueError si un hôte de même adresse IP est déjà présent (la liste
          reste alors inchangée) ;
        - sinon, ajouter à la fin (l'ordre d'insertion est conservé).
        """
        if not isinstance(host, Host):
            raise ValueError(f"host invalide (Host attendu) : {host!r}")
        # Les deux contrôles ont lieu AVANT l'ajout : en cas d'erreur, la liste
        # reste inchangée.
        if any(existing.ip == host.ip for existing in self.hosts):
            raise ValueError(f"host invalide : l'adresse {host.ip} est déjà dans le scan")
        self.hosts.append(host)

    def to_dict(self) -> dict[str, Any]:
        """Renvoie le dict au format JSON cible (voir en haut du fichier).

        À faire :
        - trois clés dans cet ordre : "scan", "hosts", "summary" ;
        - "scan" : id, target, type (= scan_type), ports, started_at,
          duration_s, status, dans cet ordre ; started_at au format
          datetime.isoformat() (ex. "2026-10-03T11:20:00+02:00") ou None ;
        - "hosts" : liste de Host.to_dict ;
        - "summary" : {"hosts_up": ..., "open_ports": ...} ;
        - le résultat doit passer json.dumps et ne rien partager avec l'objet.
        """
        # isoformat() donne par exemple "2026-10-03T11:20:00+02:00" : un datetime
        # n'est pas sérialisable en JSON.
        started_at = self.started_at.isoformat() if self.started_at is not None else None
        return {
            "scan": {
                "id": self.id,
                "target": self.target,
                "type": self.scan_type,
                "ports": self.ports,
                "started_at": started_at,
                "duration_s": self.duration_s,
                "status": self.status,
            },
            "hosts": [h.to_dict() for h in self.hosts],
            "summary": {
                "hosts_up": self.hosts_up,
                "open_ports": self.open_ports_count,
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanResult:
        """Reconstruit un ScanResult depuis un dict (inverse de to_dict).

        À faire :
        - ValueError si data n'est pas un dict, si "scan" est absent ou n'est
          pas un dict, ou si "target" est absent de "scan" ;
        - "type" de to_dict correspond à scan_type ;
        - id, type, ports, started_at, duration_s absents : None ; status
          absent : "pending" ;
        - started_at : None ou chaîne ISO lue avec datetime.fromisoformat ;
          ValueError si ce n'est pas une chaîne ou si elle est invalide ; un
          datetime sans fuseau est refusé (via __post_init__) ;
        - "hosts" absent ou None : liste vide ; présent mais pas une liste :
          ValueError ; sinon Host.from_dict sur chaque élément ;
        - ignorer "summary" (il est recalculé) et les clés inconnues ;
        - ne pas modifier data.
        """
        if not isinstance(data, dict):
            raise ValueError(f"ScanResult : un dict est attendu, reçu {data!r}")

        scan = data.get("scan")
        if not isinstance(scan, dict):
            raise ValueError(f"ScanResult : 'scan' doit être un dict, reçu {scan!r}")
        if "target" not in scan:
            raise ValueError("ScanResult : clé obligatoire 'target' absente de 'scan'")

        # started_at : None, ou une chaîne ISO lue avec fromisoformat. Une chaîne
        # sans fuseau donne un datetime naïf, refusé ensuite par __post_init__.
        started_at = scan.get("started_at")
        if started_at is not None:
            if not isinstance(started_at, str):
                raise ValueError(
                    f"started_at invalide (chaîne ISO attendue) : {started_at!r}"
                )
            try:
                started_at = datetime.fromisoformat(started_at)
            except ValueError:
                raise ValueError(
                    f"started_at invalide (format ISO attendu) : {started_at!r}"
                ) from None

        raw_hosts = data.get("hosts")
        if raw_hosts is None:
            hosts = []
        elif isinstance(raw_hosts, list):
            hosts = [Host.from_dict(h) for h in raw_hosts]
        else:
            raise ValueError(
                f"ScanResult : 'hosts' doit être une liste, reçu {raw_hosts!r}"
            )

        # "summary" n'est pas lu : il est recalculé par les propriétés.
        # La clé "type" du JSON correspond au champ scan_type.
        return cls(
            id=scan.get("id"),
            target=scan["target"],
            scan_type=scan.get("type"),
            ports=scan.get("ports"),
            status=scan.get("status", "pending"),
            started_at=started_at,
            duration_s=scan.get("duration_s"),
            hosts=hosts,
        )