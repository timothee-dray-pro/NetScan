"""
Exceptions propres à NetScan.
La CLI n'a qu'à attraper NetScanError : le message est destiné à
l'utilisateur et exit_code donne le code de retour du programme.
"""


class NetScanError(Exception):
    """Classe mère de toutes les erreurs de NetScan."""

    exit_code = 1

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message


class InvalidTargetError(NetScanError):
    """La cible est invalide (CIDR, adresse IP ou liste mal formés)."""

    exit_code = 2


class PrivilegeError(NetScanError):
    """L'opération demande les droits root (Scapy : ARP, ICMP, SYN)."""

    exit_code = 3

    def __init__(self, message: str = "Cette opération nécessite les droits root (utilise sudo).") -> None:
        super().__init__(message)