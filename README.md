# NetScan

Scanner réseau en ligne de commande écrit en Python, inspiré de nmap. Il découvre les hôtes actifs d'un sous-réseau (ARP, ICMP), scanne les ports TCP et UDP, identifie les services et exporte les résultats en JSON/CSV. Une API REST (Flask) est prévue pour lancer des scans et consulter l'historique.

> **Projet en cours de développement** : la version actuelle n'offre pas encore de fonctionnalité utilisable.

## Avertissement légal

Scanner un réseau ou une machine sans autorisation est illégal dans de nombreux pays. N'utilisez NetScan que sur votre propre lab ou sur des systèmes pour lesquels vous disposez d'une autorisation explicite et écrite. L'auteur décline toute responsabilité en cas d'usage abusif.

## Installation (développement)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Licence

MIT, voir le fichier [LICENSE](LICENSE).