"""Limiteur de débit de NetScan : espace les opérations dans le temps.

Il sert à ne pas saturer le réseau (option --rate de la CLI) : avant chaque
envoi de paquet ou ouverture de connexion, le scanner appelle le limiteur, qui
le fait attendre si nécessaire. Il est utilisé aussi bien par du code
synchrone (Scapy, threads) que par du code asyncio (scan TCP connect).

Principe : un « seau de jetons » (token bucket).
- Le seau contient au plus `burst` jetons et en gagne `rate` par seconde.
- Chaque opération consomme 1 jeton.
- S'il n'y a plus de jeton, l'opération doit attendre que le jeton manquant
  soit regagné.

Exemple avec rate=10 et burst=1 : une opération toutes les 0,1 s. Avec burst=5,
les 5 premières partent d'un coup, puis une toutes les 0,1 s.

Règle de validation : toute valeur invalide lève ValueError, avec un message
qui cite le paramètre fautif ("rate", "burst").
"""

from __future__ import annotations

import asyncio
import math
import threading
import time
from collections.abc import Awaitable, Callable


class RateLimiter:
    """Limiteur de débit à seau de jetons, sûr pour plusieurs threads.
    """

    def __init__(
        self,
        rate: float | None = None,
        burst: int = 1,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        async_sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """Crée un limiteur.

        À faire :
        - rate : opérations par seconde. None = illimité (jamais d'attente).
          Sinon un nombre (int ou float) fini et > 0, stocké en float. Refuser
          0, négatif, NaN, infini, chaîne, bool (True == 1 en Python), liste ;
        - burst : nombre d'opérations pouvant partir d'un coup. Un int >= 1 ;
          refuser 0, négatif, float (même 1.0), chaîne, None, bool. Il est
          validé même quand rate vaut None ;
        - clock, sleep, async_sleep : les stocker. Ils sont réservés aux
          arguments nommés (le "*" dans la signature) ;
        - état initial : le seau est PLEIN (burst jetons) et l'instant de
          dernière mise à jour est clock() ;
        - créer un threading.Lock pour protéger l'état.
        """
        # rate : None (illimité) ou un nombre fini > 0. bool est écarté
        # explicitement car True == 1 en Python.
        if rate is not None:
            if isinstance(rate, bool) or not isinstance(rate, (int, float)):
                raise ValueError(f"rate invalide (nombre attendu) : {rate!r}")
            # NaN et l'infini ne sont pas des débits utilisables.
            if not math.isfinite(rate) or rate <= 0:
                raise ValueError(f"rate invalide (nombre fini > 0 attendu) : {rate!r}")
            rate = float(rate)

        # burst : un entier >= 1, validé même quand rate vaut None. Un float
        # (même 1.0) et un bool sont refusés.
        if isinstance(burst, bool) or not isinstance(burst, int) or burst < 1:
            raise ValueError(f"burst invalide (entier >= 1 attendu) : {burst!r}")

        self._rate = rate
        self._burst = burst
        self._clock = clock
        self._sleep = sleep
        self._async_sleep = async_sleep

        # État du seau : plein au départ, avec l'instant de la dernière mise à
        # jour. Le verrou protège ces deux valeurs quand plusieurs threads
        # appellent reserve() en même temps.
        self._tokens = float(burst)
        self._last = clock()
        self._lock = threading.Lock()

    @property
    def rate(self) -> float | None:
        """Le débit en opérations par seconde (float), ou None si illimité.

        À faire : lecture seule (pas de setter).
        """
        # Pas de setter défini : limiter.rate = 5 lève AttributeError.
        return self._rate

    @property
    def burst(self) -> int:
        """La capacité du seau.

        À faire : lecture seule (pas de setter).
        """
        return self._burst

    @property
    def unlimited(self) -> bool:
        """True si le limiteur n'impose aucune limite (rate vaut None)."""
        return self._rate is None

    def reserve(self) -> float:
        """Réserve une opération SANS attendre et renvoie le délai à respecter.

        C'est le cœur du limiteur : acquire() et acquire_async() ne font que
        l'appeler puis attendre le délai renvoyé.

        À faire :
        - si le limiteur est illimité : renvoyer 0.0, sans toucher à l'état ;
        - sinon, sous le verrou :
            1. now = clock() ;
            2. temps écoulé = max(0, now - dernier instant) : si l'horloge
               recule, on compte 0 ;
            3. jetons = min(burst, jetons + écoulé * rate) : le seau ne
               dépasse jamais sa capacité ;
            4. mémoriser now comme dernier instant ;
            5. consommer 1 jeton : jetons = jetons - 1 ;
            6. si jetons >= 0 : renvoyer 0.0 ; sinon renvoyer -jetons / rate
               (le temps nécessaire pour rembourser la « dette »).
        - le nombre de jetons peut donc devenir négatif : c'est ce qui espace
          correctement plusieurs appels simultanés (0, 1/rate, 2/rate, ...) ;
        - renvoyer toujours un float >= 0.0 ; ne jamais dormir ici.
        """
        # Illimité : rien à calculer, et pas besoin du verrou puisque l'état
        # n'est pas touché.
        if self._rate is None:
            return 0.0

        # Tout le bloc est protégé : lecture, calcul et écriture des jetons
        # doivent se faire sans qu'un autre thread s'intercale.
        with self._lock:
            now = self._clock()

            # Si l'horloge recule (écart négatif), on compte 0 seconde écoulée.
            elapsed = max(0.0, now - self._last)

            # Les jetons regagnés depuis la dernière fois, plafonnés à burst.
            # Un nombre négatif (dette) reste négatif tant qu'il n'est pas
            # remboursé : min() ne le change pas.
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            self._last = now

            # Cette opération consomme un jeton, même s'il n'y en a plus : le
            # solde négatif réserve un créneau plus tard pour cet appel.
            self._tokens -= 1

            if self._tokens >= 0:
                return 0.0

            # Il manque -tokens jetons, gagnés à `rate` jetons par seconde.
            return -self._tokens / self._rate

    def acquire(self) -> float:
        """Version bloquante (code synchrone, threads).

        À faire :
        - délai = self.reserve() ;
        - si délai > 0 : appeler la fonction sleep injectée avec ce délai ;
        - renvoyer le délai attendu (0.0 s'il n'y a pas eu d'attente).
        """
        delay = self.reserve()
        if delay > 0:
            self._sleep(delay)
        return delay

    async def acquire_async(self) -> float:
        """Version asyncio : attend sans bloquer la boucle d'événements.

        À faire :
        - délai = self.reserve(), AVANT tout await : la réservation doit être
          faite immédiatement, pour que plusieurs tâches lancées ensemble
          (asyncio.gather) obtiennent chacune un créneau différent ;
        - si délai > 0 : await de la fonction async_sleep injectée ;
        - renvoyer le délai attendu.
        """
        # reserve() est synchrone et s'exécute d'un bloc : aucune autre tâche ne
        # peut s'intercaler avant le premier await.
        delay = self.reserve()
        if delay > 0:
            await self._async_sleep(delay)
        return delay

    def reset(self) -> None:
        """Remet le limiteur à son état initial.

        À faire : sous le verrou, remplir le seau (burst jetons) et mémoriser
        clock() comme dernier instant. Ne rien faire de plus ; aucune erreur
        sur un limiteur illimité.
        """
        with self._lock:
            self._tokens = float(self._burst)
            self._last = self._clock()

    def __repr__(self) -> str:
        """Représentation lisible, par exemple "RateLimiter(rate=10.0, burst=2)".

        À faire : utiliser les propriétés rate et burst avec !r. Pour un
        limiteur illimité : "RateLimiter(rate=None, burst=1)".
        """
        return f"RateLimiter(rate={self.rate!r}, burst={self.burst!r})"