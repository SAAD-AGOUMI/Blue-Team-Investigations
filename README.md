# Blue-Team-Investigations

## Index des write-ups

| # | Investigation | Thèmes | Outils |
|---|---|---|---|
| 01 | [Investigation d'une compromission d'un poste Windows et pivot vers un serveur Linux](Investigation%20d%E2%80%99une%20compromission%20d%E2%80%99un%20poste%20windows%20et%20pivot%20vers%20un%20serveur%20Linux/writeup.md) | PowerShell obfusqué, persistance, vol d'identifiants, mouvement latéral, anti-forensics | Splunk, CyberChef |
| 02 | [Reconstruction d’une intrusion à partir d’un dump mémoire et de ruches de registre](Reconstruction%20d%E2%80%99une%20intrusion%20%C3%A0%20partir%20d%E2%80%99un%20dump%20m%C3%A9moire%20et%20de%20ruches%20de%20registre/writeup.md) | PowerShell encodé, zones mémoire anormales, persistance dans le registre, traces de l'opérateur | Volatility, strings, Registry Explorer |

---

## À quoi sert ce dépôt

C'est mon carnet d'investigations. J'y range les analyses que je fais en réponse à incident et en forensic, écrites pour qu'on comprenne **comment je raisonne**, pas seulement ce que j'ai trouvé.

Chaque write-up suit la même logique : je pars d'une alerte ou d'un indice, je me demande si l'attaque a réussi, puis je me mets à la place de l'attaquant pour deviner la suite. C'est cette question qui m'amène d'une étape à la suivante.

## Ce que contient chaque write-up

- **Un point de départ clair** : l'alerte, l'indice ou la question à laquelle je dois répondre.
- **Des captures d'écran** des résultats importants de chaque investigation.
- **Le raisonnement** : pourquoi je regarde cette source, pourquoi cette valeur me paraît anormale.
- **Les limites** : ce que j'ai prouvé, ce que je suppose, et ce que je n'ai pas pu vérifier.
- **Des idées de détection** : ce que je surveillerais pour repérer la même attaque plus tôt.
- **Une chronologie de l'attaque** : un tableau qui résume les phases, de l'accès initial jusqu'au point où mes logs s'arrêtent.
- **Une interprétation** : ma lecture entre les étapes, c'est-à-dire ce que l'attaquant a probablement fait, ce qui reste incertain, et ce que je ferais ensuite.

## Contact

[Saad Agoumi](https://www.linkedin.com/in/saad-agoumi-19495930a/)