[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_deobfuscripter-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-deobfuscripter)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-deobfuscripter)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-deobfuscripter)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-deobfuscripter)](./LICENSE)
# DeobfuScripter Service

Static script de-obfuscator. The purpose is not to get surgical de-obfuscation, but rather to extract obfuscated IOCs.

## Service Details

### Stage 1 Modules (in order of execution):

1. HTML script extraction

### Stage 2 Modules (in order of execution):

1. MSOffice Embedded script
2. CHR and CHRB decode
3. String replace
4. Powershell carets
5. Array of strings
6. Fake array vars
7. Reverse strings
8. B64 Decode - This module may also extract files
9. Simple XOR function
10. Charcode hex
11. Powershell vars
12. MSWord macro vars
13. Concat strings
14. Charcode

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name DeobfuScripter \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-deobfuscripter

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service DeobfuScripter

Désobfuscateur de scripts statiques. L'objectif n'est pas d'obtenir une désobfuscation chirurgicale, mais plutôt d'extraire les IOC obfusqués.

## Détails du service

### Modules de l'étape 1 (dans l'ordre d'exécution) :

1. Extraction du script HTML

### Modules de l'étape 2 (dans l'ordre d'exécution) :

1. Script MSOffice Embedded
2. Décodage CHR et CHRB
3. Remplacement des chaînes de caractères
4. Carottes Powershell
5. Tableau de chaînes de caractères
6. Faux tableaux de variables
7. Chaînes inversées
8. Décodage B64 - Ce module peut également extraire des fichiers
9. Fonction XOR simple
10. Charcode hexagonal
11. Vars Powershell
12. Vars de macro MSWord
13. Chaînes de concat
14. Charcode

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name DeobfuScripter \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-deobfuscripter

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
