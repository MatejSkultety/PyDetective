# PyDetective

Rozsiahly open-source ekosystém predstavuje neustále sa meniace prostredie tvorené novými ako aj dlhodobonneudržiavanými softvérovými modulmi a knižnicami. Pri využívaní takýchto komponentov je jednou z najväčších výziev vývojárov posúdenie ich kvality a spoľahlivosti. Táto skutočnosť uľahčuje škodlivým aktérom s minimálnym úsilím kompromitovať open-source ekosystém s výhľadom dosiahnutia ich cieľov.

PyDetective je detekčný nástroj určený na analýzu a detekciu škodlivých balíkov v repozitári PyPI. Jeho cieľom je automatizovane identifikovať potenciálne nebezpečné alebo škodlivé Python balíky a tým prispieť k celkovej bezpečnosti ekosystému.

Nástroj kombinuje statickú a dynamickú analýzu, využíva YARA pravidlá, monitorovanie systémových volaní a sieťovej komunikácie v izolovanom sandboxe. Výsledkom je komplexné hodnotenie bezpečnosti analyzovaného balíka.

Projekt bol vytvorený ako súčasť bakalárskej práce na Fakulte elektrotechniky a informatiky STU v Bratislave.

## Použitie

1. Skopírujte repozitár a spustite inštalačný skript:
    ```sh
    ./setup.sh
    ```

2. Spustite analýzu balíka:
    ```sh
    sudo venv/bin/python3 pydetective.py <nazov_balika>
    ```

## Upozornenie

Tento nástroj je určený výhradne na akademické a výskumné účely. Autor nenesie zodpovednosť za škody spôsobené nesprávnym použitím.

---

**Názov práce:** Detekcia škodlivých programových knižníc v softvérovom
repozitári
**Autor:** Matej Skultéty
**Školiteľ:** Ing. Martin Kubečka
**Fakulta informatiky a informačných technológií STU v Bratislave**


---

# English

## PyDetective

The vast open-source ecosystem is a constantly evolving environment composed of both new and long-unmaintained software modules and libraries. One of the biggest challenges for developers using such components is assessing their quality and reliability. This situation makes it easier for malicious actors to compromise the open-source ecosystem with minimal effort to achieve their goals.

PyDetective is a detection tool designed for analyzing and detecting malicious packages in the PyPI repository. Its goal is to automatically identify potentially dangerous or malicious Python packages and thus contribute to the overall security of the ecosystem.

The tool combines static and dynamic analysis, uses YARA rules, monitors system calls and network communication in an isolated sandbox. The result is a comprehensive security assessment of the analyzed package.

The project was created as part of a bachelor's thesis at the Faculty of Electrical Engineering and Information Technology of STU in Bratislava.

## Usage

1. Clone the repository and run the installation script:
    ```sh
    ./setup.sh
    ```

2. Run the package analysis:
    ```sh
    sudo venv/bin/python3 pydetective.py <package_name>
    ```

## Disclaimer

This tool is intended solely for academic and research purposes. The author is not responsible for any damages caused by improper use.

---

**Thesis title:** Detection of Malicious Program Libraries in the Software Repository 
**Author:** Matej Skultéty  
**Supervisor:** Ing. Martin Kubečka  
**Faculty of Informatics and Information Technologies, STU in Bratislava**
