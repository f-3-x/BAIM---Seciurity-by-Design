# Security by Design — Aplikacje webowe i mobilne (BAIM)

Materiały do prezentacji oraz aplikacja demonstracyjna Live Demo z przedmiotu **BAIM**.

**Autorzy:** Oskar Czenczek, Mateusz Antkiewicz, Julia Juryniec

## Zawartość repozytorium

- `prezentacja.pptx` — slajdy do wystąpienia.
- `quiz.txt` — quiz sprawdzający do rozwiązania po prezentacji.
- `demo/` — interaktywna aplikacja **Hack & Secure Sandbox** (Node.js + Express + SQLite).

## Struktura wystąpienia (ok. 30 min)

1. **Część 1 (Slajdy 1–5):** Założenia Security by Design, zasada Shift-Left i Threat Modeling, koszty naprawy błędów (1x / 10x / 100x), OWASP Top 10 oraz praktyki dla aplikacji webowych.
2. **Część 2 (Slajd 6 + Live Demo):** Pokaz na żywo aplikacji *Hack & Secure Sandbox* — porównanie podatnego Trybu A (atak `1'` łamiący Fail-Secure oraz SQL Injection `1 OR 1=1`) z bezpiecznym Trybem B (Allow-Listing, zapytania parametryzowane, Least Privilege, Fail-Secure).
3. **Część 3 (Slajdy 7–10):** Specyfika aplikacji mobilnych (Web vs Mobile), Keystore/Keychain, Certificate Pinning, obfuskacja, integralność środowiska oraz złote zasady architektury (Secure by Default, Fail-Secure, Least Privilege, Defense in Depth).
4. **Po prezentacji:** Krótki quiz dla grupy (`quiz.txt`).

## Uruchomienie Live Demo (`Hack & Secure Sandbox`)

Aplikacja korzysta z bazy SQLite w pamięci RAM w trybie tylko do odczytu (`PRAGMA query_only = ON`), więc dane resetują się przy każdym restarcie i nikt nie usunie tabeli podczas testów.

### Wymagania
- **Node.js** (zalecana wersja 18+ lub 20+ LTS)

### Instalacja i start lokalny

```bash
cd demo
npm install
npm start
