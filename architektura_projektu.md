# 1\. Cel projektu

Projekt zakłada budowę systemu przeznaczonego do realizacji ostatecznego, progowego backupu sekretu kryptograficznego. System wykorzystuje schemat Shamir Secret Sharing (SSS) do podziału klucza szyfrującego na pięć udziałów, z których dowolne trzy pozwalają na jego rekonstrukcję (3 z 5).

Sekret właściwy (np. plik użytkownika) szyfrowany jest symetrycznie, natomiast dzielony jest wyłącznie klucz szyfrujący. System przeznaczony jest do jednorazowego użycia w scenariuszach awaryjnych, przy założeniu, że ujawniony udział nie może zostać „unieważniony” ani cofnięty.

Projekt obejmuje również zabezpieczenie udziałów przed nieautoryzowanym odczytem, w szczególności przed podsłuchem transmisji oraz nieuprawnionym wydaniem udziału przez urządzenie.


---


# 2\. Model zagrożeń



## Chronione zasoby:

* 256‑bitowy klucz symetryczny używany do szyfrowania pliku (AES‑256‑GCM).
* Udziały wygenerowane w schemacie Shamir Secret Sharing.
* Zaszyfrowany plik zawierający dane użytkownika.

---

## Założenia:

* Komputer PC generujący oraz rekonstruujący udziały jest elementem zaufanym.
* Mikrokontroler (RP2350) nie jest fizycznie klonowany ani poddawany analizie laboratoryjnej.
* Implementacja kryptograficzna (AES, HMAC, SSSS) jest poprawna i wolna od błędów.

---

## Rozważane zagrożenia:

* Podsłuch transmisji USB między PC a tokenem.
* Nieautoryzowana próba uzyskania udziału z tokena.
* Próba skopiowania udziału poprzez dostęp logiczny do urządzenia.
* Modyfikacja transmisji między PC a tokenem.
* Próba uzyskania udziału przez nieautoryzowaną osobę na autoryzowanym sprzęcie (po rozmowie w piątek np. Osoba ma dostęp do komputera i jeden udział i chce uzyskać do niego dostęp)

---

## Zagrożenia poza zakresem projektu:

* Ataki typu forensic na nośnik danych (odzyskiwanie danych z SSD).
* Analiza pamięci RAM lub pliku swap.
* Zaawansowana analiza fizyczna mikrokontrolera (side‑channel, fault injection).

---

## Rozszerzone zagrożenie (do rozważenia w przyszłości)

Atakujący posiada dostęp do zaufanego PC oraz fizyczny dostęp do pojedynczego tokena i może wykorzystać legalne oprogramowanie do wydobycia udziału.

Potencjalne mechanizmy ograniczające ryzyko:
* synchronizowana autoryzacja wielu tokenów,
* dodatkowy czynnik (PIN/hasło).

---

# 3\. Architektura systemu

## Komputer PC (komponent zaufany)

* Generacja losowego klucza symetrycznego (AES‑256).
* Szyfrowanie oraz odszyfrowywanie plików przy użyciu AES‑256‑GCM.
* Podział klucza na udziały przy użyciu schematu Shamir Secret Sharing (ssss).
* Rekonstrukcja klucza z dostarczonych udziałów.
* Zarządzanie komunikacją z tokenami.

---

## Token (RP2350)

* Bezpieczne przechowywanie pojedynczego udziału.
* Autoryzacja żądań wydania udziału (mechanizm challenge‑response).
* Kontrolowane i szyfrowane wydanie udziału do PC.

Token nie wykonuje pełnej rekonstrukcji ani generacji udziałów.

---

## Kanał komunikacyjny (USB)

* Dwukierunkowa komunikacja między PC a tokenem.
* Transmisja zabezpieczona przed:

  * podsłuchem,
  * modyfikacją danych,
  * nieautoryzowanymi żądaniami wydania udziału.

Bezpieczeństwo transmisji realizowane jest przez warstwę kryptograficzną protokołu aplikacyjnego.

---

# 4. Struktura danych przechowywanych w tokenie

## 4.1 Założenia

- Jeden token przechowuje dokładnie jeden udział (share).
- Token może zostać ponownie użyty do innego sekretu (nadpisanie).
- Udział przechowywany jest w postaci zaszyfrowanej.
- Operacja nadpisania powoduje wymazanie całego sektora flash i zapis nowej struktury.
- Klucz urządzenia `K_device` nie jest częścią tej struktury (przechowywany oddzielnie w firmware).

---

## 4.2 Format logiczny struktury

Struktura zapisywana w pamięci flash mikrokontrolera:

```
struct ShareContainer {
    uint8_t  version;              // Wersja formatu (1)
    uint8_t  x_index;              // Numer udziału (1–5)
    uint8_t  reserved[2];          // Wyrównanie (0x00)
    uint8_t  system_id[16];        // 128-bitowy identyfikator systemu
    uint8_t  nonce[12];            // Nonce użyty do szyfrowania (AES-GCM)
    uint8_t  encrypted_share[32];  // Zaszyfrowany udział (256 bit)
    uint8_t  tag[16];              // Tag uwierzytelniający (AES-GCM)
};
```

---

## 4.3 Opis pól

### `version`
- Umożliwia przyszłe rozszerzenie formatu.
- W wersji 1.0 wartość stała: `0x01`.

### `x_index`
- Numer udziału zgodny z generacją SSS (1–5).
- Używany przy rekonstrukcji sekretu.

### `system_id`
- 128-bitowy losowy identyfikator generowany przez PC przy dzieleniu sekretu.
- Umożliwia wykrycie prób łączenia udziałów z różnych systemów.

### `nonce`
- 96-bitowy losowy nonce używany w AES‑256‑GCM.
- Generowany podczas zapisu udziału.

### `encrypted_share`
- 256-bitowa wartość udziału zaszyfrowana przy użyciu AES‑256‑GCM.
- Klucz szyfrowania: `K_device`.

### `tag`
- 128-bitowy tag uwierzytelniający AES‑GCM.
- Zapewnia integralność i autentyczność przechowywanego udziału.

---

## 4.4 Proces nadpisania udziału

1. Wymazanie całego sektora flash.
2. Zapis nowej struktury `ShareContainer`.
3. Brak dodatkowego „zerowania” danych.

---

## 4.5 Uzasadnienie bezpieczeństwa

- Udział nie jest przechowywany w postaci jawnej.
- Fizyczny odczyt pamięci flash nie ujawnia wartości udziału bez znajomości `K_device`.
- Integralność danych zapewnia mechanizm AES‑GCM.
- `system_id` zapobiega logicznemu mieszaniu udziałów z różnych systemów.

---

# 5. Protokół komunikacyjny

## 5.1 Założenia

- Transport: USB (CDC / wirtualny port szeregowy).
- PC jest inicjatorem komunikacji.
- Token nigdy nie wydaje udziału bez uprzedniej autoryzacji.
- Autoryzacja wymagana jest przed każdym wywołaniem `GET_SHARE`.
- Protokół ma postać binarną.
- Każda operacja jest deterministyczna i jednoznaczna.

---

## 5.2 Format ramki komunikacyjnej

Każda wiadomość przesyłana między PC a tokenem ma strukturę:

```
| CMD (1B) | LEN (2B) | PAYLOAD (LEN B) |
```

- `CMD` – kod komendy (1 bajt).
- `LEN` – długość pola PAYLOAD (uint16, big endian).
- `PAYLOAD` – dane o długości LEN bajtów.

---

## 5.3 Kody komend

| Kod  | Nazwa           | Kierunek        |
|------|----------------|-----------------|
| 0x01 | PING           | PC → Token      |
| 0x02 | STORE_SHARE    | PC → Token      |
| 0x03 | REQUEST_AUTH   | PC → Token      |
| 0x04 | AUTH_RESPONSE  | PC → Token      |
| 0x05 | GET_SHARE      | PC → Token      |
| 0x81 | OK             | Token → PC      |
| 0x82 | ERROR          | Token → PC      |
| 0x83 | AUTH_CHALLENGE | Token → PC      |
| 0x84 | SHARE_DATA     | Token → PC      |

---

## 5.4 Procedury operacyjne

### 5.4.1 Zapis udziału (`STORE_SHARE`)

**PC → Token**

Payload:
```
x_index (1B)
system_id (16B)
nonce (12B)
encrypted_share (32B)
tag (16B)
```

**Token:**
1. Kasuje sektor flash.
2. Zapisuje strukturę `ShareContainer`.
3. Odpowiada `OK` lub `ERROR`.

---

### 5.4.2 Autoryzacja (`REQUEST_AUTH`)

Autoryzacja wymagana jest przed każdym wywołaniem `GET_SHARE`.

1. **PC → Token:** `REQUEST_AUTH`
2. **Token:**
   - generuje losowy 256-bitowy `nonce_auth`,
   - wysyła `AUTH_CHALLENGE (nonce_auth)`.
3. **PC:**
   - oblicza `H = HMAC_SHA256(K_device, nonce_auth)`,
   - wysyła `AUTH_RESPONSE (H)`.
4. **Token:**
   - oblicza lokalnie HMAC,
   - porównuje wynik,
   - w przypadku zgodności przechodzi do realizacji `GET_SHARE`,
   - w przeciwnym razie zwraca `ERROR`.

Autoryzacja nie jest utrzymywana jako trwała sesja. Każde `GET_SHARE` wymaga pełnego procesu challenge-response.

---

### 5.4.3 Wydanie udziału (`GET_SHARE`)

1. **PC → Token:** `GET_SHARE`
2. **Token:**
   - generuje `nonce_session`,
   - wyprowadza klucz sesji:
     ```
     K_session = SHA256(K_device || nonce_session)
     ```
   - szyfruje udział przy użyciu AES‑256‑GCM z kluczem `K_session`,
   - wysyła `SHARE_DATA` zawierające:
     ```
     nonce_session (12B)
     encrypted_share (32B)
     tag (16B)
     ```

Brak poprawnej autoryzacji powoduje zwrócenie `ERROR` i brak wydania udziału.

---

## 5.5 Właściwości bezpieczeństwa

- Udział nigdy nie jest przesyłany w postaci jawnej.
- Każde wydanie udziału wymaga oddzielnej autoryzacji.
- Transmisja chroniona jest przed podsłuchem i modyfikacją.
- Brak utrzymywanej sesji ogranicza ryzyko błędów stanu logicznego.


---

# 6. Warstwa kryptograficzna (PC)

## 6.1 Założenia

- Wszystkie operacje generacji i rekonstrukcji udziałów wykonywane są na komputerze PC.
- PC jest komponentem zaufanym w modelu zagrożeń.
- Token nie uczestniczy w generacji ani rekonstrukcji SSS.

---

## 6.2 Użyte algorytmy kryptograficzne

| Funkcja                         | Algorytm              | Parametry                  |
|----------------------------------|-----------------------|----------------------------|
| Szyfrowanie pliku               | AES‑256‑GCM          | Klucz 256 bit, nonce 96 bit |
| Uwierzytelnianie (challenge)    | HMAC‑SHA256          | Klucz 256 bit              |
| Wyprowadzanie klucza sesji      | SHA‑256              | 256 bit output             |
| Podział sekretu (SSS)           | ssss                 | `-x -s 256`                |
| Generator losowy                | os.urandom()         | Kryptograficznie bezpieczny |

---

## 6.3 Proces szyfrowania pliku

1. Generacja losowego 256-bitowego klucza:
   ```
   K = os.urandom(32)
   ```

2. Generacja losowego 96-bitowego nonce dla AES‑GCM.

3. Szyfrowanie pliku przy użyciu AES‑256‑GCM:
   - Dane wyjściowe: ciphertext + tag.
   - Nonce zapisywany razem z zaszyfrowanym plikiem.

4. Podział klucza K przy użyciu:
   ```
   ssss-split -t 3 -n 5 -x -s 256
   ```

5. Przekazanie udziałów do odpowiednich tokenów.

6. Nadpisanie zmiennej K w pamięci procesu.

---

## 6.4 Proces odszyfrowania pliku

1. Autoryzacja trzech tokenów.
2. Pobranie trzech udziałów.
3. Rekonstrukcja klucza przy użyciu:
   ```
   ssss-combine -t 3 -x
   ```

4. Odszyfrowanie pliku przy użyciu AES‑256‑GCM.
5. Nadpisanie zrekonstruowanego klucza w pamięci procesu.

---

## 6.5 Zasady bezpieczeństwa

- Klucz AES nigdy nie jest zapisywany w postaci jawnej na dysku.
- Klucz istnieje wyłącznie w pamięci procesu PC.
- Brak trwałego przechowywania sekretu poza tokenami.
- Integralność danych zapewnia AES‑GCM.
- Integralność autoryzacji zapewnia HMAC‑SHA256.

Dobrze.  
Teraz projektujemy **logikę tokena jako maszynę stanów**.

To jest bardzo ważne, bo w embedded najwięcej błędów wynika z niekontrolowanego stanu urządzenia.

---

# 7. Logika tokena (RP2350) – Model stanów 

## 7.1 Założenia

- Token przechowuje dokładnie jeden udział.
- Token nie utrzymuje trwałej sesji.
- Autoryzacja wymagana jest przed każdym `GET_SHARE`.
- Token po restarcie wraca do stanu początkowego.
- Brak pamięci stanu po odłączeniu zasilania.

---

## 7.2 Stany logiczne

Token może znajdować się w jednym z następujących stanów:

### INIT
- Uruchomienie urządzenia.
- Inicjalizacja peryferiów.
- Wczytanie struktury `ShareContainer` z flash.
- Przejście do stanu `IDLE`.

---

### IDLE
Stan oczekiwania na komendy.

Dozwolone komendy:
- `PING`
- `STORE_SHARE`
- `REQUEST_AUTH`

Niedozwolone:
- `GET_SHARE` (zwraca `ERROR`)

---

### AUTH_PENDING
Stan po wysłaniu `AUTH_CHALLENGE`.

Token:
- przechowuje tymczasowo `nonce_auth`
- oczekuje na `AUTH_RESPONSE`

Jeśli:
- HMAC poprawne → przejście do `AUTH_OK`
- HMAC błędne → powrót do `IDLE`

---

### AUTH_OK (stan przejściowy)

Stan logiczny oznaczający poprawną autoryzację.

Dozwolona operacja:
- `GET_SHARE`

Po wykonaniu `GET_SHARE`:
- natychmiastowy powrót do `IDLE`

Brak trwałej sesji.

---

## 7.3 Obsługa komend

### STORE_SHARE
- Dozwolone tylko w `IDLE`.
- Kasowanie sektora flash.
- Zapis nowej struktury.
- Powrót do `IDLE`.

---

### REQUEST_AUTH
- Dozwolone tylko w `IDLE`.
- Generacja `nonce_auth`.
- Wysłanie `AUTH_CHALLENGE`.
- Przejście do `AUTH_PENDING`.

---

### AUTH_RESPONSE
- Dozwolone tylko w `AUTH_PENDING`.
- Weryfikacja HMAC.
- Jeśli poprawne → `AUTH_OK`.
- Jeśli błędne → `IDLE`.

---

### GET_SHARE
- Dozwolone tylko w `AUTH_OK`.
- Generacja `nonce_session`.
- Wyprowadzenie `K_session`.
- Szyfrowanie udziału.
- Wysłanie `SHARE_DATA`.
- Powrót do `IDLE`.

---

## 7.4 Właściwości bezpieczeństwa

- Brak trwałej autoryzacji.
- Brak przechowywania sesji.
- Brak możliwości wydania udziału bez pełnego handshake.
- Restart urządzenia resetuje stan.

W bazowej wersji nie wprowadzono limitu prób autoryzacji ze względu na nierealność ataku brute-force przez USB, ale jest to możliwe do dodania w przyszłości.

---

# 8. Interfejs CLI ()

## 8.1 Założenia

- Interfejs użytkownika jest minimalistyczny i składa się z dwóch głównych poleceń: `encrypt` oraz `decrypt`.
- Parametry schematu progowego są zamrożone w wersji 1.0:
  - liczba udziałów `n = 5`,
  - próg rekonstrukcji `k = 3`.
- Funkcje pomocnicze (np. zapis udziału na token, odczyt udziału z tokena) istnieją w kodzie jako oddzielne funkcje/moduły, ale nie są eksponowane jako osobne komendy CLI w wersji 1.0.
- Program prowadzi użytkownika krok po kroku w momentach wymagających interakcji z tokenami (podłączenie/odłączenie urządzenia).

---

## 8.2 Polecenie `encrypt`

Przykład:
```
backup encrypt <ścieżka_do_pliku>
```

Działanie:
1. Generacja losowego 256-bitowego klucza AES.
2. Szyfrowanie pliku przy użyciu AES‑256‑GCM (wynik: plik `<nazwa>.enc` oraz metadane niezbędne do odszyfrowania).
3. Podział klucza na 5 udziałów przy użyciu SSS (3 z 5).
4. Zapis udziałów do 3 tokenów (program prosi użytkownika o podłączenie kolejnych tokenów).
5. Wyczyszczenie klucza z pamięci procesu.

Wynik:
- zaszyfrowany plik `<nazwa>.enc`,
- udziały zapisane na tokenach.

---

## 8.3 Polecenie `decrypt`

Przykład:
```
backup decrypt <ścieżka_do_pliku.enc>
```

Działanie:
1. Program prosi o podłączenie kolejnych tokenów.
2. Dla każdego tokena wykonywana jest autoryzacja (challenge‑response) i odczyt udziału.
3. Rekonstrukcja klucza AES z 3 udziałów.
4. Odszyfrowanie pliku przy użyciu AES‑256‑GCM.
5. Wyczyszczenie klucza z pamięci procesu.

Wynik:
- odszyfrowany plik wyjściowy.

---

# 9. Plan implementacyjny

## 9.1 Strategia ogólna

Implementacja prowadzona będzie warstwowo, zaczynając od warstwy PC (ze względu na brak RP2350 na ten moment), a kończąc na integracji i testach końcowych.

Kolejność prac:

1. Warstwa PC (bez tokena)
2. Minimalny firmware tokena
3. Komunikacja USB
4. Challenge‑response
5. Integracja kryptografii
6. Testy integracyjne

---

## 9.2 Etap 1 – Warstwa PC

Cel: mieć w pełni działający program `encrypt` / `decrypt` bez użycia tokenów.

Zakres:
- Implementacja CLI (`encrypt`, `decrypt`).
- Integracja AES‑256‑GCM (biblioteka `cryptography`).
- Integracja `ssss` przez subprocess.
- Test: szyfrowanie pliku → podział klucza → ręczne wklejenie udziałów → rekonstrukcja → odszyfrowanie.

Rezultat:
- Wersja działająca lokalnie bez sprzętu.

---

## 9.3 Etap 2 – Minimalny firmware tokena

Cel: komunikacja i zapis struktury w flash.

Zakres:
- Inicjalizacja USB (CDC).
- Implementacja odbioru i wysyłania ramek.
- Implementacja `STORE_SHARE`.
- Implementacja odczytu i zapisu struktury `ShareContainer`.
- Test: zapis struktury → restart → odczyt poprawności.

Rezultat:
- Token przechowuje zaszyfrowany udział.

---

## 9.4 Etap 3 – Protokół i maszyna stanów

Cel: poprawne działanie protokołu.

Zakres:
- Implementacja maszyny stanów (IDLE, AUTH_PENDING, AUTH_OK).
- Implementacja `REQUEST_AUTH` i `AUTH_RESPONSE`.
- Implementacja `GET_SHARE`.
- Testy negatywne (błędny HMAC, niepoprawne komendy).

Rezultat:
- Token poprawnie wymusza autoryzację przed wydaniem udziału.

---

## 9.5 Etap 4 – Integracja kryptografii na tokenie

Cel: pełne zabezpieczenie udziału.

Zakres:
- Implementacja HMAC‑SHA256.
- Implementacja AES‑256‑GCM.
- Implementacja wyprowadzania `K_session`.
- Testy zgodności z PC.

Rezultat:
- Udział nigdy nie opuszcza tokena w postaci jawnej.

---

## 9.6 Etap 5 – Integracja końcowa

Cel: pełny przepływ end‑to‑end.

Scenariusz:
1. `encrypt`
2. zapis udziałów na tokenach
3. `decrypt`
4. odzyskanie pliku

Testy:
- poprawne 3 z 5
- próba 2 z 5 (powinna się nie udać)
- błędny token
- błędna autoryzacja

---

## 9.7 Etap 6 – Stabilizacja i dokumentacja

- Czyszczenie kodu.
- Obsługa błędów.
- Komentarze techniczne.
- Diagramy do dokumentacji końcowej.

---

# 9.8 Priorytety ryzyka

Największe ryzyko:
1. USB komunikacja.
2. Operacje kryptograficzne na tokenie.
3. Zarządzanie pamięcią flash.

---
