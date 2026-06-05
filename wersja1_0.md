# 1. Wprowadzenie

Poniżej opisane są zmiany wprowadzone w wersji 1.0 projektu względem pierwotnych założeń architektury. Zmiany wynikają z ograniczeń środowiskowych, testów praktycznych oraz decyzji projektowych podjętych w trakcie implementacji systemu.

---

# 2. Zmiany kryptograficzne

W pierwotnych założeniach udział przechowywany w tokenie miał być zabezpieczony przy użyciu AES‑256‑GCM.

W wersji 1.0 zastosowano:

- AES‑CTR do zapewnienia poufności,
- HMAC‑SHA256 do zapewnienia integralności i autentyczności danych.

Powodem zmiany było ograniczenie biblioteki `cryptolib` w MicroPython (brak wsparcia dla trybu GCM).  
Zastosowana konstrukcja (AES‑CTR + HMAC) zachowuje właściwości równoważne AES-GCM w kontekście modelu zagrożeń projektu.

---

# 3. Zmiany w architekturze komunikacji

Początkowo zakładano binarny protokół komunikacyjny.

W wersji 1.0 zastosowano tekstowy protokół oparty na liniach zakończonych `\r\n`.

Powodem była specyfika komunikacji USB CDC w MicroPython (REPL, echo, reset przy otwarciu portu), co utrudniało implementację stabilnego protokołu binarnego bez dodatkowej warstwy transportowej.

Zastosowane rozwiązanie jest deterministyczne i wystarczające w ramach przyjętego modelu zagrożeń.

---

# 4. Zmiany w przechowywaniu danych

Udział w tokenie przechowywany jest w postaci binarnej zgodnie ze strukturą:

```
struct ShareContainer {
    uint8_t  version;              // Wersja formatu (1)
    uint8_t  x_index;              // Numer udziału (1–5)
    uint8_t  reserved[2];          // Wyrównanie (0x00)
    uint8_t  system_id[16];        // 128-bitowy identyfikator systemu
    uint8_t  nonce[16];            // Nonce użyty w AES-CTR
    uint8_t  encrypted_share[32];  // Zaszyfrowany udział (256 bit)
    uint8_t  mac[32];              // HMAC-SHA256 (nonce || ciphertext)
};
```

Struktura zapewnia:

- poufność udziału,
- integralność danych w pamięci flash,
- spójność logiczną poprzez `system_id`.

---

# 5. Funkcje dodane względem architektury

### IDENTIFY

Dodano komendę `IDENTIFY`, umożliwiającą jednoznaczną identyfikację tokena poprzez stały `DEVICE_ID`.  
Pozwoliło to wyeliminować zależność od numerów portów (COMx) oraz zapewnić stabilne przypisanie per‑token kluczy `K_DEVICE`.

---

### detect_active_tokens()

Dodano funkcję wykrywającą aktywne tokeny na podstawie VID (0x2E8A) oraz weryfikującą poprawność komunikacji poprzez komendę `IDENTIFY`.  
Zapobiega to sytuacjom, w których system rozpoczyna operację przy niepełnej liczbie dostępnych tokenów.

---

### Walidacja `system_id`

Wprowadzono kontrolę zgodności `system_id` między tokenami przed rekonstrukcją klucza.  
Zapewnia to logiczną spójność udziałów oraz uniemożliwia przypadkowe łączenie udziałów z różnych systemów.

---

# 6. Funkcje odłożone

### Synchronizowana autoryzacja 3 tokenów

Rozszerzenie polegające na wymaganiu jednoczesnej autoryzacji wszystkich wymaganych tokenów przed wydaniem udziału zostało odłożone na kolejną wersję projektu.  
Funkcja ta wykracza poza zakres wersji 1.0 ale jest priorytetem w dalszym rozwoju projektu.

---

### Limit prób autoryzacji

Mechanizm ograniczania liczby nieudanych prób nie został zaimplementowany ze względu na brak realnego scenariusza skutecznego ataku brute-force przy użyciu HMAC‑SHA256 i 256‑bitowych kluczy.

---

# 7. Ograniczenia środowiskowe

Narzędzie `ssss` dostępne jest wyłącznie w środowisku Linux, co wymusiło wykorzystanie WSL oraz wywołań `subprocess` w Windows.  
Komunikacja z tokenem wymagała dodatkowej konfiguracji portu szeregowego (zarządzanie DTR) w celu uniknięcia resetów mikrokontrolera.

---

# 8. Podsumowanie

Wersja 1.0 spełnia wszystkie kluczowe założenia pierwotnej architektury w zakresie:

- podziału klucza 3 z 5,
- zabezpieczenia udziałów w pamięci tokena,
- autoryzowanego wydania udziału,
- pełnego przepływu: szyfrowanie → zapis udziałów → rekonstrukcja → odszyfrowanie.

Zmiany wprowadzone w trakcie implementacji wynikają z ograniczeń sprzętowych i środowiskowych, jednak nie obniżają poziomu bezpieczeństwa systemu w przyjętym modelu zagrożeń.

Planowany dalszy rozwój obejmuje synchronizowaną autoryzację wielu tokenów oraz eliminację twardego przechowywania `K_DEVICE` po stronie PC.