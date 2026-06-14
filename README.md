# 1. Wstęp i Cel Projektu

## 1.1. Opis problemu
W systemach wysokiego bezpieczeństwa przechowywanie klucza szyfrującego w jednym miejscu (np. na jednym dysku lub w jednym menedżerze haseł) tworzy tzw. *Single Point of Failure* (pojedynczy punkt awarii). Kradzież lub utrata tego jednego nośnika oznacza całkowitą utratę dostępu do danych lub ich wyciek.

## 1.2. Cel projektu
Celem projektu jest budowa systemu ostatecznego backupu, który eliminuje problem pojedynczego punktu awarii poprzez zastosowanie rozproszonego przechowywania sekretu. System ma zapewniać, że klucz szyfrujący nie istnieje w całości w żadnym pojedynczym urządzeniu, a jego odzyskanie wymaga współpracy grupy zaufanych tokenów.

## 1.3. Kluczowe założenia i innowacje
W przeciwieństwie do standardowych systemów backupu, niniejszy projekt wprowadza:
*   **Progową strukturę dostępu (k-of-n):** Wykorzystanie schematu Shamir Secret Sharing (SSS), gdzie do rekonstrukcji klucza wymagane jest minimum $k$ udziałów z $n$ wygenerowanych.
*   **Sprzętowe Quorum:** Wprowadzenie mechanizmu "Sygnału Quorum", który wymusza fizyczną obecność wymaganej liczby tokenów przed wydaniem jakichkolwiek danych. System zapobiega sytuacji, w której autoryzowany komputer mógłby wyciągnąć udziały z pojedynczych tokenów po kolei.
*   **Zero Trust PC:** Przeniesienie zaufania z oprogramowania na poziomie systemu operacyjnego na poziom sprzętowy (tokeny), co chroni dane nawet w przypadku przejęcia kontroli nad komputerem przez niepowołaną osobę.


---

# 2. Model Zagrożeń i Strategie Obronne

## 2.1. Zasoby chronione
System ma na celu zapewnienie poufności i integralności następujących zasobów:
*   **Klucz główny (Master Key):** 256-bitowy klucz symetryczny służący do szyfrowania plików użytkownika.
*   **Udziały SSS (Shares):** Fragmenty klucza głównego oraz klucza odblokowującego.
*   **Szyfrowane dane użytkownika:** Pliki chronione za pomocą AES-256.

## 2.2. Założenia projektowe
*   **Mikrokontroler (RP2350):** Przyjmuje się, że urządzenie nie jest poddawane zaawansowanej analizie laboratoryjnej (np. luki w sprzęcie) ani klonowaniu.
*   **Implementacja kryptograficzna:** Przyjmuje się poprawność działania bibliotek `cryptolib` (AES) oraz funkcji `hashlib` i `hmac`.
*   **Klucz urządzenia (`K_device`):** Jest przechowywany w sposób bezpieczny wewnątrz firmware'u tokena.

## 2.3. Analiza zagrożeń i mechanizmy obronne

W poniższej tabeli zestawiono zidentyfikowane zagrożenia oraz zaimplementowane rozwiązania, które je niwelują.

| Zagrożenie | Mechanizm obronny | Opis rozwiązania |
| :--- | :--- | :--- |
| **Podsłuch transmisji USB** | Szyfrowanie sesyjne | Dane nie są przesyłane jawnie. Udziały są szyfrowane za pomocą klucza sesyjnego wyprowadzonego z `K_device` i losowego nonce. |
| **Fizyczna kradzież tokena** | Szyfrowanie w spoczynku | Udziały zapisane w pamięci Flash są zaszyfrowane kluczem urządzenia `K_device`. Bez niego odczyt bajtów z Flash jest bezużyteczny. |
| **Manipulacja plikiem `share.bin`** | Konstrukcja Encrypt-then-MAC | Każdy zapis zawiera HMAC-SHA256 obejmujący wszystkie pola (wersja, indeks, ID, nonce, szyfrogramy). Każda zmiana choćby jednego bitu skutkuje odrzuceniem tokena. |
| **Przejęcie autoryzowanego PC + 1 Token** | **Sprzętowe Quorum (Double SSS)** | Token nie wyda udziału w kluczu głównym, dopóki PC nie przedstawi poprawnie zrekonstruowanego klucza $K_{unlock}$. Rekonstrukcja ta wymaga fizycznej obecności minimum $k$ tokenów. |
| **Atak typu Replay (powtórzenie)** | Challenge-Response (Nonce) | Każda próba autoryzacji wymaga odpowiedzi na nowy, losowy nonce wygenerowany przez token. Stare odpowiedzi HMAC są nieważne. |
| **Mieszanie udziałów z różnych systemów** | System ID | Każdy zestaw udziałów posiada unikalny `system_id`. PC weryfikuje spójność tego ID między tokenami przed próbą rekonstrukcji. |

## 2.4. Zagrożenia poza zakresem projektu
Z warunków projektów wyłączone są zagrożenia:
*   Zaawansowana analiza fizyczna (np. ataki Side-Channel, Fault Injection).
*   Analiza pamięci RAM komputera PC (np. zrzuty pamięci/swap).
*   Ataki typu forensic na nośnik danych SSD.

---

# 3. Architektura Systemu

System został zaprojektowany w architekturze rozproszonej, składającej się z dwóch głównych komponentów: stacji zarządzającej (PC) oraz zestawu bezpiecznych tokenów sprzętowych.

## 3.1. Komponent PC (Stacja Zarządzająca)
Komponent PC pełni rolę koordynatora całego procesu. Jest on odpowiedzialny za operacje wysokopoziomowe, które wymagają większej mocy obliczeniowej i dostępu do systemu plików.

**Kluczowe funkcje PC:**
*   **Zarządzanie sekretami:** Generowanie losowych kluczy symetrycznych (AES-256) i ich podział za pomocą schematu Shamir Secret Sharing (SSS).
*   **Koordynacja Quorum:** Zarządzanie sesjami z wieloma tokenami jednocześnie, zbiórka udziałów odblokowujących i ich rekonstrukcja.
*   **Szyfrowanie plików:** Implementacja algorytmu AES-256-GCM do ochrony danych użytkownika.
*   **Obsługa komunikacji:** Implementacja protokołu wymiany danych z tokenami za pośrednictwem interfejsu szeregowego (UART/USB CDC).

## 3.2. Komponent Token (Urządzenie Bezpieczeństwa)
Tokeny są niezależnymi jednostkami opartymi na mikrokontrolerze RP2350, zaprogramowanymi w języku MicroPython. Ich głównym zadaniem jest bezpieczne przechowywanie fragmentu sekretu i rygorystyczna kontrola dostępu do niego.

**Kluczowe funkcje Tokena:**
*   **Bezpieczne przechowywanie:** Przechowywanie udziałów w zaszyfrowanej formie w pamięci Flash (plik `share.bin`).
*   **Weryfikacja tożsamości:** Obsługa mechanizmu Challenge-Response przy użyciu HMAC-SHA256 w celu autoryzacji PC.
*   **Wymuszanie Quorum:** Implementacja wewnętrznej weryfikacji klucza odblokowującego. Token nie wyda głównego udziału, dopóki nie zostanie mu dostarczony poprawny klucz $K_{unlock}$.
*   **Szyfrowanie w spoczynku:** Wykorzystanie unikalnego klucza urządzenia `K_device` do ochrony danych w pamięci nieulotnej.

## 3.3. Kanał Komunikacyjny i Protokół
Komunikacja odbywa się za pomocą protokołu tekstowego realizowanego przez interfejs USB CDC (wirtualny port szeregowy), w oparciu o mechanizm REPL.

**Charakterystyka protokołu:**
*   **Typ komunikacji:** Półdupleksowa, oparta na komendach tekstowych.
*   **Bezpieczeństwo transmisji:** 
    *   **Autoryzacja:** Każda sesja rozpoczyna się od wymiany nonce i HMAC.
    *   **Poufność:** Udziały przesyłane są w formie zaszyfrowanej za pomocą klucza sesyjnego wyprowadzonego z `K_device`.
*   **Model interakcji:** PC jest inicjatorem wszystkich żądań; token działa jako serwer odpowiedzi, reagując na konkretne komendy (np. `AUTH`, `STORE`, `GET_SHARE`).

---

# 4. Implementacja Techniczna

## 4.1. Szyfrowanie i Integralność Danych
W projekcie zrezygnowano z trybu AES-GCM na rzecz konstrukcji **Encrypt-then-MAC**, łączącej szyfrowanie AES-CTR z uwierzytelnianiem HMAC-SHA256. Wybór ten był podyktowany ograniczeniami bibliotek MicroPythona oraz chęcią zapewnienia najwyższego poziomu kontroli nad procesem weryfikacji danych.

### 4.1.1. Szyfrowanie AES-CTR
Do ochrony danych w spoczynku (na tokenie) oraz w transmisji wykorzystano tryb **CTR (Counter Mode)**. Jest to szyfr strumieniowy, który przekształca blokowy algorytm AES w generator strumienia klucza.
*   **Klucz:** `K_DEVICE` (unikalny dla każdego urządzenia).
*   **Nonce:** Losowy wektor inicjujący (16 bajtów), zapobiegający identycznym szyfrogramom dla tych samych danych.

### 4.1.2. Uwierzytelnianie HMAC-SHA256
Aby zapobiec atakom typu *bit-flipping* (charakterystycznym dla trybu CTR) oraz manipulacjom w pliku `share.bin`, zastosowano mechanizm **HMAC (Hash-based Message Authentication Code)**.

MAC jest obliczany nad całym stanem logicznym zapisu:
$$MAC = HMAC(K_{device}, \text{version} \parallel \text{x\_index} \parallel \text{system\_id} \parallel \text{nonce} \parallel \text{ciphertext} \parallel \dots)$$
Dzięki temu każda próba modyfikacji indeksu udziału, identyfikatora systemu lub samych danych kończy się odrzuceniem tokena przez funkcję `read_container()`.

## 4.2. Mechanizm Quorum (autoryzowanie synchronizowane)
Sercem systemu jest dwuwarstwowa implementacja schematu Shamir Secret Sharing (SSS), która przenosi zaufanie z poziomu PC na poziom fizycznej obecności urządzeń. Mechanizm bierze inspiracje z sposobu komunikacji bakterii, z której czerpie nazwę.

### 4.2.1. Pierwsza warstwa: Klucz Danych ($K_{data}$)
Klucz główny, służący do szyfrowania plików, jest dzielony na udziały $S_i$ zgodnie z progiem $k$ z $n$ (np. 3 z 5). Pojedynczy udział $S_i$ jest bezużyteczny bez pozostałych $k-1$ fragmentów.

### 4.2.2. Druga warstwa: Klucz Odblokowujący ($K_{unlock}$)
Aby zapobiec wyciekowi udziału $S_i$ w przypadku przejęcia autoryzowanego komputera, wprowadzono klucz odblokowujący.
1.  **Generacja:** Tworzony jest losowy klucz $K_{unlock}$, z którego obliczany jest skrót $H_{unlock} = SHA256(K_{unlock})$.
2.  **Podział:** $K_{unlock}$ jest dzielony na udziały $U_i$ za pomocą SSS.
3.  **Przechowywanie:** Każdy token przechowuje parę $(S_i, U_i)$ oraz pełny hash $H_{unlock}$.

### 4.2.3. Proces weryfikacji Quorum
Token nie wyda udziału $S_i$, dopóki PC nie przedstawi mu dowodu posiadania pozostałych tokenów. Dowodem tym jest zrekonstruowany klucz $K_{unlock}$.
*   Token przyjmuje $K_{unlock}$ od PC.
*   Oblicza jego hash: $\text{calc\_H} = SHA256(K_{unlock})$.
*   Porównuje $\text{calc\_H}$ z zapisanym w pamięci $H_{unlock}$.
*   Dopiero po sukcesie tej operacji token przechodzi w stan `authorized`.

## 4.3. Struktura danych w Tokenie
Udziały są przechowywane w pliku `share.bin` w postaci binarnej struktury. Wszystkie dane wrażliwe są szyfrowane za pomocą `K_device`.

**Format logiczny zapisu:**
| Pole | Rozmiar | Opis |
| :--- | :--- | :--- |
| `version` | 1B | Wersja formatu (obecnie 1) |
| `x_index` | 1B | Numer udziału w schemacie SSS |
| `reserved` | 2B | Wyrównanie danych (0x00) |
| `system_id` | 16B | Unikalny identyfikator całego systemu backupu |
| `nonce` | 16B | Nonce dla AES-CTR |
| `ciphertext` | 32B | Zaszyfrowany udział główny $S_i$ |
| `mac` | 32B | HMAC-SHA256 dla całej struktury |
| `encrypted_unlock_share` | 32B | Zaszyfrowany udział odblokowujący $U_i$ |
| `encrypted_unlock_hash` | 32B | Zaszyfrowany hash pełnego klucza $H_{unlock}$ |

## 4.4. Maszyna Stanów Tokena
Aby zapewnić determinizm i bezpieczeństwo, logika tokena została zaimplementowana jako maszyna stanów. Zapobiega to pominięciu etapów autoryzacji.

**Przebieg stanów:**
1.  **`IDLE`**: Stan oczekiwania. Obsługuje `PING`, `IDENTIFY` oraz `AUTH`.
2.  **`AUTH_WAIT`**: Oczekiwanie na poprawny HMAC od PC. Po sukcesie $\rightarrow$ wysyła $U_i$ i przechodzi do `UNLOCK_WAIT`.
3.  **`UNLOCK_WAIT`**: Oczekiwanie na pełny $K_{unlock}$. Po weryfikacji hasha $\rightarrow$ ustawia flagę `authorized` i przechodzi do `IDLE`.
4.  **Wydanie danych**: Komenda `GET_SHARE` jest obsługiwana tylko wtedy, gdy `authorized == True`. Po wydaniu danych flaga jest natychmiast resetowana.

---

# 5. Procedury Operacyjne (Workflow)

Procesy w systemie zostały zaprojektowane tak, aby maksymalnie ograniczyć ryzyko błędów i zapewnić, że żadna wrażliwa informacja nie zostanie ujawniona przed pełną autoryzacją wszystkich zaangażowanych stron.

## 5.1. Proces Tworzenia Backupu (Szyfrowanie)
Procedura tworzenia kopii zapasowej przebiega w następujących krokach:

1.  **Generowanie sekretów:**
    *   System generuje losowy 256-bitowy klucz główny $K_{data}$ oraz losowy 256-bitowy klucz odblokowujący $K_{unlock}$.
    *   Obliczany jest skrót $H_{unlock} = SHA256(K_{unlock})$.
2.  **Szyfrowanie danych:**
    *   Plik użytkownika zostaje zaszyfrowany za pomocą algorytmu AES-256-GCM z użyciem $K_{data}$.
3.  **Podział sekretów (Double SSS):**
    *   $K_{data}$ zostaje podzielony na udziały $S_1 \dots S_n$.
    *   $K_{unlock}$ zostaje podzielony na udziały $U_1 \dots U_n$.
4.  **Dystrybucja do tokenów:**
    *   Użytkownik podłącza kolejno tokeny.
    *   Na każdy token zapisywana jest struktura `ShareContainer` zawierająca:
        *   Szyfrowany udział główny $S_i$.
        *   Szyfrowany udział odblokowujący $U_i$.
        *   Szyfrowany pełny hash $H_{unlock}$.
        *   Unikalny `system_id` dla całego zestawu.
5.  **Zabezpieczenie pozostałych udziałów:**
    *   Udziały $k+1 \dots n$ (zapasowe) są wyświetlane w konsoli i muszą zostać zapisane przez użytkownika w bezpiecznym miejscu (np. papierowy backup).

## 5.2. Proces Odzyskiwania (Deszyfrowanie)
Proces odzyskiwania danych jest zsynchronizowany i składa się z czterech krytycznych faz. Wszystkie tokeny muszą przejść przez każdą fazę, aby proces mógł być kontynuowany.

### Faza I: Inicjalizacja i Zbiórka Quorum
1.  **Ustanowienie sesji:** PC wykrywa podłączone tokeny i otwiera do nich połączenia szeregowe.
2.  **Autoryzacja HMAC:** PC przeprowadza procedurę Challenge-Response z każdym tokenem, aby potwierdzić tożsamość urządzenia.
3.  **Pobranie udziałów odblokowujących:** Po udanej autoryzacji każdy token wysyła swój udział $U_i$.

### Faza II: Rekonstrukcja Klucza Dostępu
1.  **Łączenie udziałów:** PC zbiera minimum $k$ udziałów $U_i$ i za pomocą algorytmu SSS rekonstruuje pełny klucz $K_{unlock}$.
2.  **Weryfikacja spójności:** PC sprawdza, czy zrekonstruowany klucz jest poprawny przed wysłaniem go do tokenów.

### Faza III: Odblokowanie Tokenów (Sygnał Quorum)
1.  **Wysyłka klucza:** PC przesyła zrekonstruowany $K_{unlock}$ do każdego z podłączonych tokenów.
2.  **Weryfikacja wewnątrz urządzenia:** Każdy token oblicza $SHA256(K_{unlock})$ i porównuje go z zapisanym w pamięci $H_{unlock}$.
3.  **Zmiana stanu:** Jeśli hash się zgadza, token przechodzi w stan `authorized`, umożliwiając wydanie głównego sekretu.

### Faza IV: Ekstrakcja Sekretu i Deszyfrowanie
1.  **Pobieranie udziałów głównych:** PC wysyła komendę `GET_SHARE` do autoryzowanych tokenów.
2.  **Rekonstrukcja klucza głównego:** Po zebraniu $k$ udziałów $S_i$, PC rekonstruuje klucz $K_{data}$.
3.  **Odszyfrowanie pliku:** Za pomocą $K_{data}$ plik zostaje odszyfrowany i przywrócony do postaci jawnej.
4.  **Czyszczenie sesji:** Wszystkie połączenia zostają zamknięte, a tokeny automatycznie resetują swój stan do `IDLE`.

---

# 6. Instrukcja Obsługi

Niniejszy system jest aplikacją konsolową (CLI). Do jego poprawnego działania wymagana jest instalacja środowiska Python oraz zainstalowanie niezbędnych bibliotek za pomocą pliku `requirements.txt`.

## 6.1. Instalacja i przygotowanie
1.  **Instalacja programu:** Po wypakowaniu należy przejść do folderu `backup`.
2.  **Instalacja zależności:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Konfiguracja:** Upewnij się, że w pliku `config.py` znajdują się poprawne klucze urządzeń (`DEVICE_KEYS`) przypisane do identyfikatorów Twoich tokenów. (Tokeny które oddałem mają aktualną wersje oprogramowania oraz poprawne klucze)
4. **Tworzenie nowych tokenów:** By stworzyć funkcjonalny token, należy wgrać micropython'a na RP2350 w trybie BOOTSEL, a następnie zapisać plik `main.py` z folderu `micropy` na pen'ie. W zapisanym pliku należy zmienić zmienną `K_DEVICE` na wybrany ciąg 64 znaków hex zapisanych w bajtach oraz `DEVICE_ID` na wybrany identyfikator. Aby program rozpoznał token, trzeba dodać parę `DEVICE_ID`: `K_DEVICE` do zmiennej w pliku `config.py` w folderze `backup`.
Here's a ready-to-copy section in Polish for explaining system dependencies installation in the `dokumentacja.md` file. You can insert this after section 6.1 (before "Instalacja zależności"):

## 6.1.1. Instalacja zależności systemowych

Poza zależnościami python'a, system wymaga zainstalowania dodatkowych narzędzi systemowych, aby prawidłowo funkcjonować:

### Wymagania systemowe

1. **Windows Subsystem for Linux (WSL)** - wymagany do uruchomienia narzędzi SSS
   - WSL musi być zainstalowany i skonfigurowany w systemie Windows
   - Program używa WSL do uruchomienia poleceń `ssss-split` i `ssss-combine`

2. **SSSS (Shamir's Secret Sharing Scheme)** - narzędzie do dzielenia i rekonstrukcji sekretów
   - Musi być zainstalowane wewnątrz WSL
   - Jest wymagane do operacji podziału i łączenia kluczy

### Instrukcja instalacji

#### Krok 1: Instalacja WSL (jeśli nie zainstalowany)
Otwórz PowerShell jako Administrator i uruchom:
```powershell
wsl --install
```

Po instalacji uruchom WSL i zaktualizuj system:
```bash
sudo apt update
sudo apt upgrade -y
```

#### Krok 2: Instalacja SSSS w WSL
Wewnątrz WSL uruchom:
```bash
sudo apt install ssss -y
```

Aby sprawdzić, czy instalacja się powiodła:
```bash
ssss-split --help
ssss-combine --help
```

Jeśli używasz systemu linux program zadziała bez WSL, wystarczy zainstalować `ssss` i w pliku `sss.py` usunąć `"wsl", ` z funkcji `subprocess.Popen` w obydwu funkcjach.

---

**Przebieg procesu:**
1.  Przed uruchomieniem programu podłącz tokeny do komputera. 
2.  Dla każdego z 3 pierwszych tokenów system wykonuje autoryzację i zapisuje udział w kluczu głównym oraz klucz odblokowujący.
3.  Na koniec program wyświetla udziały zapasowe (4 i 5), które należy zapisać w bezpiecznym miejscu poza systemem cyfrowym.

Powodem wypisywania ostatnich udziałów w konsoli jest ograniczenie liczby tokenów przy pracy nad projektem. Jest to drobna rzecz, prosta do zmiany w przypadku braku takiego ograniczenia.

## 6.3. Procedura odszyfrowania (Odzyskiwanie)
Aby odzyskać dostęp do pliku, należy uruchomić program z parametrem `decrypt`:
```bash
python main.py decrypt <ścieżka_do_pliku.enc>
```
**Przebieg procesu:**
1.  **Podłączenie tokenów:** Należy podłączyć minimum 3 tokeny uczestniczące w backupie.
2.  **Autoryzacja i Quorum:** Program automatycznie przeprowadzi proces autoryzacji, zbierze udziały odblokowujące, zrekonstruuje klucz dostępu i odblokuje tokeny.
3.  **Ekstrakcja i deszyfrowanie:** Po uzyskaniu potwierdzenia z tokenów, program pobierze udziały główne i odszyfruje plik do oryginalnej postaci.

#### Uwaga: Ścieżka do pliku zawsze powinna być albo absolutna (np. E:\pliki\plik.txt) albo względna w porównaniu do folderu `backup` (np. ..\pliki\plik.txt)

---

# 7. Testy i Wyniki

W celu weryfikacji poprawności działania systemu oraz skuteczności zaimplementowanych mechanizmów obronnych, przeprowadzono serię testów funkcjonalnych i negatywnych.

## 7.1. Metodyka testowania
Testy przeprowadzono w środowisku rzeczywistym przy użyciu trzech fizycznych tokenów RP2350 i komputera z systemem Windows. Jako kryterium sukcesu przyjęto poprawną rekonstrukcję kluczy w obu warstwach (odblokowującej i głównej) oraz pełne odszyfrowanie pliku testowego.

## 7.2. Wyniki testów funkcjonalnych i bezpieczeństwa

| Scenariusz testowy | Oczekiwany wynik | Wynik rzeczywisty 
| :--- | :--- | :--- 
| **Pełny cykl (3 z 3)** | Poprawna rekonstrukcja $K_{unlock}$ i $K_{data} \rightarrow$ odszyfrowanie pliku. | System poprawnie przeszedł przez wszystkie fazy i odzyskał dane. 
| **Brak Quorum (2 z 3)** | Brak możliwości odtworzenia $K_{unlock} \rightarrow$ proces przerywany. | Biblioteka SSS zgłosiła błąd braku wystarczającej liczby udziałów.
| **Atak "PC + 1 Token"** | Token odmawia wydania $S_i$ z powodu braku poprawnego $K_{unlock}$. | Token pozostał w stanie `UNLOCK_WAIT`, odrzucając próby wywołania `GET_SHARE`. 
| **Manipulacja szyfrowanym plikiem** | Wykrycie błędu spójności danych podczas deszyfrowania $\rightarrow$ błąd procesu. | Po modyfikacji bajtów w zaszyfrowanym pliku, proces deszyfrowania nie odtworzył oryginalnych danych. 
| **Błędna autoryzacja PC** | Odrzucenie żądania `AUTH` z powodu niepoprawnego HMAC. | Token odpowiedział `AUTH_FAIL` i powrócił do stanu `IDLE`. | 
| **Nieprawidłowe ID systemu** | Wykrycie niedopasowania `system_id` między tokenami. | Program na PC zidentyfikował niezgodność ID i przerwał proces. 

## 7.3. Wnioski z testów
Przeprowadzone testy potwierdzają, że system spełnia założenia modelu zagrożeń. W szczególności udowodniono, że wprowadzenie drugiej warstwy kluczy (Klucz Odblokowujący) skutecznie eliminuje ryzyko wycieku danych w przypadku przejęcia autoryzowanego komputera, o ile atakujący nie posiada fizycznego dostępu do wymaganego quorum tokenów.

Dodatkowo, w kodzie tokena zaimplementowano weryfikację HMAC dla pliku `share.bin`, co zapewnia wbudowaną ochronę przed manipulacją danymi w pamięci Flash urządzenia, nawet jeśli nie są one dostępne do edycji za pomocą standardowych narzędzi programistycznych.

---

# 8. Rozwinięcie Projektu

W obecnej wersji spełnia wszystkie kluczowe założenia modelu zagrożeń, jednak projekt nadal ma spore możliwości rozwoju.

## 8.1. Plan rozwoju na ostatni tydzień
W ostatnim tygodniu praktyk planuje wdrożyć poniższe funkcje:

*   **Wizualna sygnalizacja stanów (LED Indicators):** Wykorzystanie wbudowanych diod LED w mikrokontrolerze RP2350 do informowania użytkownika o aktualnym stanie tokena (np. miganie podczas oczekiwania na autoryzację, światło stałe po pomyślnym odblokowaniu quorum). Poprawi to doświadczenie użytkownika (UX) i ułatwi diagnostykę.
*   **Procedura samokontroli (Self-Test):** Wprowadzenie komendy diagnostycznej, która weryfikuje integralność pliku `share.bin` za pomocą zapisanego HMAC-a. Pozwoli to na wykrycie uszkodzenia danych w tokenie przed rozpoczęciem krytycznego procesu odzyskiwania sekretu.
*   **Konfigurowalne progi dostępu (Variable Thresholds):** Przejście z na sztywno zdefiniowanych wartości $k=3, n=5$ na model dynamiczny. Parametry progu i liczby udziałów będą przechowywane w metadanych systemu, co pozwoli na dostosowanie poziomu bezpieczeństwa do indywidualnych potrzeb użytkownika.

W szczególności skupię się na pierwszych dwóch punktach, a ostatni postaram się wykonać jeśli starczy czasu.

## 8.2. Możliwości długoterminowego rozwoju projektu
Poniższe mechanizmy to przykłady rozszerzeń projektu, dzięki którym projekt stałby się bezpieczniejszy i prostszy dla użytkownika: 

*   **Hardware Hardening (Secure Boot):** Wykorzystanie funkcji bezpiecznego rozruchu (Secure Boot) oraz szyfrowania pamięci Flash dostępnych w RP2350, aby uniemożliwić odczyt firmware'u i klucza `K_device` metodami sprzętowymi.
*   **Wieloskładnikowe uwierzytelnianie (MFA):** Dodanie drugiego czynnika autoryzacji (np. krótkiego kodu PIN wpisywanego przez użytkownika), który byłby weryfikowany przez token przed wydaniem udziału w kluczu odblokowującym.
*   **Interfejs Graficzny (GUI):** Zastąpienie interfejsu konsolowego (CLI) dedykowaną aplikacją okienkową, która w sposób wizualny prowadzi użytkownika przez procesy szyfrowania i deszyfrowania.
*   **Wsparcie dla standardów PKI:** Rozszerzenie systemu o możliwość wykorzystania kluczy asymetrycznych do autoryzacji połączenia między PC a tokenem.
