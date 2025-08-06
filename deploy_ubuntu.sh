#!/bin/bash

# ==============================================================================
# Skrypt do pełnego wdrożenia aplikacji Flask/Gunicorn z Nginx, SSL i Logowaniem
# Wersja ostateczna: dynamiczne workery, automatyczna obsługa HTTP/2 przez Certbot.
# Poprawiona wersja bez konfliktów GIT.
# ==============================================================================

# Zatrzymaj skrypt w przypadku błędu
set -e

# --- ZMIENNE KONFIGURACYJNE (dostosuj do swoich potrzeb) ---
SERVICE_NAME="mobywatel"
PROJECT_USER="mobywatel_user"
DEST_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
DOMAIN="gov-mobywatel.polcio.p5.tiktalik.io"
SSL_EMAIL="polciovps@atomicmail.io"
GUNICORN_WORKERS=$((2 * $(nproc) + 1))
CSP_HEADER="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self';"


echo ">>> START: Rozpoczynanie wdrożenia aplikacji $SERVICE_NAME..."
echo ">>> Katalog aplikacji (uruchomienie z źródła): $DEST_DIR"
echo ">>> Użyta liczba workerów Gunicorna: $GUNICORN_WORKERS"

# --- KROK 0: Utworzenie dedykowanego użytkownika (jeśli nie istnieje) ---
echo ">>> KROK 0: Sprawdzanie i tworzenie użytkownika systemowego $PROJECT_USER..."
if ! id "$PROJECT_USER" &>/dev/null; then
    sudo useradd -r -s /bin/false $PROJECT_USER
    echo "Użytkownik $PROJECT_USER został utworzony."
else
    echo "Użytkownik $PROJECT_USER już istnieje."
fi

# --- KROK 1: Instalacja podstawowych zależności ---
echo ">>> KROK 1: Instalowanie Nginx, Pip, Venv i Certbota..."
sudo apt-get update
sudo apt-get install -y nginx python3-pip python3-venv certbot python3-certbot-nginx redis-server

# Upewnij się, że Redis jest uruchomiony i włączony przy starcie systemu
echo ">>> Upewnianie się, że Redis jest uruchomiony i włączony..."
sudo systemctl start redis-server
sudo systemctl enable redis-server

# --- KROK 1.5: Dodanie użytkownika Nginx do grupy projektu ---
echo ">>> KROK 1.5: Dodawanie użytkownika www-data do grupy $PROJECT_USER..."
sudo usermod -aG $PROJECT_USER www-data

# --- KROK 2: Przygotowanie katalogu aplikacji ---
echo ">>> KROK 2: Ustawianie właściciela katalogu $DEST_DIR..."
sudo chown -R $PROJECT_USER:$PROJECT_USER $DEST_DIR

echo ">>> KROK 2.5: Tworzenie katalogu na logi..."
sudo mkdir -p $DEST_DIR/logs
sudo chown -R $PROJECT_USER:$PROJECT_USER $DEST_DIR/logs

echo ">>> KROK 2.6: Ustawianie bezpiecznych uprawnień do plików i folderów..."
sudo find $DEST_DIR -type d -exec chmod 750 {} \;
sudo find $DEST_DIR -type f -exec chmod 640 {} \;
sudo chmod +x $0

# --- KROK 3: Konfiguracja środowiska wirtualnego i zależności ---
echo ">>> KROK 3: Uruchamianie konfiguracji środowiska Python jako użytkownik $PROJECT_USER..."
sudo -u "$PROJECT_USER" bash -c "
set -e
echo '--- Tworzenie pliku .env z sekretami...'
cat > '$DEST_DIR/.env' <<EOF
SECRET_KEY=\$(openssl rand -hex 32)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=\$(openssl rand -hex 16)
EOF

echo '--- Tworzenie środowiska w
