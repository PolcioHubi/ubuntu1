#!/bin/bash

# ==============================================================================
# Skrypt do pełnego wdrożenia aplikacji Flask/Gunicorn z Nginx, SSL i Logowaniem
# Wersja ostateczna: dynamiczne workery, automatyczna obsługa HTTP/2 przez Certbot.
# Zawiera wszystkie poprawki: uprawnienia, cache, bezpieczny Nginx i wczytywanie .env
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
<<<<<<< HEAD
CSP_HEADER="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self';"
=======
CSP_HEADER="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self';"
>>>>>>> dc94dc1a97b11b00aad043884c7595daea55a521


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

echo '--- Tworzenie środowiska wirtualnego w $DEST_DIR/venv...'
python3 -m venv '$DEST_DIR/venv'

chmod -R +x '$DEST_DIR/venv/bin'

echo '--- Aktualizacja pip i instalacja zależności z requirements.txt...'
'$DEST_DIR/venv/bin/pip' install --upgrade pip
'$DEST_DIR/venv/bin/pip' install -r '$DEST_DIR/requirements.txt'

echo '--- Wykonywanie migracji bazy danych...'
'$DEST_DIR/venv/bin/flask' --app '$DEST_DIR/wsgi.py' db upgrade
"

# --- KROK 4: Konfiguracja usługi Systemd dla Gunicorn ---
echo ">>> KROK 4: Tworzenie pliku usługi /etc/systemd/system/${SERVICE_NAME}.service..."
sudo rm -f /etc/systemd/system/${SERVICE_NAME}.service
# ==============================================================================
# OSTATNIA POPRAWKA: Dodanie EnvironmentFile, aby usługa wczytała .env
# ==============================================================================
sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<EOF
[Unit]
Description=Gunicorn instance to serve $SERVICE_NAME
After=network.target

[Service]
User=$PROJECT_USER
Group=$PROJECT_USER
WorkingDirectory=$DEST_DIR
EnvironmentFile=$DEST_DIR/.env
Environment="PATH=$DEST_DIR/venv/bin"
Environment="FLASK_ENV=production"
ExecStart=$DEST_DIR/venv/bin/gunicorn --workers $GUNICORN_WORKERS --bind unix:$DEST_DIR/${SERVICE_NAME}.sock -m 007 --access-logfile $DEST_DIR/logs/gunicorn_access.log --error-logfile $DEST_DIR/logs/gunicorn_error.log wsgi:application
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# --- KROK 5: Konfiguracja Nginx (WSTĘPNA, tylko HTTP) ---
echo ">>> KROK 5: Tworzenie WSTĘPNEJ konfiguracji Nginx dla domeny $DOMAIN (tylko port 80)..."
sudo rm -f /etc/nginx/sites-available/$SERVICE_NAME
sudo rm -f /etc/nginx/sites-enabled/$SERVICE_NAME

printf 'proxy_cache_path /var/cache/nginx/mobywatel_cache levels=1:2 keys_zone=mobywatel_cache:10m max_size=1g inactive=60m use_temp_path=off;

server {
    listen 80;
    listen [::]:80;
    server_name %s;

    location / {
        proxy_cache mobywatel_cache;
        proxy_cache_valid 200 10m;
        proxy_cache_revalidate on;
        proxy_cache_min_uses 1;
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
        proxy_cache_background_update on;
        proxy_ignore_headers Cache-Control Expires Set-Cookie;
        add_header X-Proxy-Cache \$upstream_cache_status;

        proxy_pass http://unix:%s/%s.sock;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "no-referrer-when-downgrade" always;
        add_header Content-Security-Policy "%s" always;
    }

    location /static {
        alias %s/static;
    }

    access_log %s/logs/nginx_access.log;
    error_log %s/logs/nginx_error.log;
}
' "$DOMAIN" "$DEST_DIR" "$SERVICE_NAME" "$CSP_HEADER" "$DEST_DIR" "$DEST_DIR" "$DEST_DIR" | sudo tee /etc/nginx/sites-available/$SERVICE_NAME > /dev/null

echo ">>> KROK 5.5: Tworzenie katalogu cache dla Nginx..."
sudo mkdir -p /var/cache/nginx/mobywatel_cache
sudo chown -R www-data:www-data /var/cache/nginx/mobywatel_cache

# Włącz nową konfigurację i usuń domyślną
sudo ln -sf /etc/nginx/sites-available/$SERVICE_NAME /etc/nginx/sites-enabled/
if [ -f /etc/nginx/sites-enabled/default ]; then
    sudo rm /etc/nginx/sites-enabled/default
fi

# --- KROK 6: Uruchomienie usług ---
echo ">>> KROK 6: Przeładowanie i uruchomienie usług..."
sudo systemctl daemon-reload
sudo systemctl restart $SERVICE_NAME
sudo systemctl enable $SERVICE_NAME

# Sprawdzenie konfiguracji Nginx i restart
echo ">>> Sprawdzanie i restartowanie Nginx..."
sudo nginx -t
sudo systemctl restart nginx

# --- KROK 7: Konfiguracja SSL i HTTP/2 za pomocą Certbota ---
echo ">>> KROK 7: Uruchamianie Certbota dla $DOMAIN..."
sudo certbot --nginx --non-interactive --agree-tos -m "$SSL_EMAIL" -d "$DOMAIN" --redirect

# Certbot sam przeładowuje Nginx
sudo systemctl restart nginx

echo
echo "----------------------------------------------------"
echo "✅ WDROŻENIE ZAKOŃCZONE POMYŚLNIE!"
echo "Twoja strona powinna być dostępna pod adresem: https://$DOMAIN"
echo "Logi aplikacji znajdziesz w: $DEST_DIR/logs/"
echo "----------------------------------------------------"
