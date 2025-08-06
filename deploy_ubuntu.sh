#!/bin/bash

# ==============================================================================
# Skrypt do pełnego wdrożenia aplikacji Flask/Gunicorn z Nginx, SSL i Logowaniem
# WERSJA OSTATECZNA PANCERNA v3 (2025-08-06)
# Rozwiązuje problem z nagłówkami bezpieczeństwa (HSTS) po modyfikacji przez Certbot
# poprzez wstrzyknięcie pliku z nagłówkami PO działaniu Certbota.
# ==============================================================================

# Zatrzymaj skrypt w przypadku błędu
set -e

# --- ZMIENNE KONFIGURACYJNE ---
SERVICE_NAME="mobywatel"
PROJECT_USER="mobywatel_user"
DEST_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
DOMAIN="gov-mobywatel.polcio.p5.tiktalik.io"
SSL_EMAIL="polciovps@atomicmail.io"
GUNICORN_WORKERS=$((2 * $(nproc) + 1))
CSP_HEADER="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self';"


echo ">>> START: Rozpoczynanie wdrożenia aplikacji $SERVICE_NAME..."
# ... (reszta skryptu pozostaje bez zmian aż do KROKU 4.5)

# --- KROK 0 do 3 pozostają identyczne ---
echo ">>> KROK 0: Sprawdzanie i tworzenie użytkownika systemowego $PROJECT_USER..."
if ! id "$PROJECT_USER" &>/dev/null; then
    sudo useradd -r -s /bin/false $PROJECT_USER
    echo "Użytkownik $PROJECT_USER został utworzony."
else
    echo "Użytkownik $PROJECT_USER już istnieje."
fi
echo ">>> KROK 1: Instalowanie Nginx, Pip, Venv i Certbota..."
sudo apt-get update
sudo apt-get install -y nginx python3-pip python3-venv certbot python3-certbot-nginx redis-server
echo ">>> Upewnianie się, że Redis jest uruchomiony i włączony..."
sudo systemctl start redis-server
sudo systemctl enable redis-server
echo ">>> KROK 1.5: Dodawanie użytkownika www-data do grupy $PROJECT_USER..."
sudo usermod -aG $PROJECT_USER www-data
echo ">>> KROK 2: Przygotowanie katalogu aplikacji ..."
sudo chown -R $PROJECT_USER:$PROJECT_USER $DEST_DIR
sudo mkdir -p $DEST_DIR/logs
sudo chown -R $PROJECT_USER:$PROJECT_USER $DEST_DIR/logs
sudo find $DEST_DIR -type d -exec chmod 750 {} \;
sudo find $DEST_DIR -type f -exec chmod 640 {} \;
sudo chmod +x $0
echo ">>> KROK 3: Uruchamianie konfiguracji środowiska Python..."
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
rm -rf '$DEST_DIR/migrations'
rm -f '$DEST_DIR/auth_data/database.db'
'$DEST_DIR/venv/bin/flask' --app '$DEST_DIR/wsgi.py' db init
'$DEST_DIR/venv/bin/flask' --app '$DEST_DIR/wsgi.py' db migrate -m 'Initial deployment migration'
'$DEST_DIR/venv/bin/flask' --app '$DEST_DIR/wsgi.py' db upgrade
"
echo ">>> KROK 4: Konfiguracja usługi Systemd dla Gunicorn..."
sudo rm -f /etc/systemd/system/${SERVICE_NAME}.service
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

# --- KROK 4.5: Tworzenie dedykowanego pliku z nagłówkami bezpieczeństwa ---
echo ">>> KROK 4.5: Tworzenie pliku z nagłówkami bezpieczeństwa..."
sudo mkdir -p /etc/nginx/snippets
sudo tee /etc/nginx/snippets/security-headers.conf > /dev/null <<EOF
# HSTS (max-age = 2 lata), wymusza HTTPS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
# Ochrona przed MIME sniffing
add_header X-Content-Type-Options "nosniff" always;
# Ochrona przed clickjacking
add_header X-Frame-Options "SAMEORIGIN" always;
# Ulepszona polityka Referrer
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
# Blokowanie niechcianych funkcji przeglądarki
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
# Polityka bezpieczeństwa treści
add_header Content-Security-Policy "$CSP_HEADER" always;
EOF

# --- KROK 5: Konfiguracja Nginx (WSTĘPNA, tylko HTTP) ---
echo ">>> KROK 5: Tworzenie WSTĘPNEJ konfiguracji Nginx dla domeny $DOMAIN (tylko port 80)..."
sudo rm -f /etc/nginx/sites-available/$SERVICE_NAME
sudo rm -f /etc/nginx/sites-enabled/$SERVICE_NAME

# Tym razem tworzymy BARDZO prostą konfigurację, bez żadnych nagłówków.
# Chodzi tylko o to, żeby Certbot ją znalazł i poprawnie zmodyfikował.
sudo tee /etc/nginx/sites-available/$SERVICE_NAME > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    location / {
        proxy_pass http://unix:$DEST_DIR/${SERVICE_NAME}.sock;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

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

# ==============================================================================
# OSTATECZNA POPRAWKA: Wstrzykujemy nasze nagłówki PO tym, jak Certbot skończył pracę.
# ==============================================================================
echo ">>> KROK 8: Wstrzykiwanie ostatecznych nagłówków bezpieczeństwa do konfiguracji SSL..."
CONFIG_FILE="/etc/nginx/sites-available/$SERVICE_NAME"
# Używamy sed do wstawienia linii 'include ...' zaraz po linii 'server_name ...'
sudo sed -i "/server_name $DOMAIN/a include /etc/nginx/snippets/security-headers.conf;" $CONFIG_FILE

# --- KROK 9: Ostateczny restart Nginx ---
echo ">>> KROK 9: Ostateczny restart Nginx w celu załadowania pancernych nagłówków..."
sudo systemctl restart nginx

echo
echo "----------------------------------------------------"
echo "✅ WDROŻENIE PANCERNE v3 ZAKOŃCZONE POMYŚLNIE!"
echo "Twoja strona powinna być dostępna pod adresem: https://$DOMAIN"
echo "Sprawdź jej ocenę bezpieczeństwa na https://securityheaders.com/ i https://www.ssllabs.com/ssltest/"
echo "----------------------------------------------------"
