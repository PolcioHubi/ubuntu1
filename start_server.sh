SCRIPT_DIR=$(dirname "$0")

# Check if virtual environment exists
if [ ! -d "$SCRIPT_DIR/venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$SCRIPT_DIR/venv"
fi

# Activate virtual environment
source "$SCRIPT_DIR/venv/bin/activate"

# Install dependencies
echo "Installing dependencies..."
pip install -r "$SCRIPT_DIR/requirements.txt"

# Create necessary directories
mkdir -p "$SCRIPT_DIR/logs"
mkdir -p "$SCRIPT_DIR/user_data"

# Set permissions
chmod +x "$SCRIPT_DIR/wsgi.py"

# Start the application with Gunicorn
echo "Starting server with Gunicorn..."
echo "Application will be available at: http://your-server-ip:5000"
echo "Press Ctrl+C to stop the server"

"$SCRIPT_DIR/venv/bin/gunicorn" --config "$SCRIPT_DIR/gunicorn_config.py" "$SCRIPT_DIR/wsgi:app"
