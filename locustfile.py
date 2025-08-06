# locustfile.py - Wersja w pełni zautomatyzowana
import os
import requests
from locust import HttpUser, task, between, events
from bs4 import BeautifulSoup

# --- Konfiguracja Testu ---
# Dane logowania admina - odczytywane ze zmiennych środowiskowych
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "password")

# Dane użytkownika, który będzie tworzony na czas testu
TEST_USERNAME = "locust_test_user"
TEST_PASSWORD = "password123"

# Globalna sesja dla operacji setup/teardown
setup_session = requests.Session()


def get_csrf_token(text):
    """Pomocnicza funkcja do ekstrakcji tokenu CSRF z HTML."""
    soup = BeautifulSoup(text, "html.parser")
    token_tag = soup.find("input", {"name": "csrf_token"})
    if not token_tag or not token_tag.get("value"):
        raise Exception("Nie znaleziono tokenu CSRF na stronie")
    return token_tag.get("value")

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Wykonuje się raz na początku całego testu. Przygotowuje środowisko."""
    print("--- Faza Setup: Przygotowywanie użytkownika testowego ---")
    host = environment.host

    # 1. Zaloguj się jako admin
    print(f"Logowanie jako admin: {ADMIN_USER}...")
    login_page = setup_session.get(f"{host}/admin/login")
    csrf_token = get_csrf_token(login_page.text)
    
    admin_login_res = setup_session.post(
        f"{host}/admin/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASSWORD},
        headers={"X-CSRFToken": csrf_token}
    )
    if admin_login_res.status_code != 200 or not admin_login_res.json().get("success"):
        raise Exception(f"Nie udało się zalogować jako admin: {admin_login_res.text}")
    print("Logowanie admina pomyślne.")

    # 2. Wygeneruj klucz dostępu
    print("Generowanie klucza dostępu...")
    # Potrzebujemy nowego tokenu CSRF z panelu admina
    admin_panel_page = setup_session.get(f"{host}/admin/")
    csrf_token = get_csrf_token(admin_panel_page.text)

    key_res = setup_session.post(
        f"{host}/admin/api/generate-access-key",
        json={"description": "Klucz dla testu Locust", "validity_days": 1},
        headers={"X-CSRFToken": csrf_token}
    )
    access_key = key_res.json()["access_key"]
    print(f"Wygenerowano klucz: {access_key[:10]}...")

    # 3. Zarejestruj użytkownika testowego
    print(f"Rejestrowanie użytkownika: {TEST_USERNAME}...")
    register_page = setup_session.get(f"{host}/register")
    csrf_token = get_csrf_token(register_page.text)

    reg_res = setup_session.post(
        f"{host}/register",
        json={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
            "access_key": access_key
        },
        headers={"X-CSRFToken": csrf_token}
    )
    if not reg_res.json().get("success"):
        raise Exception(f"Nie udało się zarejestrować użytkownika testowego: {reg_res.text}")
    print("Użytkownik testowy zarejestrowany pomyślnie.")
    print("--- Faza Setup zakończona ---")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Wykonuje się raz po zakończeniu całego testu. Sprząta po sobie."""
    print("--- Faza Teardown: Sprzątanie po teście ---")
    host = environment.host

    # 1. Zaloguj się ponownie jako admin (sesja mogła wygasnąć)
    print("Logowanie jako admin w celu sprzątania...")
    login_page = setup_session.get(f"{host}/admin/login")
    csrf_token = get_csrf_token(login_page.text)
    setup_session.post(
        f"{host}/admin/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASSWORD},
        headers={"X-CSRFToken": csrf_token}
    )

    # 2. Usuń użytkownika testowego
    print(f"Usuwanie użytkownika: {TEST_USERNAME}...")
    admin_panel_page = setup_session.get(f"{host}/admin/")
    csrf_token = get_csrf_token(admin_panel_page.text)
    del_res = setup_session.delete(
        f"{host}/admin/api/delete-registered-user/{TEST_USERNAME}?delete_files=true",
        headers={"X-CSRFToken": csrf_token}
    )
    if del_res.status_code == 200 and del_res.json().get("success"):
        print("Użytkownik testowy usunięty pomyślnie.")
    else:
        print(f"OSTRZEŻENIE: Nie udało się usunąć użytkownika testowego. Status: {del_res.status_code}, Odpowiedź: {del_res.text}")
    print("--- Faza Teardown zakończona ---")


class TestUserBehavior(HttpUser):
    """Definiuje zachowanie symulowanego użytkownika podczas testu."""
    wait_time = between(1, 3)
    host = "http://127.0.0.1:5000"

    def on_start(self):
        """Loguje każdego wirtualnego użytkownika na początku jego sesji."""
        login_page = self.client.get("/login")
        self.csrf_token = get_csrf_token(login_page.text)
        self.client.post(
            "/login",
            json={"username": TEST_USERNAME, "password": TEST_PASSWORD},
            headers={"X-CSRFToken": self.csrf_token}
        )

    @task
    def generate_document(self):
        """Główne zadanie: generowanie dokumentu."""
        self.client.post(
            "/",
            data={
                "user_name": TEST_USERNAME,
                "imie": "LOCUST",
                "nazwisko": "PERFORMANCE_TEST"
            },
            headers={"X-CSRFToken": self.csrf_token},
            name="/generate_document"
        )
