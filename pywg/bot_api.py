# bot_api.py
import io
import re
from pathlib import Path
from typing import Optional, List, Set

import qrcode
import requests
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, ContextTypes

# ========= НАСТРОЙКИ =========
# ВАЖНО: Заполните эти переменные в .env файле или передайте как переменные окружения
BOT_TOKEN = os.getenv("BOT_TOKEN", "")          # Ваш bot token от BotFather
WG_API_BASE = os.getenv("WG_API_BASE", "http://127.0.0.1:51821/api")  # URL WG-Easy API
WG_PASSWORD = os.getenv("WG_PASSWORD", "")      # Пароль доступа к WG-Easy

# лимит конфигов на пользователя
MAX_CONFIGS_PER_USER = int(os.getenv("MAX_CONFIGS_PER_USER", "4"))
ADMIN_ALLOW_USERNAME = "@spotlog"  # Измените на вашего admin username

# файл со списком разрешённых @usernames (по строке; @ можно не писать)
ALLOWED_FILE = Path(__file__).parent / "allowed_users.txt"
UNLIMITED_FILE = Path(__file__).parent / "unlimited_users.txt"

# ========= УТИЛИТЫ / АВТОРИЗАЦИЯ =========
class WGEasyAPI:
    """
    Клиент для WG-Easy:
      - Логин по паролю -> cookie connect.sid
      - Список клиентов:       GET   /api/wireguard/client
      - Создать клиента:       POST  /api/wireguard/client {name}
      - Скачать конфиг:        GET   /api/wireguard/client/{id}/configuration
      - (Удалить клиента):     DELETE/api/wireguard/client/{id}
    """

    def __init__(self, base: str, password: str):
        self.base = base.rstrip("/")
        self.password = password
        self.s = requests.Session()
        self._login()

    def _login(self):
        r = self.s.post(
            f"{self.base}/session",
            json={"password": self.password},
            timeout=20,
        )
        if r.status_code not in (200, 204):
            raise RuntimeError(f"WG-Easy login failed: {r.status_code} {r.text}")

        # проверим, что сессия активна
        r2 = self.s.get(f"{self.base}/session", timeout=20)
        if r2.status_code != 200 or not r2.json().get("authenticated", False):
            raise RuntimeError("WG-Easy session not authenticated")

    def _req(self, method: str, path: str, **kw) -> requests.Response:
        """
        Запрос с автоперелогином на случай просрочки cookie.
        """
        url = f"{self.base}{path}"
        r = self.s.request(method, url, timeout=30, **kw)
        if r.status_code == 401:
            # пробуем перезалогиниться и повторить один раз
            self._login()
            r = self.s.request(method, url, timeout=30, **kw)
        return r

    # --- API методы ---
    def list_clients(self) -> list[dict]:
        r = self._req("GET", "/wireguard/client")
        if r.status_code not in (200, 204):
            raise RuntimeError(f"List clients error: {r.status_code} {r.text}")
        return r.json()

    def create_client(self, name: str) -> dict:
        r = self._req("POST", "/wireguard/client", json={"name": name})
        if r.status_code not in (200, 204):
            raise RuntimeError(f"Create client error: {r.status_code} {r.text}")
        return r.json()

    def get_configuration(self, client_id: str) -> str:
        r = self._req("GET", f"/wireguard/client/{client_id}/configuration")
        if r.status_code not in (200, 204):
            raise RuntimeError(f"Get configuration error: {r.status_code} {r.text}")
        return r.text

    # опционально:
    # def delete_client(self, client_id: str) -> dict:
    #     r = self._req("DELETE", f"/wireguard/client/{client_id}")
    #     if r.status_code not in (200, 204):
    #         raise RuntimeError(f"Delete client error: {r.status_code} {r.text}")
    #     return r.json()


# ========= ВСПОМОЩНИКИ =========
def normalize_username(name: str) -> str:
    name = (name or "").strip()
    if not name:
        return ""
    return name if name.startswith("@") else f"@{name}"

def load_allowed_usernames() -> Set[str]:
    allowed: Set[str] = set()
    if ALLOWED_FILE.exists():
        for line in ALLOWED_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                allowed.add(normalize_username(line))
    return allowed

def load_unlimited_usernames() -> Set[str]:
    s: Set[str] = set()
    if UNLIMITED_FILE.exists():
        for line in UNLIMITED_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                s.add(normalize_username(line))
    return s

def is_unlimited(user) -> bool:
    return bool(user and user.username and normalize_username(user.username) in load_unlimited_usernames())

def max_configs_for(username_at: str) -> Optional[int]:
    """None => без лимита, иначе конкретное число."""
    unlim = load_unlimited_usernames()
    return None if normalize_username(username_at) in unlim else MAX_CONFIGS_PER_USER

def is_allowed(user) -> bool:
    return bool(user and user.username and normalize_username(user.username) in load_allowed_usernames())

def is_admin(user) -> bool:
    return bool(user and user.username and normalize_username(user.username) == ADMIN_ALLOW_USERNAME)

def add_allowed_username(username_at: str) -> bool:
    """Return True if added, False if already existed."""
    username_at = normalize_username(username_at)
    if not username_at:
        raise ValueError("Пустой username")
    if not re.fullmatch(r"@[A-Za-z0-9_]{5,32}", username_at):
        raise ValueError("Некорректный username")

    existing = load_allowed_usernames()
    if username_at in existing:
        return False

    ALLOWED_FILE.parent.mkdir(parents=True, exist_ok=True)

    prefix = ""
    if ALLOWED_FILE.exists() and ALLOWED_FILE.stat().st_size > 0:
        with ALLOWED_FILE.open("rb") as check_f:
            check_f.seek(-1, 2)
            if check_f.read(1) != b"\n":
                prefix = "\n"

    with ALLOWED_FILE.open("a", encoding="utf-8") as f:
        f.write(prefix + username_at + "\n")
    return True

def _to_int(v) -> int:
    try:
        return int(v)
    except Exception:
        return 0

def _client_total_bytes(c: dict) -> int:
    """Best-effort extraction of total bytes from wg-easy client payload."""
    # Common flat keys across wg-easy versions.
    rx_keys = ["transferRx", "receivedBytes", "rxBytes", "totalRx", "rx"]
    tx_keys = ["transferTx", "sentBytes", "txBytes", "totalTx", "tx"]

    rx = 0
    tx = 0
    for k in rx_keys:
        if k in c:
            rx = _to_int(c.get(k))
            break
    for k in tx_keys:
        if k in c:
            tx = _to_int(c.get(k))
            break

    # Some versions may have nested transfer object.
    transfer = c.get("transfer")
    if isinstance(transfer, dict):
        if rx == 0:
            rx = _to_int(transfer.get("rx") or transfer.get("received") or transfer.get("download"))
        if tx == 0:
            tx = _to_int(transfer.get("tx") or transfer.get("sent") or transfer.get("upload"))

    return max(0, rx) + max(0, tx)

def read_usage_from_api(api: WGEasyAPI) -> List[tuple[str, int]]:
    """Return list of (wg_name, total_bytes) from wg-easy API payload."""
    rows: List[tuple[str, int]] = []
    for c in api.list_clients():
        if not isinstance(c, dict):
            continue
        name = str(c.get("name") or "unknown")
        total = _client_total_bytes(c)
        rows.append((name, total))
    rows.sort(key=lambda x: x[1], reverse=True)
    return rows

def human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    val = float(max(0, n))
    idx = 0
    while val >= 1024 and idx < len(units) - 1:
        val /= 1024
        idx += 1
    return f"{val:.2f} {units[idx]}"

def conf_to_qr_png_bytes(conf_text: str) -> bytes:
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_Q)
    qr.add_data(conf_text)
    qr.make(fit=True)
    img = qr.make_image()
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

async def send_conf_and_qr(chat_id: int, filename: str, conf_text: str, app, caption_prefix: str = ""):
    file_buf = io.BytesIO(conf_text.encode())
    file_buf.name = filename
    await app.bot.send_document(
        chat_id=chat_id,
        document=InputFile(file_buf, filename=filename),
        caption=(caption_prefix + "Импортируйте в приложение WireGuard.").strip()
    )
    png = conf_to_qr_png_bytes(conf_text)
    await app.bot.send_photo(chat_id=chat_id, photo=png, caption="QR для быстрого импорта")


# ========= КЛАВИАТУРА =========
def api_user_clients(api: WGEasyAPI, username_at: str) -> List[dict]:
    uname_plain = username_at.replace("@", "")
    return [c for c in api.list_clients() if c.get("name", "").startswith(uname_plain + "#")]

def list_user_ordinals(api: WGEasyAPI, username_at: str) -> List[int]:
    ords: List[int] = []
    for c in api_user_clients(api, username_at):
        m = re.search(r"#(\d+)$", c.get("name", ""))
        if m:
            try:
                ords.append(int(m.group(1)))
            except:
                pass
    return sorted(ords)

def next_ordinal(api: WGEasyAPI, username_at: str) -> int:
    ords = list_user_ordinals(api, username_at)
    return (max(ords) + 1) if ords else 1

def _chunk(lst, n):
    return [lst[i:i+n] for i in range(0, len(lst), n)]

def make_keyboard_for_user(api: WGEasyAPI, username_at: str) -> InlineKeyboardMarkup:
    ords = list_user_ordinals(api, username_at)
    limit = max_configs_for(username_at)

    num_buttons = [InlineKeyboardButton(f"#{n}", callback_data=f"get_n:{n}") for n in ords]
    rows = _chunk(num_buttons, 4)  # по 4 в ряд

    if limit is None or len(ords) < limit:
        next_n = next_ordinal(api, username_at)
        rows.append([InlineKeyboardButton(f"➕ Новый (#{next_n})", callback_data="new_conf")])

    if not rows:
        rows = [[InlineKeyboardButton("➕ Новый (#1)", callback_data="new_conf")]]

    return InlineKeyboardMarkup(rows)

def greeting_text() -> str:
    return (
        "Привет! Это бот для выдачи WireGuard-конфигов через WG-Easy.\n\n"
        "• Нажмите номер, чтобы получить нужный конфиг (#1, #2, ...),\n"
        "• или «Новый», чтобы создать следующий.\n\n"
        "Команды:\n"
        "/start - открыть меню\n"
        "/get N - получить конфиг #N\n"
        "/new - создать новый конфиг\n"
        "/usage - показать расход трафика по клиентам\n"
        "/allow @username - добавить в allowed (только @spotlog)\n"
        "/help - показать эту подсказку\n"
    )

# ========= ТЕЛЕГРАМ ЛОГИКА =========
async def ensure_access_or_inform(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Optional[str]:
    user = update.effective_user
    chat_id = update.effective_chat.id
    if not is_allowed(user):
        await context.bot.send_message(chat_id=chat_id, text="Нет доступа. Обратитесь к Админисатртору для добавления вашего тг ника")
        return None
    return normalize_username(user.username)

async def handle_get_by_number(update: Update, context: ContextTypes.DEFAULT_TYPE, api: WGEasyAPI, num: int):
    uname = await ensure_access_or_inform(update, context)
    if not uname:
        return
    chat_id = update.effective_chat.id
    try:
        uname_plain = uname.replace("@", "")
        clients = api_user_clients(api, uname)
        # точное имя username#N
        target_name = f"{uname_plain}#{num}"
        for c in clients:
            if c.get("name") == target_name:
                conf_text = api.get_configuration(c["id"])
                await send_conf_and_qr(chat_id, f"{target_name}.conf", conf_text, context.application,
                                       caption_prefix=f"Конфиг для {uname} #{num}. ")
                break
        else:
            await context.bot.send_message(chat_id=chat_id, text=f"Конфиг #{num} для {uname} не найден.")
    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"Ошибка: {e}")
    await context.bot.send_message(chat_id=chat_id, text="Ваши конфиги:", reply_markup=make_keyboard_for_user(api, uname))

async def handle_new(update: Update, context: ContextTypes.DEFAULT_TYPE, api: WGEasyAPI):
    uname = await ensure_access_or_inform(update, context)
    if not uname:
        return
    chat_id = update.effective_chat.id
    try:
        ords = list_user_ordinals(api, uname)
        limit = max_configs_for(uname)
        if limit is not None and len(ords) >= limit:
            await context.bot.send_message(chat_id=chat_id, text=f"Достигнут лимит {limit} конфигов.")
            return
        new_n = next_ordinal(api, uname)
        uname_plain = uname.replace("@", "")
        client_name = f"{uname_plain}#{new_n}"

        # создаём клиента
        api.create_client(client_name)

        # ищем его в списке
        clients = api_user_clients(api, uname)
        client = next((c for c in clients if c.get("name") == client_name), None)
        if not client:
            await context.bot.send_message(chat_id=chat_id, text="Ошибка: клиент создан, но не найден в списке.")
            return

        conf_text = api.get_configuration(client["id"])
        await send_conf_and_qr(chat_id, f"{client_name}.conf", conf_text, context.application,
                               caption_prefix=f"Новый конфиг для {uname} #{new_n}. ")
    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"Ошибка: {e}")
    await context.bot.send_message(chat_id=chat_id, text="Ваши конфиги:", reply_markup=make_keyboard_for_user(api, uname))

# ========= ХЕНДЛЕРЫ =========
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # инициализируем API-клиент и кладём в bot_data (чтобы переиспользовать один сеанс)
    if "api" not in context.bot_data:
        context.bot_data["api"] = WGEasyAPI(WG_API_BASE, WG_PASSWORD)

    api: WGEasyAPI = context.bot_data["api"]
    uname = await ensure_access_or_inform(update, context)
    if not uname:
        return
    await update.message.reply_text(greeting_text(), reply_markup=make_keyboard_for_user(api, uname))

async def on_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if "api" not in context.bot_data:
        context.bot_data["api"] = WGEasyAPI(WG_API_BASE, WG_PASSWORD)
    api: WGEasyAPI = context.bot_data["api"]

    uname = normalize_username(update.effective_user.username or "")
    if not is_allowed(update.effective_user):
        await q.edit_message_text("Нет доступа.")
        return

    data = q.data or ""
    if data == "new_conf":
        await handle_new(update, context, api)
    elif data.startswith("get_n:"):
        try:
            num = int(data.split(":")[1])
        except Exception:
            num = 1
        await handle_get_by_number(update, context, api, num)

async def get_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if "api" not in context.bot_data:
        context.bot_data["api"] = WGEasyAPI(WG_API_BASE, WG_PASSWORD)
    api: WGEasyAPI = context.bot_data["api"]

    n = 1
    if context.args:
        try:
            n = int(context.args[0])
        except Exception:
            pass
    await handle_get_by_number(update, context, api, n)

async def new_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if "api" not in context.bot_data:
        context.bot_data["api"] = WGEasyAPI(WG_API_BASE, WG_PASSWORD)
    api: WGEasyAPI = context.bot_data["api"]
    await handle_new(update, context, api)

async def usage_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not (is_allowed(update.effective_user) or is_admin(update.effective_user)):
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="Нет доступа к /usage",
        )
        return

    try:
        if "api" not in context.bot_data:
            context.bot_data["api"] = WGEasyAPI(WG_API_BASE, WG_PASSWORD)
        api: WGEasyAPI = context.bot_data["api"]

        rows = read_usage_from_api(api)
        top_n = 30
        total = sum(v for _, v in rows)
        lines = [
            "WG usage (накопительный, с последнего рестарта интерфейса):",
            f"Всего: {human_bytes(total)}",
            "",
        ]
        if not rows:
            lines.append("Нет данных по клиентам")
        else:
            for i, (name, b) in enumerate(rows[:top_n], start=1):
                lines.append(f"{i}. {name}: {human_bytes(b)}")
            if len(rows) > top_n:
                lines.append(f"... и еще {len(rows) - top_n}")

        await context.bot.send_message(chat_id=update.effective_chat.id, text="\n".join(lines))
    except Exception as e:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Ошибка /usage: {e}")

async def allow_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user):
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="Только @spotlog может добавлять пользователей",
        )
        return

    if not context.args:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="Использование: /allow username или /allow @username",
        )
        return

    target = normalize_username(context.args[0])
    try:
        created = add_allowed_username(target)
        if created:
            msg = f"Добавлен в allowed_users: {target}"
        else:
            msg = f"Уже есть в allowed_users: {target}"
        await context.bot.send_message(chat_id=update.effective_chat.id, text=msg)
    except Exception as e:
        err = str(e)
        if "Read-only file system" in err:
            err = "allowed_users.txt смонтирован в read-only. Уберите :ro в docker-compose для /app/allowed_users.txt"
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Ошибка /allow: {err}")

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_message(chat_id=update.effective_chat.id, text=greeting_text())


# ========= ЗАПУСК =========
def run_bot():
    if not BOT_TOKEN or not WG_PASSWORD:
        raise RuntimeError("BOT_TOKEN и WG_PASSWORD должны быть установлены в переменных окружения!")
    
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(on_button))
    app.add_handler(CommandHandler("get", get_cmd))
    app.add_handler(CommandHandler("new", new_cmd))
    app.add_handler(CommandHandler("usage", usage_cmd))
    app.add_handler(CommandHandler("allow", allow_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    app.run_polling()

if __name__ == "__main__":
    # зависимости: python-telegram-bot==21.4, qrcode, pillow, requests
    import os  # add missing import
    run_bot()
