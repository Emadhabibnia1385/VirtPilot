import os
import asyncio
import re
import math
from typing import Any, Dict, List, Optional, Tuple, Union

import aiohttp
import aiosqlite
from dotenv import load_dotenv

from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart
from aiogram.types import (
    Message, CallbackQuery,
    ReplyKeyboardMarkup, KeyboardButton,
    InlineKeyboardMarkup, InlineKeyboardButton
)
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup


# =========================
# ENV
# =========================
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
CHECK_INTERVAL_SECONDS = int(os.getenv("CHECK_INTERVAL_SECONDS", "300"))

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is missing. Put it in .env")

DB_PATH = "bot.db"


# =========================
# FSM
# =========================
class AddProfile(StatesGroup):
    title = State()
    panel_url = State()
    api_key = State()
    api_pass = State()
    verify_ssl = State()

class SetThresholds(StatesGroup):
    disk_warn = State()
    disk_critical = State()
    bw_warn = State()
    bw_critical = State()


# =========================
# DB
# =========================
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        CREATE TABLE IF NOT EXISTS api_profiles(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            panel_url TEXT NOT NULL,
            api_key TEXT NOT NULL,
            api_pass TEXT NOT NULL,
            verify_ssl INTEGER NOT NULL DEFAULT 1
        )
        """)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS alert_settings(
            user_id INTEGER PRIMARY KEY,
            alerts_enabled INTEGER NOT NULL DEFAULT 1,
            disk_warn INTEGER NOT NULL DEFAULT 80,
            disk_critical INTEGER NOT NULL DEFAULT 100,
            bw_warn INTEGER NOT NULL DEFAULT 80,
            bw_critical INTEGER NOT NULL DEFAULT 100,
            suspend_alerts INTEGER NOT NULL DEFAULT 1
        )
        """)
        await db.execute("""
        CREATE TABLE IF NOT EXISTS alert_state(
            user_id INTEGER NOT NULL,
            profile_id INTEGER NOT NULL,
            vps_id TEXT NOT NULL,
            last_disk_level TEXT,
            last_bw_level TEXT,
            last_suspend INTEGER,
            PRIMARY KEY(user_id, profile_id, vps_id)
        )
        """)
        await db.commit()

async def ensure_alert_settings(user_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT user_id FROM alert_settings WHERE user_id=?", (user_id,))
        row = await cur.fetchone()
        if not row:
            await db.execute("INSERT INTO alert_settings(user_id) VALUES(?)", (user_id,))
            await db.commit()

async def get_alert_settings(user_id: int) -> Dict[str, Any]:
    await ensure_alert_settings(user_id)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("""
            SELECT alerts_enabled,disk_warn,disk_critical,bw_warn,bw_critical,suspend_alerts
            FROM alert_settings WHERE user_id=?
        """, (user_id,))
        r = await cur.fetchone()
        return {
            "alerts_enabled": bool(r[0]),
            "disk_warn": int(r[1]),
            "disk_critical": int(r[2]),
            "bw_warn": int(r[3]),
            "bw_critical": int(r[4]),
            "suspend_alerts": bool(r[5]),
        }

async def update_alert_settings(user_id: int, **kwargs):
    await ensure_alert_settings(user_id)
    if not kwargs:
        return
    fields, vals = [], []
    for k, v in kwargs.items():
        fields.append(f"{k}=?")
        vals.append(1 if v else 0 if isinstance(v, bool) else v)
    vals.append(user_id)
    q = "UPDATE alert_settings SET " + ",".join(fields) + " WHERE user_id=?"
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(q, tuple(vals))
        await db.commit()

async def add_profile(user_id: int, title: str, panel_url: str, api_key: str, api_pass: str, verify_ssl: bool):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO api_profiles(user_id,title,panel_url,api_key,api_pass,verify_ssl)
            VALUES(?,?,?,?,?,?)
        """, (user_id, title, panel_url, api_key, api_pass, 1 if verify_ssl else 0))
        await db.commit()

async def list_profiles(user_id: int) -> List[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("""
            SELECT id,title,panel_url,verify_ssl
            FROM api_profiles WHERE user_id=?
            ORDER BY id DESC
        """, (user_id,))
        rows = await cur.fetchall()
        return [{"id": r[0], "title": r[1], "panel_url": r[2], "verify_ssl": bool(r[3])} for r in rows]

async def get_profile(user_id: int, profile_id: int) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("""
            SELECT id,title,panel_url,api_key,api_pass,verify_ssl
            FROM api_profiles
            WHERE user_id=? AND id=?
        """, (user_id, profile_id))
        r = await cur.fetchone()
        if not r:
            return None
        return {
            "id": r[0],
            "title": r[1],
            "panel_url": r[2],
            "api_key": r[3],
            "api_pass": r[4],
            "verify_ssl": bool(r[5]),
        }

async def delete_profile(user_id: int, profile_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM api_profiles WHERE user_id=? AND id=?", (user_id, profile_id))
        await db.execute("DELETE FROM alert_state WHERE user_id=? AND profile_id=?", (user_id, profile_id))
        await db.commit()

async def get_alert_state(user_id: int, profile_id: int, vps_id: str) -> Dict[str, Any]:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("""
            SELECT last_disk_level,last_bw_level,last_suspend
            FROM alert_state
            WHERE user_id=? AND profile_id=? AND vps_id=?
        """, (user_id, profile_id, vps_id))
        r = await cur.fetchone()
        return {
            "last_disk_level": r[0] if r else None,
            "last_bw_level": r[1] if r else None,
            "last_suspend": int(r[2]) if (r and r[2] is not None) else None,
        }

async def set_alert_state(user_id: int, profile_id: int, vps_id: str,
                          last_disk_level: Optional[str], last_bw_level: Optional[str],
                          last_suspend: Optional[int]):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO alert_state(user_id,profile_id,vps_id,last_disk_level,last_bw_level,last_suspend)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(user_id,profile_id,vps_id)
            DO UPDATE SET last_disk_level=excluded.last_disk_level,
                         last_bw_level=excluded.last_bw_level,
                         last_suspend=excluded.last_suspend
        """, (user_id, profile_id, vps_id, last_disk_level, last_bw_level, last_suspend))
        await db.commit()


# =========================
# UI
# =========================
def main_menu_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🔑 پروفایل‌های API"), KeyboardButton(text="🖥 VPS ها")],
            [KeyboardButton(text="🔔 اعلان‌ها"), KeyboardButton(text="ℹ️ راهنما")],
        ],
        resize_keyboard=True
    )

def profiles_kb(profiles: List[Dict[str, Any]]) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text=p["title"], callback_data=f"prof:{p['id']}")] for p in profiles]
    rows.append([InlineKeyboardButton(text="➕ افزودن پروفایل", callback_data="prof_add")])
    rows.append([InlineKeyboardButton(text="🏠 خانه", callback_data="home")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

def profile_manage_kb(profile_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🖥 VPS ها", callback_data=f"vps_list:{profile_id}")],
        [InlineKeyboardButton(text="🗑 حذف پروفایل", callback_data=f"prof_del:{profile_id}")],
        [InlineKeyboardButton(text="🏠 خانه", callback_data="home")],
    ])

def vps_profiles_pick_kb(profiles: List[Dict[str, Any]]) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text=p["title"], callback_data=f"vps_list:{p['id']}")] for p in profiles]
    rows.append([InlineKeyboardButton(text="🏠 خانه", callback_data="home")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

def vps_list_kb(profile_id: int, vps_list: List[Dict[str, Any]]) -> InlineKeyboardMarkup:
    rows = []
    for v in vps_list[:80]:
        title = v.get("name") or v.get("hostname") or v.get("vps_name") or f"VPS {v.get('vpsid')}"
        rows.append([InlineKeyboardButton(text=title, callback_data=f"vps:{profile_id}:{v.get('vpsid')}")])
    rows.append([InlineKeyboardButton(text="🔄 بروزرسانی", callback_data=f"vps_list:{profile_id}")])
    rows.append([InlineKeyboardButton(text="🏠 خانه", callback_data="home")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

def vps_manage_kb(profile_id: int, vps_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="⏹ توقف", callback_data=f"vps_act:{profile_id}:{vps_id}:stop"),
            InlineKeyboardButton(text="🔁 ریستارت", callback_data=f"vps_act:{profile_id}:{vps_id}:restart"),
        ],
        [
            InlineKeyboardButton(text="▶️ روشن کردن", callback_data=f"vps_act:{profile_id}:{vps_id}:start"),
            InlineKeyboardButton(text="⏻ خاموشی کامل", callback_data=f"vps_act:{profile_id}:{vps_id}:poweroff"),
        ],
        [
            InlineKeyboardButton(text="💽 دیسک", callback_data=f"vps_info:{profile_id}:{vps_id}:disk"),
            InlineKeyboardButton(text="📶 ترافیک", callback_data=f"vps_info:{profile_id}:{vps_id}:bw"),
        ],
        [
            InlineKeyboardButton(text="🔄 تازه‌سازی", callback_data=f"vps:{profile_id}:{vps_id}"),
            InlineKeyboardButton(text="⬅️ برگشت", callback_data=f"vps_list:{profile_id}"),
        ],
        [InlineKeyboardButton(text="🏠 خانه", callback_data="home")],
    ])

def alerts_kb(enabled: bool, suspend: bool) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=("✅ اعلان‌ها: روشن" if enabled else "❌ اعلان‌ها: خاموش"), callback_data="alerts_toggle")],
        [InlineKeyboardButton(text=("✅ Suspend alerts: روشن" if suspend else "⛔ Suspend alerts: خاموش"), callback_data="alerts_suspend_toggle")],
        [InlineKeyboardButton(text="✏️ تنظیم آستانه‌ها", callback_data="alerts_set_thresholds")],
        [InlineKeyboardButton(text="🏠 خانه", callback_data="home")],
    ])


# =========================
# TEXTS
# =========================
def dashboard_text(user_id: int) -> str:
    return "🏠 داشبورد\n👤 کاربر: {}\n\nاز منو یکی از گزینه‌ها را انتخاب کنید.".format(user_id)

GUIDE_TEXT = (
    "ℹ️ راهنما\n\n"
    "1) ابتدا از منوی «🔑 پروفایل API» یک پروفایل بسازید.\n"
    "2) در پنل Virtualizor از مسیر «API Credentials» می‌توانید Key/Pass بسازید.\n"
    "3) بعد از ساخت پروفایل، از «🖥 VPS ها» سرورها را مدیریت کنید.\n\n"
    "نکته: اگر پنل شما SSL سلف‌ساین دارد، هنگام افزودن پروفایل گزینه «بدون Verify SSL» را انتخاب کنید."
)


# =========================
# API HELPERS
# =========================
def normalize_panel_url(url: str) -> str:
    return (url or "").strip().rstrip("/")

def is_valid_url(url: str) -> bool:
    return bool(re.match(r"^https?://", url.strip(), re.I))

async def v_api_request(
    panel_url: str, api_key: str, api_pass: str, verify_ssl: bool,
    act: str, params: Optional[Dict[str, Any]] = None, method: str = "GET"
) -> Dict[str, Any]:
    endpoint = f"{panel_url}/index.php"
    q = {"act": act, "api": "json", "apikey": api_key, "apipass": api_pass}
    if params:
        q.update(params)

    timeout = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(ssl=verify_ssl)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        if method.upper() == "POST":
            async with session.post(endpoint, params=q) as resp:
                data = await resp.json(content_type=None)
        else:
            async with session.get(endpoint, params=q) as resp:
                data = await resp.json(content_type=None)

    if isinstance(data, dict):
        return data
    return {"raw": data}

def _normalize_vps_item(item: Dict[str, Any]) -> Dict[str, Any]:
    if "vps_id" in item and "vpsid" not in item:
        item["vpsid"] = item["vps_id"]
    if "id" in item and "vpsid" not in item:
        # بعضی خروجی‌ها id می‌دن
        item["vpsid"] = item["id"]
    return item

def _looks_like_vps(item: Dict[str, Any]) -> bool:
    keys = set(item.keys())
    if "vpsid" in keys:
        return True
    # اگر vpsid نیاد ولی hostname/name/ip بیاد هم می‌پذیریم
    if ("hostname" in keys or "name" in keys or "primary_ip" in keys or "ip" in keys) and ("uid" not in keys):
        return True
    return False

def deep_find_vps_list(obj: Any, limit: int = 5000) -> List[Dict[str, Any]]:
    """
    اسکن عمیق JSON برای پیدا کردن لیست/دیکشنری VPS ها.
    Virtualizor در نصب‌های مختلف ساختار متفاوت می‌دهد.
    """
    found: List[Dict[str, Any]] = []
    visited = 0

    def walk(x: Any):
        nonlocal visited, found
        if visited > limit or len(found) > 500:
            return
        visited += 1

        if isinstance(x, list):
            # list of dicts?
            if x and all(isinstance(i, dict) for i in x):
                items = []
                for it in x:
                    it = _normalize_vps_item(dict(it))
                    if _looks_like_vps(it):
                        items.append(it)
                if len(items) >= 1:
                    found.extend(items)
                    return
            for i in x:
                walk(i)

        elif isinstance(x, dict):
            # dict of dicts?
            if x and all(isinstance(v, dict) for v in x.values()):
                items = []
                for _, it in x.items():
                    it = _normalize_vps_item(dict(it))
                    if _looks_like_vps(it):
                        items.append(it)
                if len(items) >= 1:
                    found.extend(items)
                    return
            for v in x.values():
                walk(v)

    walk(obj)

    # dedupe by vpsid if exists
    uniq = {}
    for it in found:
        vid = str(it.get("vpsid") or "")
        if vid:
            uniq[vid] = it
    return list(uniq.values()) if uniq else found

def pick_vps_list(api_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(api_data, dict):
        return []
    # اول مسیرهای رایج
    for key in ("vs", "vps", "data", "result"):
        v = api_data.get(key)
        if isinstance(v, list):
            out = []
            for it in v:
                if isinstance(it, dict):
                    it = _normalize_vps_item(dict(it))
                    if _looks_like_vps(it):
                        out.append(it)
            if out:
                return out
        if isinstance(v, dict):
            out = []
            # dict of dicts
            for _, it in v.items():
                if isinstance(it, dict):
                    it = _normalize_vps_item(dict(it))
                    if _looks_like_vps(it):
                        out.append(it)
            if out:
                return out

    # اگر پیدا نشد، اسکن عمیق
    return deep_find_vps_list(api_data)

def pick_vps_details(api_data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(api_data, dict):
        return {}
    for key in ("info", "vps", "vs", "data", "result"):
        v = api_data.get(key)
        if isinstance(v, dict) and any(k in v for k in ("vpsid", "hostname", "name", "primary_ip", "ip")):
            return v
    return api_data

def to_int(x: Any, default: int = 0) -> int:
    try:
        return int(float(x))
    except Exception:
        return default

def compute_percent(used: float, total: float) -> Optional[int]:
    if total <= 0:
        return None
    return int(math.floor((used / total) * 100))

def classify_level(pct: Optional[int], warn: int, critical: int) -> Optional[str]:
    if pct is None:
        return None
    if pct >= critical:
        return "critical"
    if pct >= warn:
        return "warn"
    return "ok"

def parse_percent(text: str) -> Optional[int]:
    t = (text or "").strip().replace("%", "").replace("٪", "")
    if not t.isdigit():
        return None
    n = int(t)
    if n < 1 or n > 100:
        return None
    return n

def extract_disk_usage(info: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    # این‌ها ممکنه در پنل شما فرق داشته باشه
    used = info.get("disk_used") or info.get("used_disk") or info.get("hdd_used") or info.get("used_hdd")
    total = info.get("disk") or info.get("vps_disk") or info.get("hdd") or info.get("total_hdd")
    try:
        return float(used), float(total)
    except Exception:
        return None, None

def extract_bw_usage(info: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    used = info.get("bandwidth_used") or info.get("bw_used") or info.get("used_bandwidth") or info.get("used_bw")
    total = info.get("bandwidth") or info.get("bw") or info.get("total_bandwidth") or info.get("total_bw")
    try:
        return float(used), float(total)
    except Exception:
        return None, None


# =========================
# BOT
# =========================
bot = Bot(BOT_TOKEN)
dp = Dispatcher()


# =========================
# HANDLERS: HOME
# =========================
@dp.message(CommandStart())
async def start(m: Message):
    await m.answer(dashboard_text(m.from_user.id), reply_markup=main_menu_kb())

@dp.callback_query(F.data == "home")
async def cb_home(cb: CallbackQuery):
    await cb.message.answer(dashboard_text(cb.from_user.id), reply_markup=main_menu_kb())
    await cb.answer()


# =========================
# HELP
# =========================
@dp.message(F.text == "ℹ️ راهنما")
async def help_menu(m: Message):
    await m.answer(GUIDE_TEXT, reply_markup=main_menu_kb())


# =========================
# PROFILES
# =========================
@dp.message(F.text == "🔑 پروفایل‌های API")
async def profiles_menu(m: Message):
    profiles = await list_profiles(m.from_user.id)
    text = "🔑 پروفایل‌های API\n\n"
    text += f"تعداد: {len(profiles)}\n" if profiles else "هنوز پروفایلی ندارید.\n"
    text += "برای مدیریت روی هر پروفایل بزنید:"
    await m.answer(text, reply_markup=profiles_kb(profiles))

@dp.callback_query(F.data.startswith("prof:"))
async def cb_profile(cb: CallbackQuery):
    user_id = cb.from_user.id
    profile_id = int(cb.data.split(":")[1])
    p = await get_profile(user_id, profile_id)
    if not p:
        await cb.answer("پروفایل پیدا نشد", show_alert=True)
        return
    verify = "✅ Verify SSL" if p["verify_ssl"] else "⛔ بدون Verify SSL"
    text = (
        "🔑 پروفایل\n\n"
        f"عنوان: {p['title']}\n"
        f"URL: {p['panel_url']}\n"
        f"SSL: {verify}\n"
    )
    await cb.message.edit_text(text, reply_markup=profile_manage_kb(profile_id))
    await cb.answer()

@dp.callback_query(F.data == "prof_add")
async def cb_profile_add(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await state.set_state(AddProfile.title)
    await cb.message.answer(
        "➕ افزودن پروفایل جدید\n\n"
        "لطفاً یک عنوان برای این پروفایل بفرستید (مثلاً: Panel 1)."
    )
    await cb.answer()

@dp.message(AddProfile.title)
async def addprof_title(m: Message, state: FSMContext):
    title = (m.text or "").strip()
    if len(title) < 2:
        await m.answer("عنوان خیلی کوتاه است. دوباره بفرست.")
        return
    await state.update_data(title=title)
    await state.set_state(AddProfile.panel_url)
    await m.answer("حالا Panel URL را بفرستید.\nمثال: https://hostname:4083")

@dp.message(AddProfile.panel_url)
async def addprof_url(m: Message, state: FSMContext):
    url = normalize_panel_url(m.text or "")
    if not is_valid_url(url):
        await m.answer("URL معتبر نیست. حتماً با http یا https شروع شود.\nمثال: https://hostname:4083")
        return
    await state.update_data(panel_url=url)
    await state.set_state(AddProfile.api_key)
    await m.answer("حالا API Key را بفرستید.")

@dp.message(AddProfile.api_key)
async def addprof_key(m: Message, state: FSMContext):
    key = (m.text or "").strip()
    if len(key) < 5:
        await m.answer("API Key نامعتبر است. دوباره بفرست.")
        return
    await state.update_data(api_key=key)
    await state.set_state(AddProfile.api_pass)
    await m.answer("حالا API Pass را بفرستید.")

@dp.message(AddProfile.api_pass)
async def addprof_pass(m: Message, state: FSMContext):
    apipass = (m.text or "").strip()
    if len(apipass) < 5:
        await m.answer("API Pass نامعتبر است. دوباره بفرست.")
        return
    await state.update_data(api_pass=apipass)
    await state.set_state(AddProfile.verify_ssl)
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Verify SSL", callback_data="ssl:1")],
        [InlineKeyboardButton(text="⛔ بدون Verify SSL (Self-signed)", callback_data="ssl:0")],
    ])
    await m.answer("SSL را انتخاب کنید:", reply_markup=kb)

@dp.callback_query(AddProfile.verify_ssl, F.data.startswith("ssl:"))
async def addprof_ssl(cb: CallbackQuery, state: FSMContext):
    verify_ssl = cb.data.split(":")[1] == "1"
    data = await state.get_data()
    await add_profile(
        user_id=cb.from_user.id,
        title=data["title"],
        panel_url=data["panel_url"],
        api_key=data["api_key"],
        api_pass=data["api_pass"],
        verify_ssl=verify_ssl,
    )
    await state.clear()
    await cb.message.answer("✅ پروفایل اضافه شد.", reply_markup=main_menu_kb())
    await cb.answer()

@dp.callback_query(F.data.startswith("prof_del:"))
async def cb_profile_del(cb: CallbackQuery):
    user_id = cb.from_user.id
    profile_id = int(cb.data.split(":")[1])
    await delete_profile(user_id, profile_id)
    await cb.message.answer("🗑 پروفایل حذف شد.", reply_markup=main_menu_kb())
    await cb.answer()


# =========================
# VPS
# =========================
@dp.message(F.text == "🖥 VPS ها")
async def vps_menu(m: Message):
    profiles = await list_profiles(m.from_user.id)
    if not profiles:
        await m.answer("اول یک پروفایل بسازید: 🔑 پروفایل‌های API", reply_markup=main_menu_kb())
        return
    await m.answer("🖥 VPS ها\n\nیک پروفایل را انتخاب کنید:", reply_markup=vps_profiles_pick_kb(profiles))

@dp.callback_query(F.data.startswith("vps_list:"))
async def cb_vps_list(cb: CallbackQuery):
    user_id = cb.from_user.id
    profile_id = int(cb.data.split(":")[1])
    p = await get_profile(user_id, profile_id)
    if not p:
        await cb.answer("پروفایل پیدا نشد", show_alert=True)
        return

    # در پنل شما act=vs جواب می‌دهد ✅
    act = "vs"

    try:
        data = await v_api_request(p["panel_url"], p["api_key"], p["api_pass"], p["verify_ssl"], act=act)
        vps_list = pick_vps_list(data)
    except Exception as e:
        await cb.message.answer(f"خطا در اتصال به پنل:\n{e}")
        await cb.answer()
        return

    if not vps_list:
        # کمک دیباگ: کلیدهای سطح اول را نشان بده (امن)
        keys = list(data.keys())[:60] if isinstance(data, dict) else []
        await cb.message.answer("⚠️ VPS ها پیدا نشدند. ساختار JSON متفاوت است.\n\nکلیدهای پاسخ:\n" + str(keys))
        await cb.answer()
        return

    text = f"🖥 VPS ها\n\nپروفایل: {p['title']}\nتعداد: {len(vps_list)}\n\nبرای مدیریت روی VPS بزنید:"
    await cb.message.edit_text(text, reply_markup=vps_list_kb(profile_id, vps_list))
    await cb.answer()

@dp.callback_query(F.data.startswith("vps:"))
async def cb_vps_detail(cb: CallbackQuery):
    user_id = cb.from_user.id
    _, profile_id_s, vps_id = cb.data.split(":")
    profile_id = int(profile_id_s)
    p = await get_profile(user_id, profile_id)
    if not p:
        await cb.answer("پروفایل پیدا نشد", show_alert=True)
        return

    # جزئیات/مدیریت VPS در اکثر نسخه‌ها managevs است
    act = "managevs"

    try:
        data = await v_api_request(p["panel_url"], p["api_key"], p["api_pass"], p["verify_ssl"], act=act, params={"vpsid": vps_id})
        info = pick_vps_details(data)
    except Exception as e:
        await cb.message.answer(f"خطا:\n{e}")
        await cb.answer()
        return

    info = dict(info) if isinstance(info, dict) else {}

    name = info.get("hostname") or info.get("name") or info.get("vps_name") or f"VPS {vps_id}"
    os_name = info.get("os_name") or info.get("os") or "-"
    virt = info.get("virt") or info.get("type") or "-"
    ip = info.get("primary_ip") or info.get("ip") or info.get("ipaddress") or "-"
    cpu = info.get("cores") or info.get("cpu") or info.get("vps_cpu") or "-"
    ram = info.get("ram") or info.get("vps_ram") or info.get("memory") or "-"
    disk = info.get("disk") or info.get("vps_disk") or info.get("hdd") or "-"

    bw_used = info.get("bandwidth_used") or info.get("bw_used") or info.get("used_bandwidth")
    bw_total = info.get("bandwidth") or info.get("bw") or info.get("total_bandwidth")
    bw_line = ""
    if bw_used is not None and bw_total is not None:
        bw_line = f"\n📶 BW: {bw_used} / {bw_total}"

    text = (
        f"🖥 {name}\n"
        f"━━━━━━━━━━━━━━\n"
        f"🆔 ID: {vps_id}\n"
        f"🧩 OS: {os_name} • {virt}\n"
        f"🌐 IP: {ip}\n"
        f"🧠 CPU: {cpu}\n"
        f"🧷 RAM: {ram}\n"
        f"💽 Disk: {disk}"
        f"{bw_line}"
    )
    await cb.message.edit_text(text, reply_markup=vps_manage_kb(profile_id, vps_id))
    await cb.answer()

@dp.callback_query(F.data.startswith("vps_act:"))
async def cb_vps_action(cb: CallbackQuery):
    user_id = cb.from_user.id
    _, profile_id_s, vps_id, action = cb.data.split(":")
    profile_id = int(profile_id_s)
    p = await get_profile(user_id, profile_id)
    if not p:
        await cb.answer("پروفایل پیدا نشد", show_alert=True)
        return

    # بسیاری از پنل‌ها: act=managevs + action
    act = "managevs"
    params = {"vpsid": vps_id, "action": action}

    try:
        await v_api_request(p["panel_url"], p["api_key"], p["api_pass"], p["verify_ssl"], act=act, params=params, method="POST")
        await cb.answer("✅ انجام شد")
    except Exception as e:
        await cb.answer("خطا", show_alert=True)
        await cb.message.answer(f"خطا:\n{e}")
        return

    await cb_vps_detail(cb)

@dp.callback_query(F.data.startswith("vps_info:"))
async def cb_vps_info(cb: CallbackQuery):
    user_id = cb.from_user.id
    _, profile_id_s, vps_id, which = cb.data.split(":")
    profile_id = int(profile_id_s)
    p = await get_profile(user_id, profile_id)
    if not p:
        await cb.answer("پروفایل پیدا نشد", show_alert=True)
        return

    act = "managevs"
    try:
        data = await v_api_request(p["panel_url"], p["api_key"], p["api_pass"], p["verify_ssl"], act=act, params={"vpsid": vps_id})
        info = pick_vps_details(data)
    except Exception as e:
        await cb.message.answer(f"خطا:\n{e}")
        await cb.answer()
        return

    info = dict(info) if isinstance(info, dict) else {}
    name = info.get("hostname") or info.get("name") or f"VPS {vps_id}"

    if which == "disk":
        used, total = extract_disk_usage(info)
        pct = compute_percent(used or 0, total or 0) if (used and total) else None
        await cb.message.answer(f"💽 دیسک\n\n{name}\nUsed: {used}\nTotal: {total}\nPercent: {pct}%")
    else:
        used, total = extract_bw_usage(info)
        pct = compute_percent(used or 0, total or 0) if (used and total) else None
        await cb.message.answer(f"📶 ترافیک\n\n{name}\nUsed: {used}\nTotal: {total}\nPercent: {pct}%")

    await cb.answer()


# =========================
# ALERTS
# =========================
@dp.message(F.text == "🔔 اعلان‌ها")
async def alerts_menu(m: Message):
    s = await get_alert_settings(m.from_user.id)
    text = (
        "🔔 تنظیمات اعلان‌ها\n\n"
        f"اعلان‌ها: {'روشن ✅' if s['alerts_enabled'] else 'خاموش ❌'}\n"
        f"Disk Warn: {s['disk_warn']}٪ | Critical: {s['disk_critical']}٪\n"
        f"BW Warn: {s['bw_warn']}٪ | Critical: {s['bw_critical']}٪\n"
        f"Suspend alerts: {'روشن ✅' if s['suspend_alerts'] else 'خاموش ⛔'}\n\n"
        "اگر فعال باشد، ربات به صورت دوره‌ای وضعیت VPS ها را چک می‌کند."
    )
    await m.answer(text, reply_markup=alerts_kb(s["alerts_enabled"], s["suspend_alerts"]))

@dp.callback_query(F.data == "alerts_toggle")
async def cb_alerts_toggle(cb: CallbackQuery):
    s = await get_alert_settings(cb.from_user.id)
    await update_alert_settings(cb.from_user.id, alerts_enabled=not s["alerts_enabled"])
    s2 = await get_alert_settings(cb.from_user.id)
    text = (
        "🔔 تنظیمات اعلان‌ها\n\n"
        f"اعلان‌ها: {'روشن ✅' if s2['alerts_enabled'] else 'خاموش ❌'}\n"
        f"Disk Warn: {s2['disk_warn']}٪ | Critical: {s2['disk_critical']}٪\n"
        f"BW Warn: {s2['bw_warn']}٪ | Critical: {s2['bw_critical']}٪\n"
        f"Suspend alerts: {'روشن ✅' if s2['suspend_alerts'] else 'خاموش ⛔'}\n\n"
        "اگر فعال باشد، ربات به صورت دوره‌ای وضعیت VPS ها را چک می‌کند."
    )
    await cb.message.edit_text(text, reply_markup=alerts_kb(s2["alerts_enabled"], s2["suspend_alerts"]))
    await cb.answer()

@dp.callback_query(F.data == "alerts_suspend_toggle")
async def cb_alerts_suspend_toggle(cb: CallbackQuery):
    s = await get_alert_settings(cb.from_user.id)
    await update_alert_settings(cb.from_user.id, suspend_alerts=not s["suspend_alerts"])
    s2 = await get_alert_settings(cb.from_user.id)
    text = (
        "🔔 تنظیمات اعلان‌ها\n\n"
        f"اعلان‌ها: {'روشن ✅' if s2['alerts_enabled'] else 'خاموش ❌'}\n"
        f"Disk Warn: {s2['disk_warn']}٪ | Critical: {s2['disk_critical']}٪\n"
        f"BW Warn: {s2['bw_warn']}٪ | Critical: {s2['bw_critical']}٪\n"
        f"Suspend alerts: {'روشن ✅' if s2['suspend_alerts'] else 'خاموش ⛔'}\n\n"
        "اگر فعال باشد، ربات به صورت دوره‌ای وضعیت VPS ها را چک می‌کند."
    )
    await cb.message.edit_text(text, reply_markup=alerts_kb(s2["alerts_enabled"], s2["suspend_alerts"]))
    await cb.answer()

@dp.callback_query(F.data == "alerts_set_thresholds")
async def cb_alerts_set_thresholds(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await state.set_state(SetThresholds.disk_warn)
    await cb.message.answer("✏️ تنظیم آستانه‌ها\n\nDisk Warn را به درصد بفرستید (مثلاً 80):")
    await cb.answer()

@dp.message(SetThresholds.disk_warn)
async def st_disk_warn(m: Message, state: FSMContext):
    n = parse_percent(m.text or "")
    if n is None:
        await m.answer("عدد 1 تا 100 بفرست (مثلاً 80).")
        return
    await state.update_data(disk_warn=n)
    await state.set_state(SetThresholds.disk_critical)
    await m.answer("Disk Critical را به درصد بفرستید (مثلاً 100):")

@dp.message(SetThresholds.disk_critical)
async def st_disk_crit(m: Message, state: FSMContext):
    n = parse_percent(m.text or "")
    if n is None:
        await m.answer("عدد 1 تا 100 بفرست (مثلاً 100).")
        return
    data = await state.get_data()
    if n < data["disk_warn"]:
        await m.answer("Critical باید >= Warn باشد. دوباره بفرست.")
        return
    await state.update_data(disk_critical=n)
    await state.set_state(SetThresholds.bw_warn)
    await m.answer("BW Warn را به درصد بفرستید (مثلاً 80):")

@dp.message(SetThresholds.bw_warn)
async def st_bw_warn(m: Message, state: FSMContext):
    n = parse_percent(m.text or "")
    if n is None:
        await m.answer("عدد 1 تا 100 بفرست (مثلاً 80).")
        return
    await state.update_data(bw_warn=n)
    await state.set_state(SetThresholds.bw_critical)
    await m.answer("BW Critical را به درصد بفرستید (مثلاً 100):")

@dp.message(SetThresholds.bw_critical)
async def st_bw_crit(m: Message, state: FSMContext):
    n = parse_percent(m.text or "")
    if n is None:
        await m.answer("عدد 1 تا 100 بفرست (مثلاً 100).")
        return
    data = await state.get_data()
    if n < data["bw_warn"]:
        await m.answer("Critical باید >= Warn باشد. دوباره بفرست.")
        return
    await update_alert_settings(
        m.from_user.id,
        disk_warn=data["disk_warn"],
        disk_critical=data["disk_critical"],
        bw_warn=data["bw_warn"],
        bw_critical=n
    )
    await state.clear()
    await m.answer("✅ آستانه‌ها ذخیره شد.", reply_markup=main_menu_kb())


# =========================
# BACKGROUND ALERT LOOP
# =========================
async def alert_loop():
    while True:
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                cur = await db.execute("SELECT DISTINCT user_id FROM api_profiles")
                users = [r[0] for r in await cur.fetchall()]

            for user_id in users:
                s = await get_alert_settings(user_id)
                if not s["alerts_enabled"]:
                    continue

                profiles = await list_profiles(user_id)
                for pr in profiles:
                    p = await get_profile(user_id, pr["id"])
                    if not p:
                        continue

                    # list VPS
                    try:
                        data = await v_api_request(p["panel_url"], p["api_key"], p["api_pass"], p["verify_ssl"], act="vs")
                        vps_list = pick_vps_list(data)
                    except Exception:
                        continue

                    for v in vps_list:
                        vps_id = str(v.get("vpsid") or "")
                        if not vps_id:
                            continue

                        try:
                            details = await v_api_request(p["panel_url"], p["api_key"], p["api_pass"], p["verify_ssl"], act="managevs", params={"vpsid": vps_id})
                            info = pick_vps_details(details)
                        except Exception:
                            continue

                        info = dict(info) if isinstance(info, dict) else {}
                        name = info.get("hostname") or info.get("name") or f"VPS {vps_id}"
                        ip = info.get("primary_ip") or info.get("ip") or info.get("ipaddress") or "-"

                        suspended = to_int(info.get("suspended") or info.get("is_suspended") or 0, 0)

                        d_used, d_total = extract_disk_usage(info)
                        b_used, b_total = extract_bw_usage(info)

                        disk_pct = compute_percent(d_used or 0, d_total or 0) if (d_used and d_total) else None
                        bw_pct = compute_percent(b_used or 0, b_total or 0) if (b_used and b_total) else None

                        disk_level = classify_level(disk_pct, s["disk_warn"], s["disk_critical"])
                        bw_level = classify_level(bw_pct, s["bw_warn"], s["bw_critical"])

                        prev = await get_alert_state(user_id, p["id"], vps_id)

                        if disk_level in ("warn", "critical") and disk_level != prev["last_disk_level"]:
                            await bot.send_message(
                                user_id,
                                f"⚠️ Disk {disk_level.upper()}\nVPS: {name}\nIP: {ip}\nمصرف: {disk_pct}%"
                            )

                        if bw_level in ("warn", "critical") and bw_level != prev["last_bw_level"]:
                            await bot.send_message(
                                user_id,
                                f"⚠️ BW {bw_level.upper()}\nVPS: {name}\nIP: {ip}\nمصرف: {bw_pct}%"
                            )

                        if s["suspend_alerts"]:
                            if prev["last_suspend"] is not None:
                                if suspended == 1 and prev["last_suspend"] == 0:
                                    await bot.send_message(user_id, f"⛔ VPS Suspend شد:\n{name}\nIP: {ip}")
                                if suspended == 0 and prev["last_suspend"] == 1:
                                    await bot.send_message(user_id, f"✅ VPS Unsuspend شد:\n{name}\nIP: {ip}")

                        await set_alert_state(
                            user_id, p["id"], vps_id,
                            last_disk_level=disk_level,
                            last_bw_level=bw_level,
                            last_suspend=suspended
                        )

        except Exception:
            pass

        await asyncio.sleep(CHECK_INTERVAL_SECONDS)


# =========================
# RUN
# =========================
async def main():
    await init_db()
    asyncio.create_task(alert_loop())
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
