
<div align="center">

<img src="./VirtPilot_LOGO.png" alt="VirtPilot Logo" width="260"/>

# 🚀 VirtPilot

### مدیریت حرفه‌ای پنل Virtualizor در تلگرام

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org)
[![Telegram](https://img.shields.io/badge/Telegram-Bot-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://telegram.org)
[![Stars](https://img.shields.io/github/stars/Emadhabibnia1385/VirtPilot?style=for-the-badge&logo=github)](https://github.com/Emadhabibnia1385/VirtPilot/stargazers)

**یک ربات قدرتمند برای مدیریت VPS ها، کنترل پاور، مشاهده مصرف منابع و دریافت اعلان‌های هوشمند از پنل Virtualizor**

[نصب سریع](#-نصب-سریع) • [ویژگی‌ها](#-ویژگیها) • [راهنما](#-راهنمای-استفاده) • [پشتیبانی](#-پشتیبانی)

---

</div>

## 📖 درباره VirtPilot

VirtPilot یک ربات تلگرام کاملاً فارسی برای مدیریت پنل **Virtualizor** از طریق **API** است.  
با VirtPilot می‌توانید چندین پنل اضافه کنید، VPS ها را مدیریت کنید و برای مصرف **Disk/Bandwidth** اعلان هوشمند بگیرید.

### 🎯 مناسب برای:
- 💼 مدیران سرور و دیتاسنتر
- 🧑‍💻 ادمین‌های VPS و هاستینگ
- 🏢 شرکت‌ها و تیم‌های DevOps
- 👥 کسانی که چند پنل/چند VPS دارند

---

## ✨ ویژگی‌ها

<table>
<tr>
<td width="25%" align="center">

### 🖥 مدیریت VPS
✅ لیست VPS ها  
✅ کنترل پاور (Start/Stop/Restart/Poweroff)  
✅ مشاهده اطلاعات پایه  
✅ پنل چندگانه (Multi-Panel)

</td>
<td width="25%" align="center">

### 🔔 سیستم اعلان‌ها
✅ اعلان مصرف Disk  
✅ اعلان مصرف Bandwidth  
✅ تنظیم Warn/Critical دلخواه  
✅ اعلان Suspend/Unsuspend

</td>
<td width="25%" align="center">

### 🎨 رابط کاربری
✅ منوهای اینترکتیو  
✅ فارسی و ساده  
✅ دکمه‌های مدیریتی سریع  
✅ مناسب موبایل

</td>
<td width="25%" align="center">

### 🛡️ امنیت و پایداری
✅ اجرا به صورت سرویس systemd  
✅ فایل env با دسترسی محدود  
✅ ریستارت خودکار در خطا  
✅ لاگ‌های کامل در journalctl

</td>
</tr>
</table>

---

## 🚀 نصب سریع

### روش اول: نصب خودکار (پیشنهادی) ⚡

تنها با **یک دستور** VirtPilot را روی سرور Ubuntu/Debian نصب کنید:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Emadhabibnia1385/VirtPilot/main/install.sh)
````

> **نکته:** برای اجرای این دستور نیاز به دسترسی root دارید.

---

## 📱 راهنمای استفاده

### دریافت اطلاعات لازم

#### 1) دریافت Bot Token:

1. به [@BotFather](https://t.me/BotFather) پیام دهید
2. دستور `/newbot` را ارسال کنید
3. نام و یوزرنیم ربات را وارد کنید
4. توکن دریافتی را کپی کنید

#### 2) ساخت API Credentials در Virtualizor:

1. وارد پنل Virtualizor شوید
2. مسیر **API Credentials** را پیدا کنید
3. یک **Key / Pass** بسازید
4. آدرس پنل را هم آماده کنید (مثلاً `https://hostname:4083`)

> اگر SSL شما Self-Signed است، هنگام افزودن پروفایل گزینه **بدون Verify SSL** را انتخاب کنید.

---

## 🧭 منوی ربات

### 🏠 داشبورد

نمایش منوی اصلی و اطلاعات کاربر.

### 🔑 پروفایل‌های API

* افزودن پروفایل جدید (عنوان، URL، Key، Pass)
* لیست پنل‌های اضافه‌شده
* حذف پروفایل

### 🖥 VPS ها

* انتخاب پنل
* نمایش لیست VPS ها
* مدیریت هر VPS:

  * Start / Stop / Restart / Poweroff
  * مشاهده وضعیت Disk و Bandwidth
  * تازه‌سازی اطلاعات

### 🔔 اعلان‌ها

* روشن/خاموش اعلان‌ها
* تنظیم Warn/Critical برای Disk و BW
* روشن/خاموش اعلان Suspend

---

## 🎮 مدیریت سرویس

بعد از نصب، می‌توانید از دستورات زیر برای مدیریت ربات استفاده کنید:

```bash
# مشاهده وضعیت ربات
systemctl status virtpilot

# شروع ربات
systemctl start virtpilot

# توقف ربات
systemctl stop virtpilot

# ریستارت ربات
systemctl restart virtpilot

# مشاهده لاگ‌های زنده
journalctl -u virtpilot -f
```

---

## 📁 ساختار پروژه

```
VirtPilot/
├── README.md            # مستندات پروژه
├── bot.py               # فایل اصلی ربات
├── install.sh           # اسکریپت نصب خودکار
├── requirements.txt     # وابستگی‌های پایتون
├── LICENSE              # لایسنس پروژه
└── VirtPilot_LOGO.png   # لوگو (اختیاری)
```

---

## 🔧 تنظیمات

بعد از نصب، فایل تنظیمات اینجاست:

```bash
nano /opt/virtpilot/.env
```

نمونه `.env`:

```env
BOT_TOKEN=YOUR_BOT_TOKEN
CHECK_INTERVAL_SECONDS=300
```

بعد از تغییرات:

```bash
systemctl restart virtpilot
```

---

## 🐛 رفع مشکلات رایج

<details>
<summary><b>ربات استارت نمی‌شود</b></summary>

```bash
journalctl -u virtpilot -n 100 --no-pager
cat /opt/virtpilot/.env

cd /opt/virtpilot
source venv/bin/activate
python3 bot.py
```

</details>

<details>
<summary><b>خطا در اتصال به پنل Virtualizor</b></summary>

* آدرس پنل را درست وارد کنید (مثلاً `https://hostname:4083`)
* Key/Pass را از بخش API Credentials درست بسازید
* اگر SSL سلف‌ساین دارید، گزینه **بدون Verify SSL** را انتخاب کنید
* پورت/فایروال سرور را بررسی کنید

</details>

<details>
<summary><b>VPS ها نمایش داده نمی‌شود</b></summary>

در برخی نسخه‌ها نام اکشن‌های API متفاوت است.
اگر این مشکل را دیدید، یک نمونه خروجی API از پنل بگیرید تا اکشن‌ها و فیلدها دقیقاً مچ شوند.

</details>

---

## 🤝 مشارکت در پروژه

مشارکت شما خوشآمد است!

1. پروژه را Fork کنید
2. یک Branch جدید بسازید (`git checkout -b feature/amazing-feature`)
3. تغییرات خود را Commit کنید (`git commit -m 'Add amazing feature'`)
4. به Branch خود Push کنید (`git push origin feature/amazing-feature`)
5. یک Pull Request باز کنید

---

## 📞 پشتیبانی

<div align="center">

[![Telegram](https://img.shields.io/badge/Developer-@EmadHabibnia-blue?style=for-the-badge\&logo=telegram)](https://t.me/EmadHabibnia)
[![Channel](https://img.shields.io/badge/Channel-@VirtPilot-blue?style=for-the-badge\&logo=telegram)](https://t.me/VirtPilot)

</div>

* 💬 **تلگرام:** [@EmadHabibnia](https://t.me/EmadHabibnia)
* 📢 **کانال:** [@VirtPilot](https://t.me/VirtPilot)

---

## ⭐ حمایت از پروژه

اگر VirtPilot برای شما مفید بود:

* ⭐ به پروژه Star بدهید
* 🔀 آن را Fork کنید
* 📢 در کانال‌های خود معرفی کنید
* 💡 ایده‌ها و پیشنهادها را بفرستید

---

<div align="center">

**ساخته شده با ❤️ توسط [Emad Habibnia](https://t.me/EmadHabibnia)**

</div>
```
