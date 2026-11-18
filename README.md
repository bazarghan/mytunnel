<div dir="rtl">

<p align="center"><img src="docs/icon.png" width="240" alt="MyTunnel"></p>
<p align="center"><b>تانل‌های کرنلی + تانل Spoof (مبدأ جعلی) روی همه‌ی پروتکل‌ها، با پنل فارسی و نصب یک‌خطی</b></p>
<p align="center">
<a href="https://github.com/bazarghan/mytunnel/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/bazarghan/mytunnel/ci.yml?branch=main&style=flat-square&label=tests&labelColor=111111" alt="tests"></a>
<img src="https://img.shields.io/badge/Ubuntu-20.04%2B-ececec?style=flat-square&labelColor=111111" alt="ubuntu">
<a href="LICENSE"><img src="https://img.shields.io/github/license/bazarghan/mytunnel?style=flat-square&color=ececec&labelColor=111111" alt="license"></a>
</p>

<p align="center"><img src="docs/screenshots/dashboard.png" alt="داشبورد پنل: جریان ترافیک زنده‌ی هر تانل، بار سرور، پینگ، کارت شبکه و جزئیات سرور"></p>

یک سرور (مثلاً ایران) **سرور اصلی** است و پنل روی آن نصب می‌شود. سرورهای مقصد (خارج) با یک دستور به آن وصل می‌شوند و از آن به بعد **هر تغییری در پنل، خودکار روی هر دو طرف اعمال می‌شود**.

<table>
<tr>
<td width="50%">🎭 <b>تانل Spoof روی همه‌ی پروتکل‌ها</b><br>جعل IP مبدأ روی ۶ حامل (<code>UDP</code>، <code>FakeTCP</code>، <code>GRE</code>، <code>IPIP</code>، <code>6to4/SIT</code>، <code>ICMP</code>) به‌صورت مستقل یا زیرِ هر پروتکل دیگر.</td>
<td width="50%">⚡ <b>سرعت کرنل</b><br>تانل‌ها مستقیم در کرنل لینوکس ساخته می‌شوند؛ MTU خودکار، BBR و بافرهای شبکه با یک کلیک.</td>
</tr>
<tr>
<td>🧭 <b>بررسی زنده و تست مسیر Spoof</b><br>بررسی زنده‌ی پروتکل‌ها پیش از ساخت + تست دوطرفه‌ی هر ۶ حامل Spoof بین سرور ایران و خارج.</td>
<td>🎛️ <b>کنترل کامل هر تانل</b><br>روشن/خاموش، سقف سرعت، حجم ماهانه، رمزنگاری، MTU، پورت و صف هوشمند (CAKE).</td>
</tr>
<tr>
<td>👤 <b>IP واقعی کاربر</b><br>حالت شفاف، PROXY protocol v1/v2 و رله TCP، برای TCP و UDP.</td>
<td>🔒 <b>امن و ماندگار</b><br>TLS 1.3 دوطرفه بین سرورها، IPsec در کرنل، XChaCha20 / AES-GCM، سرویس systemd با ترمیم خودکار.</td>
</tr>
<tr>
<td>📊 <b>مقایسه‌ی همه‌ی پروتکل‌ها در یک دقیقه</b><br>اول اتصال همه با هم، بعد تست سرعت واقعی فقط برای آن‌هایی که وصل شدند.</td>
<td>📈 <b>آمار از یک ساعت تا از ابتدا</b><br>ترافیک، پینگ و افت هر تانل، پردازنده و حافظه؛ میانگین هر بازه همراه با اوج آن.</td>
</tr>
</table>

## نصب روی سرور اصلی (ایران)

> **نکته:** چون مخزن `bazarghan/mytunnel` خصوصی (Private) است، برای نصب مستقیم از گیت‌هاب یا باید از توکن گیت‌هاب (`GITHUB_TOKEN`) استفاده کنید یا از باینری آماده‌ی داخل مخزن استفاده نمایید.

### روش ۱: نصب یک‌خطی از گیت‌هاب

اگر مخزن را Public کرده‌اید، روی سرور با دسترسی root بزنید:

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/bazarghan/mytunnel/main/install.sh | sudo bash
```

<div dir="rtl">

اگر مخزن **Private** است (با توکن گیت‌هاب خودتان `ghp_...` یا `github_pat_...`):

</div>

```bash
TOKEN="YOUR_GITHUB_TOKEN"
curl -fsSL -H "Authorization: Bearer $TOKEN" https://raw.githubusercontent.com/bazarghan/mytunnel/main/install.sh -o /tmp/install.sh
curl -fsSL -H "Authorization: Bearer $TOKEN" https://raw.githubusercontent.com/bazarghan/mytunnel/main/neotunnel-linux-$(dpkg --print-architecture) -o /tmp/neotunnel-linux-$(dpkg --print-architecture)
sudo bash /tmp/install.sh --binary /tmp/neotunnel-linux-$(dpkg --print-architecture)
```

<div dir="rtl">

<details>
<summary>گزینه‌های نصب آنلاین</summary>

</div>

```bash
# پورت پنل دلخواه
curl -fsSL https://raw.githubusercontent.com/bazarghan/mytunnel/main/install.sh | sudo bash -s -- --port 2096
# بدون پنل (سرور مقصد)
curl -fsSL https://raw.githubusercontent.com/bazarghan/mytunnel/main/install.sh | sudo bash -s -- --no-panel
```

<div dir="rtl">

نصاب نسخه‌ی مناسب را نصب و checksum را بررسی می‌کند، پنل را روی پورت انتخابی (یا تصادفی) بالا می‌آورد و آدرس، نام کاربری و رمز را نمایش می‌دهد:

</div>

```text
  address   https://203.0.113.10:34127/k7m2xq9p4d/
  username  admin
  password  9hq4m2xkp7wtrn
```

<div dir="rtl">

</details>

### روش ۲: نصب آفلاین با باینری آماده (ساده‌ترین روش بدون نیاز به اینترنت گیت‌هاب)

فایل `neotunnel-linux-amd64` و `SHA256SUMS` از قبل کامپایل‌شده و داخل همین مخزن قرار دارند:

۱. فایل `neotunnel-linux-amd64` (و در صورت تمایل `SHA256SUMS`) را در پوشه‌ی `/root` سرور ایران بگذارید (با `scp`، WinSCP یا FileZilla).

۲. روی سرور ایران با کاربر `root` این دستور را بزنید:

</div>

```bash
chmod +x /root/neotunnel-linux-amd64 && sudo /root/neotunnel-linux-amd64 setup
```

<div dir="rtl">

برای پورت دلخواه پنل، `--port 2096` و برای سرور مقصد بدون پنل `--no-panel` را به انتهای دستور اضافه کنید. برای به‌روزرسانی آفلاین هم کافی است باینری جدید را جایگزین کرده و همین دستور را دوباره اجرا کنید؛ تنظیمات و رمز پنل دست نمی‌خورند.

### روش ۳: کلون و نصب مستقیم از گیت‌هاب

</div>

```bash
git clone https://github.com/bazarghan/mytunnel.git
cd mytunnel
sudo ./neotunnel-linux-amd64 setup
```

<div dir="rtl">

## شروع در سه قدم

1. **افزودن سرور مقصد (خارج)**: در پنل وب وارد صفحه‌ی «سرورها» شوید و نام و IP سرور خارج را وارد کنید.
2. **اتصال**: پنل یک دستور یک‌خطی می‌سازد؛ آن را روی سرور خارج اجرا کنید. برنامه مستقیم از سرور ایران روی سرور خارج دانلود و نصب می‌شود (سرور خارج نیازی به دسترسی به گیت‌هاب ندارد).
3. **ساخت تانل**: «تانل جدید» ← مقصد ← پروتکل ← امنیت و پورت (یا روشن کردن **حمل با تانل Spoof**) ← فوروارد. هر دو طرف خودکار ساخته می‌شوند.

<p align="center"><img src="docs/screenshots/wizard.png" alt="ویزارد ساخت تانل با بررسی زنده‌ی اتصال هر پروتکل"></p>

---

## تانل Spoof (مبدأ جعلی) روی همه‌ی پروتکل‌ها

این قابلیت برای عبور از محدودیت‌ها و فیلترینگ‌های شدید طراحی شده و هم به‌صورت **تانل مستقل (`spoof`)** و هم به‌عنوان **لایه‌ی حامل زیرِ تمام پروتکل‌ها** قابل استفاده است:

- **سوار شدن زیر تمام پروتکل‌ها**: هر پروتکلی را انتخاب کنید (`6to4`، `6to4-gre`، `IPIP`، `GRE`، `SIT`، `WireGuard`، `NeoObfs`، `GRETAP`، `VXLAN`، `GENEVE`، `L2TPv3`، `EoIP`، `TCP`، `TCP+mux`، `TLS+mux`)، می‌توانید گزینه‌ی **«حمل با تانل Spoof»** را در پنل (یا `--spoof` در CLI) روشن کنید تا کل ترافیک آن پروتکل با IP مبدأ جعلی منتقل شود.
- **۶ حامل روی سیم (`spoof_proto` / `--spoof-proto`)**:
  - `udp`: بسته‌های UDP با IP مبدأ جعلی (سریع‌ترین، همراه با `recvmmsg` و `GRO`)
  - `tcp`: بسته‌های FakeTCP / TCP خام (`PSH-ACK`) با فیلتر BPF کرنل و مسدودسازی خودکار `RST` کرنل در `nftables`
  - `gre`: فریم‌های GRE (پروتکل ۴۷) با مبدأ جعلی
  - `ipip`: بسته‌های IPIP (پروتکل ۴) با مبدأ جعلی
  - `sit`: بسته‌های 6to4 / SIT (پروتکل ۴۱) با مبدأ جعلی
  - `icmp`: بسته‌های ICMP Echo Reply (پروتکل ۱) با مبدأ جعلی بدون ایجاد پاسخ خودکار در کرنل
- **۳ حالت جهت Spoof (`spoof_mode` / `--spoof-mode`)**:
  - `both` (پیش‌فرض): هر دو سرور بسته‌ها را با IP مبدأ جعلی می‌فرستند.
  - `out`: فقط سرور اصلی (ایران) با IP مبدأ جعلی می‌فرستد و سرور مقصد پاسخ را با IP واقعی خودش برمی‌گرداند (مناسب وقتی دیتاسنتر خارج `uRPF` دارد).
  - `in`: فقط سرور مقصد با IP مبدأ جعلی می‌فرستد.
- **۴ حالت تولید IP مبدأ جعلی (`spoof_src` / `--spoof-src`)**:
  - `auto`: یک IP عمومی معتبر و ثابت برای هر طرف
  - `iran`: انتخاب و چرخش از رنج IPهای عمومی ایران
  - `rotate`: چرخش پویا و مداوم IP مبدأ در بسته‌ها
  - یا وارد کردن یک IPv4 دلخواه (یا دو IP با کاما برای دو طرف، مثل `185.143.233.10,8.8.8.8`)
- **تست زنده‌ی مسیر Spoof**: پیش از ساخت تانل، با دکمه‌ی **«تست مسیر Spoof روی همه‌ی پروتکل‌ها»** در ویزارد یا دستور `sudo neotunnel spoof-test <peer>`، هر ۶ حامل در هر دو جهت (`ایران ⇄ خارج`) تست می‌شوند و بهترین حامل و جهت به‌صورت خودکار انتخاب می‌گردد.

---

## انواع تانل

| نوع | لایه | بستر | روی پورت | حمل روی Spoof |
|---|:-:|---|:-:|:-:|
| **6to4** (SIT + IPIP6) | 3 | IPv4 | UDP (اختیاری) | ✅ (`--spoof`) |
| 6to4-gre (SIT + GRE6) | 3 | IPv4 | UDP (اختیاری) | ✅ (`--spoof`) |
| IPIP / SIT | 3 | IPv4 یا IPv6 | UDP (روی IPv4) | ✅ (`--spoof`) |
| GRE / GRETAP | 3 / 2 | IPv4 یا IPv6 | UDP (روی IPv4) | ✅ (`--spoof`) |
| **EoIP / EoIPv6** | 2 | IPv4 یا IPv6 | UDP (اختیاری) | ✅ (`--spoof`) |
| VXLAN / GENEVE | 2 | IPv4 یا IPv6 | همیشه UDP | ✅ (`--spoof`) |
| L2TPv3 | 2 | IPv4 یا IPv6 | UDP یا IP 115 | ✅ (`--spoof`) |
| **WireGuard** (رمزدار) | 3 | IPv4 یا IPv6 | همیشه UDP | ✅ (`--spoof`) |
| **NeoObfs** (رمزدار، مبهم) | 3 | IPv4 یا IPv6 | همیشه UDP | ✅ (`--spoof`) |
| **TCP** | 3 | IPv4 یا IPv6 | همیشه TCP | ✅ (`--spoof`) |
| **TCP + mux / TLS + mux** | 4 | IPv4 یا IPv6 | همیشه TCP | ✅ (`--spoof`) |
| **Spoof** (مستقل، رمزدار) | 3 | IPv4 | UDP / FakeTCP / GRE / IPIP / SIT / ICMP | بومی |

## داشبورد، آمار و تست سرعت

<p align="center"><img src="docs/screenshots/flow.png" width="720" alt="کارت Traffic flow"></p>
<p align="center"><img src="docs/screenshots/speed.png" alt="تست سرعت زنده‌ی تانل"></p>

- **تست یک تانل و مقایسه‌ی همه**: اندازه‌گیری پینگ، جیتر، افت بسته و سرعت واقعی آپلود و دانلود روی ۱ تا ۳۲ اتصال هم‌زمان (بدون احتساب زمان گرم شدن TCP).
- **مدیریت کامل هر تانل**: سقف سرعت کرنلی (TBF)، سهمیه‌ی حجم ماهانه، صف هوشمند (CAKE) برای گیمینگ، MTU خودکار، و چند تانل پشتیبان برای هر پورت با جابه‌جایی خودکار.
- **فوروارد پورت**: حالت‌های `nat`، `transparent` (IP واقعی کاربر)، `proxy` (PROXY protocol v1/v2)، `relay` (رله TCP) و `socks` (پروکسی SOCKS5/HTTP).

## دستورات خط فرمان (CLI)

همه‌ی امکانات پنل در ترمینال هم در دسترس است (`sudo neotunnel` منوی تعاملی را باز می‌کند):

</div>

```bash
# تست مسیر Spoof در هر دو جهت روی هر ۶ پروتکل حامل
sudo neotunnel spoof-test germany --src iran

# تانل Spoof مستقل با حامل FakeTCP و IP مبدأ ایران + فوروارد پورت 443
sudo neotunnel quick germany --address 198.51.100.24 --mode spoof --spoof-proto tcp --spoof-src iran --forward 443

# اجرای هر پروتکلی (مثلاً 6to4، GRE یا WireGuard) روی لایه‌ی Spoof
sudo neotunnel quick germany --mode 6to4 --spoof --spoof-proto udp --spoof-mode both --forward 443
sudo neotunnel quick germany --mode wireguard --spoof --spoof-proto tcp --spoof-src rotate --forward 8443

# سایر دستورات پرکاربرد
sudo neotunnel quick germany --address 198.51.100.24 --forward 443          # 6to4 + فوروارد در یک مرحله
sudo neotunnel tunnel add mk1 --kind eoip --remote 203.0.113.99 --tunnel-id 10
sudo neotunnel tunnel limit t1 --rate 200 --quota 500
sudo neotunnel bench germany
```

<div dir="rtl">

| دستور | کار |
|---|---|
| `spoof-test <peer> [--src auto\|iran\|rotate\|ip]` | تست دوطرفه‌ی Spoof روی هر ۶ حامل (UDP، FakeTCP، GRE، IPIP، SIT، ICMP) |
| `quick <server> --address <ip> [--mode] [--spoof] [--spoof-proto] [--spoof-mode] [--spoof-src] [--forward]` | ساخت تانل (با یا بدون Spoof) در یک مرحله |
| `tunnel add\|set\|list\|remove\|kinds` | مدیریت تانل‌ها و تنظیمات پیشرفته |
| `tunnel enable\|disable\|limit <name>` | روشن/خاموش، سقف سرعت و حجم ماهانه |
| `forward add\|set <tunnel> <ports> [--to] [--proto] [--mode nat\|transparent\|proxy\|relay]` | فوروارد پورت |
| `peer add\|list\|link\|sync\|upgrade\|remove` | مدیریت سرورهای مقصد |
| `test <tunnel>` / `bench <server>` / `mtu <tunnel>` | تست سرعت، مقایسه، بهترین MTU |
| `traffic` / `status` / `doctor` | ترافیک زنده، وضعیت و عیب‌یابی |
| `panel info\|setup\|password\|port\|disable` | مدیریت پنل وب |
| `boost` / `update` / `uninstall` | تنظیم شبکه (BBR)، به‌روزرسانی، حذف کامل |

## ساخت از سورس

</div>

```bash
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X neotunnel/internal/version.Version=v0.9.0-spoof" -o neotunnel-linux-amd64 ./cmd/neotunnel
sudo test/e2e.sh neotunnel-linux-amd64   # تست کامل روی کرنل واقعی
```

<div dir="rtl">

## مجوز

[MIT](LICENSE)

</div>
