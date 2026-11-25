# راهنمای افزودن پروتکل و متد تانل جدید به HLTunnel

این راهنما معماری لایه‌بندی پروتکل‌ها در `HLTunnel` و چک‌لیست دقیق فایل‌ها، اینترفیس‌ها و تست‌های لازم برای افزودن سریع پروتکل‌های جدید (مانند تانل گیمینگ با FEC، `AmneziaWG`، `QUIC`/`MASQUE`، `KCP` و غیره) را توضیح می‌دهد.

---

## ۱. سه دسته‌ی اصلی پروتکل‌ها در HLTunnel

هر متد جدید در یکی از سه دسته‌ی زیر قرار می‌گیرد:

| دسته | کاربرد نمونه | مسیر دیتا | نمونه فعلی |
|---|---|---|---|
| **۱) تانل کرنلی لایه ۳ / ۲ (Netlink / `ip link`)** | پروتکل‌های کرنل لینوکس یا ماژول‌های DKMS (`amneziawg`) | مستقیم در کرنل (`internal/engine/link_linux.go`) | `gre`, `vxlan`, `wireguard`, `sit`, `ipip`, `l2tpv3` |
| **۲) تانل بسته‌ای در فضای کاربر (`Userspace TUN/TAP`)** | ضد-DPI اختصاصی، **FEC/UDPspeeder**، **KCP**، **AmneziaWG-go** | دیمن `internal/daemon/userspace.go` + `internal/tun` + `linkDriver` | `obfs` (`HLObfs`), `spoof`, `tcp`, `eoip` |
| **۳) تانل اتصال‌محور / استریم (`Stream / L4 Mux`)** | عبور از فیلترینگ با نشست‌های چندگانه روی **QUIC** یا **TLS** (`stream`) | `internal/transport` (`Hub`) + `internal/relay` | `stream-tcp` (`tcpmux`), `stream-tls` (`tlsmux`) |

---

## ۲. محدودیت‌های حیاتی سیستم و شبکه (`IFNAMSIZ` و nftables)

پیش از انتخاب نام `Kind` و پسوندها، حتماً موارد زیر را رعایت کنید:

1. **محدودیت ۱۵ کاراکتری نام اینترفیس کرنل لینوکس (`IFNAMSIZ = 16`)**:
   - پیشوند استاندارد اینترفیس‌های دائمی `hl-` (۳ بایت) و اینترفیس‌های موقت بنچمارک `hlx-` (۴ بایت) است (`internal/engine/engine_linux.go` / `link_linux.go`).
   - برای تانل‌های تک‌لایه حداکثر طول اسم تانل کاربر ۱۲ کاراکتر است (`3 + 12 = 15`).
   - اگر پروتکل بتواند به‌عنوان لایه‌ی زیرین (Carrier) در تانل ترکیبی استفاده شود، `CarrierSuffix` (مثل `-o`، `-s`، `-w`، `-6`) باید حداکثر ۲ کاراکتر باشد (`PlanTunnel` طول نام تانل ترکیبی را به ۸ کاراکتر محدود می‌کند تا جا برای پسوند و شماره‌ی lane بماند).
2. **جدول‌ها و کانترهای `nftables` و Routing Marks**:
   - از مارک‌های رزروشده‌ی فعلی (`0x4e540000`, `0x4e550001`, `0x4e560000`, `spiBase = 0x4e000000`) و نام جدول‌های `hltunnel*` تخطی نکنید تا قانون‌های فوروارد، Return و Leak-Guard خودکار روی تانل جدید اعمال شوند.
3. **پورت‌های بنچمارک (`BenchPort` در `internal/bench/bench.go`)**:
   - هر پروتکل که در تست مقایسه‌ای ویزارد قرار می‌گیرد باید یک پورت منحصربه‌فرد بدون تداخل (`BenchPort + N`) در `Candidates()` بگیرد.

---

## ۳. چک‌لیست گام‌به‌گام افزودن پروتکل جدید

### گام ۱: تعریف متادیتا در `internal/config/`
- **`internal/config/kind.go`**:
  - ثابت جدید اضافه کنید: `KindMyProto Kind = "myproto"`
  - یک رکورد در اسلایس `kinds` اضافه کنید. تمام قابلیت‌ها به‌صورت متمرکز از اینجا خوانده می‌شوند (`kindByID` در `init()` به‌صورت O(1) ایندکس می‌شود):
    - `Layer` (`2` یا `3`, برای `Stream` برابر `0`), `Under6` / `UnderAny`, `Carry4` / `Carry6`
    - `Overhead` (برای محاسبه‌ی MTU خودکار؛ در صورت وابستگی به پارامترها مثل FEC یا Spoof، متد `(t Tunnel) PacketOverhead(...)` را هم به‌روزرسانی کنید)
    - `UDP` / `TCP` / `FOU` / `PortEncap`
    - `Encrypted` (اگر خود پروتکل رمزنگاری دارد تا IPsec اضافه نشود) و در صورت وجود کلید داخلی متد `(t Tunnel) EffectiveEncrypt()`
    - `Userspace` (`true` برای درایورهای فضای کاربر یا Stream)
    - `NeedsPeer` (`true` اگر هر دو سر باید `hltunnel` داشته باشند؛ در غیر این صورت `false` مثل WireGuard یا میکروتیک)
    - `Stream` (`true` برای متدهای connection/relay بدون اینترفیس TUN)
    - `PMTU`, `IgnoreDF`, `Lanes` (امکانات کرنلی در `model.go` به‌صورت خودکار به `KindInfo` ارجاع می‌دهند)
    - `DefaultPort`, `AutoPort` (`true` تا ویزارد و CLI پورت آزاد خودکار انتخاب کنند), `HasVNI`, `HasPadding`, `HasObfsAES`
    - `Modules`: لیست ماژول‌های کرنلی (`[]string{"tun"}` برای فضای کاربر یا مثلاً `[]string{"amneziawg"}`) که `modulesFor` در `engine_linux.go` خودکار بارگذاری می‌کند
    - `IPv6Kind`, `CarrierSuffix` (اگر حامل تانل ترکیبی است), `ConflictGroup`, `Hint` (راهنمای متنی در منوی CLI)
- **`internal/config/model.go` و `internal/config/secret.go`**:
  - اگر پروتکل تنظیمات اختصاصی دارد (مثل پارامترهای FEC یا پارامترهای `AmneziaWG`) فیلدهای `omitempty` را به `config.Tunnel` اضافه کنید و در صورت نیاز از `NeedsSecret()` مطمئن شوید (بر اساس `ki.Encrypted || ki.NeedsPeer` یا فیلد اختصاصی).

### گام ۲: ثبت Mode و اعتبارسنجی در `internal/manage/`
- **`internal/manage/tunnels.go`**:
  - به اسلایس `modes` یک خط با `modeOf(name, title, hint, kinds...)` اضافه کنید (`Port`, `Layer`, `UDP`, `TCP`, `Crypt`, `Peer`, `Stream`, `Hint`, `AutoPort` خودکار از `KindInfo` پر می‌شوند!).
  - اگر پارامتر جدیدی روی `TunnelRequest` / `TunnelOpts` / `Settings` دارید، مقداردهی و اعتبارسنجی آن‌ها را در `PlanTunnel`, `NewTunnel`, `UpdateTunnel` و `SettingsOf` قرار دهید.
- **`internal/cli/`**:
  - اگر فلگ CLI جدید لازم است، به `tunnel.go` / `quick.go` / `menu.go` اضافه کنید. (گزینه‌ی انتخاب متد در منوی تعاملی `menu.go` از `manage.Modes()` و `m.Hint` خودکار خوانده می‌شود و نیاز به تغییر ندارید.)

### گام ۳: پیاده‌سازی دیتاپلین (بر اساس دسته‌ی پروتکل)
- **`internal/engine/render.go`**:
  - فیلدهای لازم را به `LinkSpec` اضافه کنید و حتماً در `linkSignature(s)` بگنجانید تا با تغییر پارامتر، دیمن تانل را بازسازی (`restart`) کند.
  - در `RenderTunnels` حالت `case config.KindMyProto:` را در صورت نیاز به پیش‌فرض پورت/کلید خاص اضافه کنید (پورت‌های پیش‌فرض ساده از `ki.EffectivePort` استفاده می‌کنند).
- **برای دسته‌ی ۱ (کرنلی)**:
  - در `internal/engine/link_linux.go` منطق ساخت/ویرایش لینک Netlink را اضافه کنید (ماژول‌ها از `KindInfo.Modules` خودکار `modprobe` می‌شوند).
  - در `internal/engine/ipsec.go` پورت خارجی آن برای استثنای `nftables`/`xfrm` بررسی شود (`DefaultPort` در `KindInfo` کمک می‌کند).
- **برای دسته‌ی ۲ (فضای کاربر TUN/TAP)**:
  - پکیج جدید `internal/<myproto>/` بسازید:
    - یک `Manager` با متدهای `NewManager()`, `Sync([]Config) []error`, `Close()`.
    - تابع `Start(Config) (*Link, error)` برای اجرای تک‌تانل در بنچمارک (تایپ `*Link` باید متد `Close()` داشته باشد).
    - از `internal/tun` برای ساخت اینترفیس و از `internal/pmtu` / `SO_MARK` (برای جلوگیری از Routing Loop) استفاده کنید.
  - در **`internal/daemon/userspace.go`**:
    - تابع سازنده‌ی تنظیمات `myProtoConfig(engine.LinkSpec) myproto.Config` را بنویسید.
    - در `newDataPlane()` درایور جدید را با `specDriver` در نقشه‌ی `d.drivers[config.KindMyProto]` و لیست `d.driverOrder` ثبت کنید. تمام چرخه‌ی `SyncLinks`, `StartBench` و `Close()` بدون نیاز به تغییر در توابع دیگر خودکار کار خواهد کرد.
- **برای دسته‌ی ۳ (Stream / L4 Mux)**:
  - دیالر و لیسنر پروتکل جدید را در `internal/transport/` اضافه کنید؛ `Hub` و `relay.Manager` بر اساس `ki.Stream == true` به‌صورت خودکار رله‌های پورت را روی آن سوار می‌کنند.

### گام ۴: هماهنگ‌سازی بین سرورها (`agent`), تست مسیر (`bench`) و رابط وب (`web`)
- اگر فیلدهای جدیدی به `config.Tunnel` اضافه شده و دو سرور باید آن را همگام کنند، از ارسال درست در `internal/config/masters.go` و `internal/agent/protocol.go` مطمئن شوید (در حال حاضر `State`/`Managed.Tunnels` مستقیماً serialize می‌شود).
- **`internal/bench/bench.go`**: در `Candidates()` یک `Candidate` با پورت آزاد `BenchPort + N` اضافه کنید تا ابزار `bench` و ویزارد پنل به صورت خودکار آن را تست و رتبه‌بندی کنند.
- **`internal/web/live.go` و `internal/web/static/app.js`**:
  - در `app.js` مشخصات پروتکل را در جدول `KINDS` و مراحل ویزارد اضافه کنید (مقادیر `Overhead`، `Encrypt`، `VNI` و نمایش پایه از API پنل خوانده می‌شوند).

### گام ۵: تست‌ها (الزامی)
- تست واحد برای کدک/فرمینگ و پکت‌هندلینگ در `internal/<myproto>/*_test.go` (از جمله round-trip بسته و هندل خطا).
- تست رندر و محاسبه‌ی MTU در `internal/engine/render_test.go` (اطمینان از `len(Ifname) <= 15`).
- تست برنامه‌ریزی و تداخل نام/پورت در `internal/manage/tunnels_test.go`.
- اضافه‌کردن سناریوی تست کرنل/نت‌اسپیس در `test/e2e.sh` و بررسی با `go vet ./...`, `GOOS=linux GOARCH=amd64 go vet ./...` و `go test ./...`.

---

## ۴. الگوی پیاده‌سازی برای پروتکل‌های اولویت‌دار بعدی

### الف) تانل گیمینگ با FEC (`KindFEC` — الگوی UDPspeeder)
- **دسته**: دسته‌ی ۲ (فضای کاربر L3 TUN روی UDP با قابلیت رمزنگاری سبک و بازیابی بسته).
- **متادیتای پیشنهادی**: `Layer: 3, UnderAny: true, Carry4: true, Carry6: true, UDP: true, Encrypted: true, Userspace: true, NeedsPeer: true, AutoPort: true, Modules: []string{"tun"}`.
- **طراحی دیتاپلین (`internal/fec/`)**:
  - گروهبندی بسته‌های IP ورودی TUN به بلوک‌های `K` تایی داده + `M` بسته‌ی افزونه‌ی Reed-Solomon (مثل `klauspost/reedsolomon`؛ حالت پایه مثلاً `4+1` یا `4+2` برای گیم).
  - **تایمر Flush کوتاه (`fec_timeout_ms` مثلاً ۳ تا ۵ میلی‌ثانیه)**: اگر جریان گیم آرام باشد و `K` بسته پر نشود، بلوک ناقص فوری بسته و parity ارسال شود تا جیتِر (Jitter) بالا نرود.
  - استفاده از `SO_MARK` یا ارسال روی اینترفیس زیرین همراه با Keepalive سبک و نمایش نرخ بازسازی FEC در `LinkState` یا پنل.
  - ثبت یک‌خطی با `specDriver` در `internal/daemon/userspace.go`.

### ب) `AmneziaWG` (`KindAWG`)
- **دو مسیر پیاده‌سازی**:
  1. **ماژول کرنل (`amneziawg-linux-kernel-module`) — دسته‌ی ۱ (سریع‌تر و کم‌مصرف‌تر):**
     - `Userspace: false, Modules: []string{"amneziawg"}, Encrypted: true, NeedsPeer: false` (سازگار با کلاینت/روترهای AmneziaWG).
     - اضافه کردن فیلدهای `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1..H4` در `Tunnel` و `LinkSpec` و اعمال آن‌ها در `link_linux.go` با Fallback مناسب در صورت نبودن ماژول کرنل.
  2. **نسخه‌ی فضای کاربر (`amneziawg-go`) — دسته‌ی ۲ (بدون نیاز به نصب ماژول کرنل روی میزبان):**
     - `Userspace: true, Modules: []string{"tun"}, Encrypted: true, NeedsPeer: false` + پیاده‌سازی `Manager` / `Start` و ثبت به‌عنوان `linkDriver` در `daemon/userspace.go`.
     - مزیت: اجرا روی هر سرور اوبونتو/دبیان بدون نیاز به کرنل‌هدر یا DKMS (مشابه `HLObfs` و `Spoof`).

### ج) `QUIC` / `MASQUE` / `KCP`
- **برای تونل پورت و رله‌های وب/TCP (پیشنهادی: `KindStreamQUIC` در دسته‌ی ۳)**:
  - `Stream: true, UDP: true, Encrypted: true, Userspace: true, NeedsPeer: true, AutoPort: true`.
  - روی `quic-go` در `internal/transport/` اجرا می‌شود؛ مالتی‌پلکس استریم بدون Head-of-Line Blocking در لایه ۴، کنترل ازدحام مدرن (BBR/Cubic)، قابلیت Connection Migration و تنظیم ALPN دلخواه (مثل `h3`).
- **برای انتقال بسته لایه ۳ (`MASQUE` HTTP/3 Connect-IP یا `KCP` روی TUN — دسته‌ی ۲)**:
  - بسته‌های IP از TUN خوانده شده و روی Datagramهای QUIC (RFC 9298 / RFC 9484) یا نشست `kcp-go` منتقل می‌شوند و به‌عنوان یک `linkDriver` در `daemon/userspace.go` ثبت می‌گردند.
