# Kontrak sesi PWA

## Deployment

1. Jalankan migrasi `migrations/001_browser_sessions.sql` sekali sebelum menjalankan backend baru. Migrasi membuat tabel sesi baru dan mencabut refresh token lama; pengguna harus login kembali. Migrasi tidak dijalankan otomatis saat startup.
2. Set `FE_ALLOWED_ORIGINS` ke daftar origin FE lengkap, dipisahkan koma, tanpa trailing slash. Contoh development: `http://localhost:5173,http://127.0.0.1:5173`. Contoh produksi: `https://app.example.com`. Konfigurasi kosong menolak endpoint sesi.
3. Cookie selalu host-only, HttpOnly, Secure, Path=/v1/auth, dengan Max-Age. Gunakan HTTPS pada deployment; HTTP development memerlukan dukungan secure localhost browser atau proxy HTTPS.
4. `REFRESH_COOKIE_SAME_SITE=lax` adalah default. Gunakan `none` hanya untuk deployment cross-site yang sudah diuji terhadap kebijakan third-party cookie browser.
5. `ACCESS_TOKEN_DURATION` dalam menit, default 5 dan maksimum 15. `REFRESH_TOKEN_DURATION` dalam hari, default 30 dan maksimum 90. Nilai kosong/tidak valid/nonpositif menggunakan default. JWT membutuhkan pasangan RSA serta JWT_ISSUER dan JWT_AUDIENCE sesuai konfigurasi deployment.

## Endpoint

Login tetap menerima email JSON dan password RSA-OAEP di Authorization: Bearer. Login, refresh, dan logout wajib membawa Origin yang terdaftar, X-Requested-With: XMLHttpRequest, dan Content-Type: application/json.

Login dan refresh mengembalikan `error: false`, data.token.access_token, data.user_data (termasuk uuid), tenant_uuid, school_uuid, menu, dan permission. Refresh hanya membaca cookie; bearer token dan scope browser tidak dibutuhkan. Token refresh tidak dikirim dalam JSON atau disimpan mentah di database.

Logout hanya membutuhkan cookie dan header CSRF, tidak memerlukan email atau access token. Logout tanpa cookie/berulang berhasil. Kegagalan database mengembalikan 500 tanpa menghapus cookie supaya pencabutan dapat diulang. Cookie dari rotasi terdahulu juga dapat mencabut sesi yang sama, sehingga logout yang bersamaan dengan refresh tetap mencabut sesi.

## Kebijakan sesi dan refresh bersamaan

Setiap login membuat sesi perangkat independen. Rotasi mempertahankan batas kedaluwarsa absolut sejak login. PostgreSQL mengunci sesi dan token dalam transaksi; refresh token hanya dapat digunakan satu kali.

Jika dua tab memakai cookie yang sama bersamaan, satu berhasil dan lainnya mendapat **409**. Respons 409 tidak mengubah cookie dan tidak mencabut sesi. FE perlu menunggu refresh tab lain lalu mencoba sekali lagi dengan cookie terbaru, atau mengoordinasikan refresh lintas tab. Single promise dalam satu tab saja belum mencukupi. Jika respons rotasi hilang sebelum browser menerima cookie, pengguna harus login kembali; tidak ada grace period untuk replay token lama.

Token lama disimpan sebagai hash agar logout yang terlambat tetap dapat mencabut sesi. Jadwalkan pembersihan `browser_session` yang expired (misalnya setelah retensi operasional); token terkait terhapus melalui ON DELETE CASCADE. Jangan menghapus token rotasi dari sesi aktif.

## Otorisasi fitur

Repo ini hanya memuat endpoint autentikasi. `RequirePermission("permission.code")` harus dipasang sebelum setiap handler fitur yang ditambahkan di repo ini. Middleware memvalidasi JWT RS256 beserta expiry/issuer/audience, sesi aktif, scope tenant/sekolah terhadap pengguna saat ini, dan permission terkini dari database. Logout langsung membatalkan validasi access token sesi tersebut.

POST /v1/auth/validate-token menggunakan pemeriksaan sesi dan mewajibkan bearer token serta tenant_uuid/school_uuid. Layanan fitur di repo lain tetap perlu memasang pemeriksaan permission dan scope sendiri sebelum mutasi; memvalidasi tanda tangan JWT saja tidak memeriksa pencabutan sesi.

Semua respons melalui router utama memakai Cache-Control: no-store. Header Authorization dan body request tidak lagi dicetak ke log. Respons error publik menggunakan boolean dan tidak membocorkan pesan error internal.

## Verifikasi

`go test ./...` menguji CSRF, preflight CORS, konfigurasi origin gagal tertutup, atribut/penghapusan cookie, logout berulang tanpa kredensial, dan penolakan token kosong sebelum akses database. `go vet ./...` memeriksa kode.

Sebelum rilis, jalankan migrasi pada database pengujian dan uji login RSA, refresh setelah tutup/buka PWA, expiry, refresh bersamaan (200/409), logout yang bersamaan dengan refresh, perubahan permission/scope, serta isolasi dua perangkat. Pengujian HTTP lokal tidak membuktikan integrasi PostgreSQL, penerimaan cookie oleh browser, atau IndexedDB FE.
