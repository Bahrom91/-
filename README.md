# Private Vault

Bu loyiha ko‘p qurilmali, internet orqali ishlaydigan shaxsiy vault uchun boshlang‘ich to‘liq backend/frontend skeletidir.

## Muhim xavfsizlik

- GitHub Pages faqat frontend uchun mos; maxfiy vault backend'ini GitHub Pages'ga joylashtirmang.
- Ishlab chiqarishda HTTPS majburiy.
- `.env` faylini GitHub'ga yuklamang.
- `INITIAL_PIN` va `INITIAL_PASSWORD` faqat birinchi server ishga tushishida ishlatiladi; keyin database'da bcrypt hash sifatida saqlanadi.
- Vault ma'lumotlari brauzerda AES-GCM bilan shifrlanadi.
- WebAuthn/passkey biometrik bosqich sifatida ishlatiladi.
- Bu kod production security auditidan o'tmagan; haqiqiy iCloud/Google va boshqa muhim parollarni kiritishdan oldin mustaqil audit va backup siyosati kerak.

## Ishga tushirish

1. Node.js LTS o‘rnating.
2. PostgreSQL database yarating.
3. `.env.example` nusxasini `.env` qiling.
4. `.env` ichidagi DATABASE_URL, SESSION_SECRET va WebAuthn qiymatlarini sozlang.
5. `npm install`
6. `psql "$DATABASE_URL" -f schema.sql`
7. `npm start`
8. Brauzerda `http://localhost:3000` oching.

## WebAuthn

`RP_ID` va `ORIGIN` real domeningizga mos bo‘lishi kerak. Localhost testida:
RP_ID=localhost
ORIGIN=http://localhost:3000

Productionda:
RP_ID=your-domain.com
ORIGIN=https://your-domain.com

Safari/WebAuthn biometrikasi user gesture bilan chaqirilishi kerak; tugma bosish orqali chaqirilgan oqim shuning uchun ishlatilgan.

## Dastlabki login

`.env` dagi:
INITIAL_PIN=20082011
INITIAL_PASSWORD=Bahromu

Birinchi kirishdan keyin biometrikani ro‘yxatdan o‘tkazing. Keyin Settings orqali PIN va harfli parolni almashtiring.
