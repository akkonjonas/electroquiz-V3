# Electro Quiz · Cuentas con huella + progreso en tu servidor

Con esto cada alumno:
1. **Crea su cuenta una sola vez** con su nombre + un **código de activación que solo vos le das por WhatsApp** (sirve una única vez).
2. **Entra siempre con su huella digital** (no hay contraseña ni código para compartir).
3. **No pierde el progreso**: se guarda en tu base de datos y se recupera en cualquier momento.

Vos manejás todo desde una página privada: `admin.html`.

---

## Lo que vas a crear (todo gratis para empezar)

| Servicio | Para qué | Cuenta |
|---|---|---|
| **GitHub Pages** | Aloja la app (la página) | github.com |
| **Supabase** | Base de datos + validación de códigos y huellas | supabase.com |

> GitHub solo guarda archivos: no puede guardar datos ni validar códigos. Por eso se usa Supabase como tu "servidor".

---

## PASO 1 · Subir la app a GitHub

1. Entrá a **github.com** y creá tu cuenta (o iniciá sesión).
2. Tocá **New repository**. Nombre: `electro-quiz`. Dejalo **Public**. Tocá **Create repository**.
3. Tocá **uploading an existing file** y subí **todos los archivos** de esta carpeta (excepto la carpeta `supabase` y este LEEME, que no hacen falta en la página):
   `index.html`, `preguntas.js`, `sw.js`, `manifest.json`, `icon.svg`, `guia_pdf.js`, `Guia_Proyecto_Electrico.pdf`, `admin.html`.
   Tocá **Commit changes**.
4. Andá a **Settings → Pages**. En *Branch* elegí `main` y la carpeta `/ (root)`. Guardá.
5. Esperá 1–2 minutos. GitHub te muestra la dirección de tu app, por ejemplo:
   `https://TUUSUARIO.github.io/electro-quiz/`
   Anotá estas dos cosas (las vas a necesitar en el paso 2):
   - **RP_ID** = `TUUSUARIO.github.io` (solo el dominio, sin https://)
   - **ORIGIN** = `https://TUUSUARIO.github.io` (sin barra al final y sin `/electro-quiz`)

⚠️ **No cambies esa dirección después**: las huellas quedan atadas a ella. Si algún día la cambiás, todos deberían volver a activar su cuenta (con códigos nuevos).

---

## PASO 2 · Crear tu servidor en Supabase

1. Entrá a **supabase.com** → *Start your project* → creá tu cuenta.
2. **New project**: nombre `electro-quiz`, una contraseña (guardala), región **South America (São Paulo)**. Esperá a que termine de crearse.
3. **Crear las tablas**: menú **SQL Editor → New query**. Abrí el archivo `supabase/schema.sql`, copiá **todo** su contenido, pegalo y tocá **Run**. Debe decir *Success*.
4. **Crear la función**: menú **Edge Functions → Deploy a new function → Via Editor**.
   - Nombre exacto: `api`
   - Borrá el texto de ejemplo, pegá **todo** el contenido de `supabase/functions/api/index.ts` y tocá **Deploy**.
   - Entrá a la función `api` → **Details / Settings** y **apagá "Verify JWT"** (Enforce JWT verification = OFF). Guardá.
5. **Cargar los 3 secretos**: **Edge Functions → Secrets → Add new secret** (uno por uno):
   - `ADMIN_KEY` = una clave larga que inventes (es tu contraseña de administrador)
   - `RP_ID` = `TUUSUARIO.github.io`
   - `ORIGIN` = `https://TUUSUARIO.github.io`
6. Copiá la **dirección de tu función**: en **Project Settings → API** copiá *Project URL* (algo como `https://abcdefgh.supabase.co`) y agregale al final `/functions/v1/api`. Queda:
   `https://abcdefgh.supabase.co/functions/v1/api`

---

## PASO 3 · Conectar la app con tu servidor

1. En GitHub abrí `index.html` y tocá el lápiz (*Edit*).
2. Buscá esta línea (está al principio del archivo, cerca de `<script>`):
   ```
   window.CFG={API:""};
   ```
3. Pegá tu dirección entre las comillas:
   ```
   window.CFG={API:"https://abcdefgh.supabase.co/functions/v1/api"};
   ```
4. **Commit changes**. Listo.

> Mientras `API` quede vacío, la app funciona como antes (sin cuentas, solo en el teléfono).

---

## PASO 4 · Dar el primer código y probar

1. Abrí `https://TUUSUARIO.github.io/electro-quiz/admin.html`.
2. Pegá la dirección de tu función (la del paso 2.6) y tu `ADMIN_KEY`. Tocá **Entrar**.
3. Escribí el nombre del alumno (solo lo ves vos) → **Generar código** → **Enviar por WhatsApp**. El mensaje ya sale armado con el código y el link.
4. El alumno abre la app, toca **Crear cuenta**, escribe su nombre y el código, y apoya el dedo en el sensor. Desde ahí entra solo con la huella.

Probalo primero con tu propio teléfono.

---

## Cómo funciona (y qué esperar)

- **El código se usa una sola vez**, solo para activar la cuenta. Después ya no se pide.
- **Cambio de teléfono o huella perdida**: en `admin.html`, en el alumno, tocá **Reiniciar / cambio de teléfono**. El teléfono viejo deja de entrar, se genera un código nuevo y el alumno lo usa en el teléfono nuevo con **el mismo nombre**. **Conserva todo su progreso.**
- **Progreso**: se guarda en tu base cada vez que juega. Sin internet sigue funcionando y se sube cuando vuelve la conexión.
- **Ranking**: ahora es de todos los alumnos del curso.
- **Requisitos del teléfono**: tener bloqueo de pantalla con huella configurada, y abrir la app desde Chrome (Android) o Safari (iPhone) en la dirección `https://`.
- El progreso que ya tenían en la versión vieja (otra dirección) **no se traslada** solo, porque el navegador guarda los datos por dirección. Si un alumno lo pierde, empieza de nuevo con su cuenta.
- Plan gratis de Supabase: si nadie usa el proyecto durante **una semana**, se pausa; se reactiva con un botón en su panel. Para más tranquilidad existe el plan pago.

## Límites de seguridad (sé realista)

- La huella no se envía ni se guarda: cada teléfono guarda una llave secreta y el servidor solo guarda la llave pública. El servidor **no puede ver huellas**.
- Esto evita compartir cuentas por contraseña o código. No impide que alguien **preste su teléfono desbloqueado** o registre la huella de otra persona en su teléfono.
- El ranking usa los puntajes que envía la app; una persona técnica podría falsificarlos.
- Elegí una `ADMIN_KEY` larga y no la compartas.

## Si algo falla

- **"Sin conexión con el servidor"**: revisá que la dirección en `CFG.API` esté completa y bien escrita.
- **"dominio inválido" / "origen inválido"**: `RP_ID` u `ORIGIN` no coinciden con la dirección real de tu página.
- **Error 401 en la función**: no apagaste "Verify JWT".
- Mirá los mensajes de error en **Supabase → Edge Functions → api → Logs**.
- **Importante**: esta versión se probó en una computadora con una base PostgreSQL real y huellas simuladas, pero no sobre tu cuenta de Supabase. Si algo falla en la primera instalación, mandame el texto del error y lo ajusto.

## Contenido de la carpeta

- `index.html`, `preguntas.js`, `sw.js`, `manifest.json`, `icon.svg`, `guia_pdf.js`, `Guia_Proyecto_Electrico.pdf`: la app.
- `admin.html`: tu panel privado (genera códigos, ve alumnos, reinicia cuentas).
- `supabase/schema.sql`: crea las tablas.
- `supabase/functions/api/index.ts`: el servidor (huellas, códigos y progreso).
