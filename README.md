<img width="2554" height="1772" alt="image" src="https://github.com/user-attachments/assets/63ec2e24-4a94-4afe-bc03-69aae9473fff" />

Herramienta de encriptado y desencriptado de archivos con interfaz web minimalista. Utiliza exclusivamente cifrado autenticado AES-GCM con derivación de claves PBKDF2 a 600.000 iteraciones (estándar OWASP 2024+). Todo el procesamiento ocurre localmente en tu navegador — ningún dato sale de tu máquina.

![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Web-blue)
![Security](https://img.shields.io/badge/encryption-AES--GCM-red)
![KDF](https://img.shields.io/badge/KDF-PBKDF2--600K-orange)
![Kali](https://img.shields.io/badge/Kali-Linux-557C94)

## Índice

- [Características](#características)
- [Seguridad y criptografía](#seguridad-y-criptografía)
- [Formato de archivo `.encrypted` (CVLT v2)](#formato-de-archivo-encrypted-cvlt-v2)
- [Requisitos previos](#requisitos-previos)
- [Instalación en Kali Linux](#instalación-en-kali-linux)
  - [1. Actualizar el sistema](#1-actualizar-el-sistema)
  - [2. Instalar Node.js](#2-instalar-nodejs)
  - [3. Instalar pnpm](#3-instalar-pnpm)
  - [4. Clonar el repositorio](#4-clonar-el-repositorio)
  - [5. Instalar dependencias](#5-instalar-dependencias)
  - [6. Ejecutar en modo desarrollo](#6-ejecutar-en-modo-desarrollo)
  - [7. Compilar para producción (opcional)](#7-compilar-para-producción-opcional)
- [Uso](#uso)
- [Compatibilidad hacia atrás](#compatibilidad-hacia-atrás)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Tecnologías utilizadas](#tecnologías-utilizadas)
- [Recomendaciones de contraseña](#recomendaciones-de-contraseña)
- [Solución de problemas](#solución-de-problemas)
- [Scripts disponibles](#scripts-disponibles)
- [Licencia](#licencia)
- [Aviso legal](#aviso-legal)
- [Créditos](#créditos)
- [Soporte](#soporte)

---

## Características

- **Cifrado autenticado exclusivo (AEAD):**
  - `AES-256-GCM` — Recomendado (confidencialidad + integridad)
  - `AES-128-GCM` — Rápido (confidencialidad + integridad)
  - ~~AES-256-CBC~~ — **Eliminado** por vulnerabilidad a ataques Padding Oracle

- **Derivación de clave reforzada:** PBKDF2-HMAC-SHA256 con **600,000 iteraciones** (mínimo recomendado por OWASP 2024+)

- **Formato versionado CVLT v2:** Cabecera con magic bytes, versión, metadatos autenticados (AAD) y compatibilidad hacia atrás

- **Metadatos autenticados:** El nombre original, tipo MIME, tamaño y timestamp se incluyen como AAD (Additional Authenticated Data) en AES-GCM, garantizando su integridad sin cifrarlos

- **Procesamiento 100% local:** Todo el cifrado ocurre en tu navegador vía Web Crypto API — sin servidores, sin telemetría

- **Interfaz dark/light mode:** Diseño minimalista con tipografía Space Grotesk (titulares) y Space Mono (cuerpo)

- **Animación de desencriptado:** El título se revela con un efecto de caracteres aleatorios al cargar la app

---

## Seguridad y criptografía

### Modelo de amenazas

| Amenaza | Mitigación |
|---------|------------|
| Fuerza bruta sobre contraseña | PBKDF2 con 600K iteraciones + salt aleatorio de 128 bits |
| Tampering del ciphertext | AES-GCM detecta cualquier modificación (AEAD) |
| Tampering de metadatos | Metadatos incluidos como AAD — autenticados por GCM |
| Padding Oracle | AES-CBC eliminado por completo |
| Reutilización de IV/nonce | IV de 96 bits generado con `crypto.getRandomValues()` por cada cifrado |
| Clave en memoria | CryptoKey no extractable (`extractable: false`) |

### Parámetros criptográficos

| Parámetro | Valor |
|-----------|-------|
| Algoritmo | AES-GCM (128 o 256 bits) |
| KDF | PBKDF2-HMAC-SHA256 |
| Iteraciones | 600,000 (v2) / 100,000 (v1 legacy) |
| Salt | 128 bits (16 bytes), aleatorio |
| IV / Nonce | 96 bits (12 bytes), aleatorio |
| Metadatos | JSON UTF-8, autenticados como AAD |


---

## Formato de archivo `.encrypted` (CVLT v2)

Los archivos cifrados por Crypto Vault usan un formato binario propio con la siguiente estructura:

```
Offset  Tamaño       Campo
──────  ───────────  ─────────────────────────────
0       4 bytes      Magic bytes: 'CVLT' (ASCII)
4       1 byte       Versión del formato (2)
5       1 byte       ID del algoritmo (0=AES-256-GCM, 1=AES-128-GCM)
6       16 bytes     Salt (PBKDF2)
22      1 byte       Longitud del IV
23      12 bytes     IV / Nonce (AES-GCM)
35      4 bytes      Longitud de metadatos (big-endian uint32)
39      N bytes      Metadatos JSON (UTF-8, usado como AAD)
39+N    Resto        Ciphertext (AES-GCM, incluye tag de 128 bits)
```

### Metadatos (AAD)

```json
{
  "originalName": "documento.pdf",
  "mimeType": "application/pdf",
  "size": 1048576,
  "timestamp": 1710700800000
}
```

Estos metadatos **no están cifrados** (son legibles en el header), pero están **autenticados** por AES-GCM como Additional Authenticated Data. Cualquier modificación de los metadatos hará fallar la desencriptación.

### Versionado

| Versión | PBKDF2 Iteraciones | Algoritmos | Estado |
|---------|-------------------|------------|--------|
| v2 | 600,000 | AES-GCM only | **Actual** |
| v1 | 100,000 | AES-GCM only | Compatible (lectura) |
| Legacy (sin header CVLT) | 100,000 | AES-GCM | Compatible (lectura) |
| Legacy CBC | 100,000 | AES-CBC | ❌ Rechazado |

---

## Requisitos previos

- Node.js >= 18.x
- pnpm (gestor de paquetes)

---

## Instalación en Kali Linux

### 1. Actualizar el sistema

```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Instalar Node.js

Si no tienes Node.js instalado, puedes hacerlo mediante NodeSource:

```bash
# Instalar curl si no lo tienes
sudo apt install curl -y

# Agregar repositorio de NodeSource (Node.js 20.x LTS)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -

# Instalar Node.js
sudo apt install nodejs -y

# Verificar instalación
node --version
npm --version
```

### 3. Instalar pnpm

```bash
# Instalar pnpm globalmente
npm install -g pnpm

# Verificar instalación
pnpm --version
```

### 4. Clonar el repositorio

```bash
git clone https://github.com/afsh4ck/crypto-vault.git
cd crypto-vault
```

### 5. Instalar dependencias

```bash
pnpm install
```

### 6. Ejecutar en modo desarrollo

```bash
pnpm dev
```

La aplicación estará disponible en: `http://localhost:5173`

### 7. Compilar para producción (opcional)

```bash
# Generar build de producción
pnpm build

# Previsualizar build
pnpm preview
```

---

## Uso

1. **Selecciona el modo:** `ENCRYPT` para encriptar o `DECRYPT` para desencriptar
2. **Elige el algoritmo:** (Solo en modo encriptación) Selecciona entre AES-256-GCM o AES-128-GCM
3. **Carga tu archivo:** Arrastra y suelta o haz clic para seleccionar
4. **Ingresa la contraseña:** Usa una contraseña fuerte (el indicador te mostrará su fortaleza)
5. **Procesa:** El archivo encriptado/desencriptado se descargará automáticamente

<img width="2566" height="1912" alt="image" src="https://github.com/user-attachments/assets/c5aeed14-3ce1-4873-b8c4-a19bc4111083" />
<br><br>

> **Nota:** El algoritmo, la versión y los metadatos se detectan automáticamente al desencriptar. No necesitas recordar qué cifrado usaste ni configurar nada manualmente.

---

## Compatibilidad hacia atrás

| Formato del archivo | ¿Se puede descifrar? | Notas |
|---------------------|---------------------|-------|
| CVLT v2 (actual) | ✅ Sí | 600K iteraciones PBKDF2 |
| CVLT v1 | ✅ Sí | Detecta v1 y usa 100K iteraciones |
| Legacy GCM (sin header CVLT) | ✅ Sí | Formato anterior, 100K iteraciones |
| Legacy CBC | ❌ Rechazado | Muestra error con instrucciones |

---

## Estructura del proyecto

```
crypto-vault/
├── src/
│   ├── App.tsx          # Componente principal con motor criptográfico
│   ├── index.css        # Estilos globales, fuentes y animaciones
│   └── main.tsx         # Punto de entrada de React
├── public/              # Archivos estáticos
├── dist/                # Build de producción (generado)
├── index.html           # HTML principal
├── package.json         # Dependencias del proyecto
├── pnpm-lock.yaml       # Lock file de pnpm
├── vite.config.ts       # Configuración de Vite
├── tailwind.config.js   # Configuración de Tailwind CSS
├── postcss.config.js    # Configuración de PostCSS
└── tsconfig.json        # Configuración de TypeScript
```

---

## Tecnologías utilizadas

| Tecnología | Descripción |
|------------|-------------|
| React 18 | Biblioteca de UI |
| TypeScript | Tipado estático |
| Vite | Build tool ultrarrápido |
| Tailwind CSS | Framework de estilos utilitarios |
| Lucide React | Iconos SVG |
| Web Crypto API | Encriptación nativa del navegador |

---

## Recomendaciones de contraseña

| Fortaleza | Longitud | Ejemplo |
|-----------|----------|---------|
| ❌ Débil | < 6 chars | `abc12` |
| ⚠️ Media | 6-9 chars | `MyPass1!` |
| ✅ Fuerte | 10-13 chars | `Tr0ub4dor&3` |
| 🔒 Segura | ≥ 14 chars | `correct-horse-battery-staple` |

**Recomendaciones:**
- Usa **14+ caracteres** con una mezcla de mayúsculas, minúsculas, números y símbolos
- Considera usar una **passphrase** (frase de contraseña) de 4+ palabras aleatorias
- No reutilices contraseñas — cada archivo debería tener su propia clave
- Usa un **gestor de contraseñas** para almacenar las claves de forma segura

---

## Solución de problemas

### Error: `pnpm: command not found`

```bash
npm install -g pnpm
```

### Error: `node: command not found`

Reinstala Node.js siguiendo los pasos de instalación del punto 2.

### Puerto 5173 en uso

```bash
# Ejecutar en otro puerto
pnpm dev --port 3000
```

### Permisos denegados al ejecutar scripts

```bash
chmod +x node_modules/.bin/*
```

### Error al instalar dependencias

```bash
# Limpiar caché e intentar de nuevo
pnpm store prune
rm -rf node_modules
pnpm install
```

---

## Scripts disponibles

| Comando | Descripción |
|---------|-------------|
| `pnpm dev` | Inicia servidor de desarrollo |
| `pnpm build` | Genera build de producción |
| `pnpm preview` | Previsualiza el build de producción |
| `pnpm lint` | Ejecuta ESLint |

---

## Licencia

Este proyecto está bajo la licencia **MIT**.

---

## Aviso legal

Esta herramienta está diseñada para uso legítimo de protección de datos personales. El autor no se hace responsable del mal uso de esta aplicación. Utilízala de manera ética y responsable.

---

## Créditos
- Autor:       afsh4ck 
- Instagram:   <a href="https://www.instagram.com/afsh4ck">afsh4ck</a>
- Youtube:     <a href="https://youtube.com/@afsh4ck">afsh4ck</a>
- Linkedin:    <a href="https://linkedin.com/in/afsh4ck">afsh4ck</a>

---

## Soporte

<a href="https://www.buymeacoffee.com/afsh4ck" rel="nofollow"><img width="250" align="left">
![buy-me-a-coffe](https://github.com/user-attachments/assets/8c8f9e81-334e-469e-b25e-29888cfc9fcc)
</a>
