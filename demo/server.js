const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const os = require('os');

const app = express();
const isLanFlag = process.argv.includes('--lan');
const PORT = process.env.PORT || 3000;
const HOST = isLanFlag ? '0.0.0.0' : (process.env.HOST || '127.0.0.1');

// Serwowanie plików statycznych z katalogu public
app.use(express.static(path.join(__dirname, 'public')));

// Inicjalizacja bazy danych SQLite w pamięci RAM (in-memory)
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      password TEXT NOT NULL,
      credit_card TEXT NOT NULL,
      role TEXT NOT NULL
    )
  `);

  const stmt = db.prepare(
    'INSERT INTO users (username, password, credit_card, role) VALUES (?, ?, ?, ?)'
  );

  const seedUsers = [
    ['admin', 'Sup3rS3cret_Root#2026!', '4532-8910-4421-9001 (Corp VIP)', 'Administrator Systemu'],
    ['j.kowalski', 'Wiosna2025!@#', '5412-7534-8890-1123', 'Starszy Księgowy'],
    ['a.nowak', 'Koteczek123', '4916-3321-6754-0987', 'Specjalista HR'],
    ['m.wisniewski', 'HasloDoBanku99', '5105-1051-0510-5100', 'Dyrektor Finansowy (CFO)']
  ];

  seedUsers.forEach((user) => stmt.run(user));
  stmt.finalize();

  // Zabezpieczenie bazy w tryb Read-Only (nikt z zewnątrz nie usunie ani nie nadpisze danych)
  db.run('PRAGMA query_only = ON;');
});

// ============================================================================
// TRYB A: PODATNY ENDPOINT (Insecure Design: Brak walidacji, konkatenacja,
//         SELECT * łamiący Least Privilege oraz wyciek błędów bazy danych)
// ============================================================================
app.get('/api/vulnerable/users', (req, res) => {
  const id = req.query.id || '';

  // 1. LUKA SQL INJECTION: Zwykła konkatenacja stringów
  // 2. BRAK LEAST PRIVILEGE: SELECT * pobiera również hasła i karty kredytowe
  const unsafeQuery = `SELECT * FROM users WHERE id = ${id}`;

  db.all(unsafeQuery, (err, rows) => {
    if (err) {
      // 3. BRAK FAIL-SECURE: Ujawnienie surowego błędu silnika SQLite i struktury zapytania
      return res.status(500).json({
        status: 'error',
        mode: 'vulnerable',
        error: `SQLITE_ERROR: ${err.message}`,
        executedQuery: unsafeQuery,
        details:
          'Wyciek informacji technicznych (Information Disclosure): serwer ujawnił silnik bazy danych (SQLite), nazwę tabeli (users) oraz pełną składnię nieprzefiltrowanego zapytania.'
      });
    }

    res.json({
      status: 'success',
      mode: 'vulnerable',
      executedQuery: unsafeQuery,
      leaked: rows.length > 1,
      count: rows.length,
      data: rows
    });
  });
});

// ============================================================================
// TRYB B: BEZPIECZNY ENDPOINT (Security by Design:
//         Allow-Listing + Parameterized Queries + Least Privilege + Fail-Secure)
// ============================================================================
app.get('/api/secure/users', (req, res) => {
  const id = req.query.id || '';

  // 1. ZERO-TRUST & ALLOW-LISTING: Akceptujemy wyłącznie dodatnie liczby całkowite
  const isStrictNumber = /^\d+$/.test(id);
  if (!isStrictNumber) {
    // 2. ZASADA FAIL-SECURE: Odrzucenie żądania u źródła bez ujawniania logów bazy
    return res.status(400).json({
      status: 'blocked',
      mode: 'secure',
      message: 'Atak SQL Injection zablokowany u źródła. Nieprawidłowy format danych.'
    });
  }

  // 3. LEAST PRIVILEGE (Minimalizacja danych): Pobieramy TYLKO publiczne kolumny
  // 4. PARAMETERIZED QUERIES: Bindowanie parametru (?) oddziela kod od danych
  const safeQuery = 'SELECT id, username, role FROM users WHERE id = ?';
  const numericId = parseInt(id, 10);

  db.all(safeQuery, [numericId], (err, rows) => {
    if (err) {
      // ZASADA FAIL-SECURE: Logowanie błędu tylko wewnętrznie, bezpieczny komunikat na zewnątrz
      console.error('[Internal DB Error]:', err.message);
      return res.status(500).json({
        status: 'error',
        mode: 'secure',
        message: 'Wystąpił błąd przetwarzania żądania.'
      });
    }

    res.json({
      status: 'success',
      mode: 'secure',
      executedQuery: `SELECT id, username, role FROM users WHERE id = ?   [Zbindowany parametr: ${numericId}]`,
      leaked: false,
      count: rows.length,
      data: rows
    });
  });
});

function getLocalIPv4Addresses() {
  const interfaces = os.networkInterfaces();
  const addresses = [];
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name] || []) {
      if ((iface.family === 'IPv4' || iface.family === 4) && !iface.internal) {
        addresses.push(iface.address);
      }
    }
  }
  return addresses;
}

app.listen(PORT, HOST, () => {
  console.log(`[Hack & Secure Sandbox] Serwer uruchomiony lokalnie: http://localhost:${PORT}`);
  if (HOST === '0.0.0.0' || isLanFlag) {
    const lanIps = getLocalIPv4Addresses();
    if (lanIps.length > 0) {
      lanIps.forEach((ip) => {
        console.log(`[Hack & Secure Sandbox] Dostęp w sieci lokalnej (LAN / Wi-Fi): http://${ip}:${PORT}`);
      });
    } else {
      console.log(`[Hack & Secure Sandbox] Nasłuchiwanie na http://0.0.0.0:${PORT}`);
    }
  }
});
