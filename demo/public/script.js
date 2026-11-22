// Aktualny stan architektury ('vulnerable' = Tryb A, 'secure' = Tryb B)
let currentMode = 'vulnerable';

// Referencje do elementów DOM
const bodyEl = document.body;
const btnModeA = document.getElementById('btnModeA');
const btnModeB = document.getElementById('btnModeB');
const architectureStatusBadge = document.getElementById('architectureStatusBadge');
const endpointBadge = document.getElementById('endpointBadge');
const codePreviewA = document.getElementById('codePreviewA');
const codePreviewB = document.getElementById('codePreviewB');

// Pasek 4 filarów SbD
const pillarValidationState = document.getElementById('pillarValidationState');
const pillarQueryState = document.getElementById('pillarQueryState');
const pillarPrivilegeState = document.getElementById('pillarPrivilegeState');
const pillarFailState = document.getElementById('pillarFailState');

// Nagłówki wrażliwych kolumn w tabeli
const thPassword = document.getElementById('thPassword');
const thCreditCard = document.getElementById('thCreditCard');

const searchForm = document.getElementById('searchForm');
const userIdInput = document.getElementById('userIdInput');
const executedSqlPreview = document.getElementById('executedSqlPreview');

const breachBanner = document.getElementById('breachBanner');
const shieldBanner = document.getElementById('shieldBanner');
const errorBanner = document.getElementById('errorBanner');
const errorBannerText = document.getElementById('errorBannerText');
const errorBannerQuery = document.getElementById('errorBannerQuery');
const errorBannerQueryRow = document.getElementById('errorBannerQueryRow');
const errorBannerDetails = document.getElementById('errorBannerDetails');
const tableWrapper = document.getElementById('tableWrapper');
const resultsTableBody = document.getElementById('resultsTableBody');
const recordCountBadge = document.getElementById('recordCountBadge');

// Przełączanie pomiędzy Trybem A (Podatny) a Trybem B (Security by Design)
function setMode(mode) {
  currentMode = mode;

  if (mode === 'vulnerable') {
    bodyEl.className = 'mode-vulnerable';
    btnModeA.className = 'mode-btn active-vulnerable';
    btnModeB.className = 'mode-btn';

    architectureStatusBadge.textContent = 'Architektura podatna';
    architectureStatusBadge.className = 'status-pill pill-danger';

    pillarValidationState.textContent = 'Brak (pełne zaufanie do frontendu)';
    pillarQueryState.textContent = 'Konkatenacja stringów (${id})';
    pillarPrivilegeState.textContent = 'SELECT * (pobiera hasła i karty)';
    pillarFailState.textContent = 'Wyciek surowych logów SQLite';

    endpointBadge.textContent = 'GET /api/vulnerable/users';
    codePreviewA.classList.remove('hidden');
    codePreviewB.classList.add('hidden');
  } else {
    bodyEl.className = 'mode-secure';
    btnModeA.className = 'mode-btn';
    btnModeB.className = 'mode-btn active-secure';

    architectureStatusBadge.textContent = 'Security by Design aktywne';
    architectureStatusBadge.className = 'status-pill pill-secure';

    pillarValidationState.textContent = 'Allow-Listing (Tylko liczby /^\\d+$/)';
    pillarQueryState.textContent = 'Parameterized Queries (?)';
    pillarPrivilegeState.textContent = 'Tylko id, username, role';
    pillarFailState.textContent = 'Zablokowano wyciek błędów DB';

    endpointBadge.textContent = 'GET /api/secure/users';
    codePreviewA.classList.add('hidden');
    codePreviewB.classList.remove('hidden');
  }

  // Automatyczne odświeżenie zapytania po przełączeniu architektury
  executeSearch();
}

btnModeA.addEventListener('click', () => setMode('vulnerable'));
btnModeB.addEventListener('click', () => setMode('secure'));

// Obsługa przycisków scenariuszy testowych
document.querySelectorAll('.chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    userIdInput.value = chip.getAttribute('data-payload');
    executeSearch();
  });
});

// Obsługa formularza wyszukiwania
searchForm.addEventListener('submit', (e) => {
  e.preventDefault();
  executeSearch();
});

async function executeSearch() {
  const queryVal = userIdInput.value.trim();
  if (!queryVal) return;

  // Reset komunikatów przed zapytaniem
  breachBanner.classList.add('hidden');
  shieldBanner.classList.add('hidden');
  errorBanner.classList.add('hidden');

  const endpoint =
    currentMode === 'vulnerable'
      ? `/api/vulnerable/users?id=${encodeURIComponent(queryVal)}`
      : `/api/secure/users?id=${encodeURIComponent(queryVal)}`;

  try {
    const response = await fetch(endpoint);
    const result = await response.json();

    // SCENARIUSZ 1: Atak zablokowany w Trybie B (Security by Design)
    if (response.status === 400 && result.status === 'blocked') {
      executedSqlPreview.textContent =
        'ZAPYTANIE ZABLOKOWANE PRZED BAZĄ DANYCH (Warstwa Allow-Listing odrzuciła wejście)';
      tableWrapper.classList.add('hidden');
      shieldBanner.classList.remove('hidden');
      return;
    }

    // SCENARIUSZ 2: Błąd składni SQL w Trybie A (naruszenie Fail-Secure)
    if (!response.ok) {
      const leakedQuery = result.executedQuery || '';
      executedSqlPreview.textContent = leakedQuery || 'Błąd wykonania zapytania';
      tableWrapper.classList.add('hidden');
      errorBannerText.textContent = result.error || result.message || 'Błąd serwera';
      if (leakedQuery) {
        errorBannerQuery.textContent = leakedQuery;
        errorBannerQueryRow.classList.remove('hidden');
      } else {
        errorBannerQuery.textContent = '';
        errorBannerQueryRow.classList.add('hidden');
      }
      errorBannerDetails.textContent = result.details || '';
      errorBanner.classList.remove('hidden');
      return;
    }

    // SCENARIUSZ 3: Zwrócono dane z bazy
    executedSqlPreview.textContent = result.executedQuery;
    renderTable(result.data, result.leaked, result.mode);
  } catch (err) {
    errorBannerText.textContent = 'Brak połączenia z serwerem lokalnym.';
    errorBannerQuery.textContent = '';
    errorBannerQueryRow.classList.add('hidden');
    errorBannerDetails.textContent = '';
    errorBanner.classList.remove('hidden');
  }
}

function renderTable(users, isBreach, mode) {
  tableWrapper.classList.remove('hidden');
  resultsTableBody.innerHTML = '';

  // Dostosowanie nagłówków kolumn wrażliwych w zależności od trybu (Least Privilege)
  if (mode === 'secure') {
    thPassword.textContent = 'Hasło (Least Privilege)';
    thPassword.className = 'protected-col';
    thCreditCard.textContent = 'Karta kredytowa (Least Privilege)';
    thCreditCard.className = 'protected-col';
  } else {
    thPassword.textContent = 'Hasło (Plaintext)';
    thPassword.className = 'sensitive-col';
    thCreditCard.textContent = 'Karta kredytowa';
    thCreditCard.className = 'sensitive-col';
  }

  if (isBreach) {
    breachBanner.classList.remove('hidden');
    recordCountBadge.textContent = `Wyciek: ${users.length} rekordy`;
    recordCountBadge.classList.add('count-breach');
  } else {
    recordCountBadge.textContent = `${users.length} rekord(y)`;
    recordCountBadge.classList.remove('count-breach');
  }

  if (users.length === 0) {
    const emptyRow = document.createElement('tr');
    emptyRow.innerHTML = `<td colspan="5" class="empty-row-cell">Brak pracownika o podanym ID.</td>`;
    resultsTableBody.appendChild(emptyRow);
    return;
  }

  users.forEach((user) => {
    const tr = document.createElement('tr');
    if (isBreach) tr.classList.add('row-leaked');

    const isAdmin = user.username.toLowerCase() === 'admin';
    const roleClass = isAdmin ? 'role-badge role-admin' : 'role-badge';

    // W Trybie B backend w ogóle nie zwraca pól password i credit_card (zasada Least Privilege)
    const passwordCell =
      user.password !== undefined
        ? `<td class="cell-sensitive">${escapeHtml(user.password)}</td>`
        : `<td class="cell-protected">Niepobrane z bazy (Least Privilege)</td>`;

    const cardCell =
      user.credit_card !== undefined
        ? `<td class="cell-sensitive">${escapeHtml(user.credit_card)}</td>`
        : `<td class="cell-protected">Niepobrane z bazy (Least Privilege)</td>`;

    tr.innerHTML = `
      <td class="cell-id">#${escapeHtml(String(user.id))}</td>
      <td><strong>${escapeHtml(user.username)}</strong></td>
      <td><span class="${roleClass}">${escapeHtml(user.role)}</span></td>
      ${passwordCell}
      ${cardCell}
    `;

    resultsTableBody.appendChild(tr);
  });
}

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Załadowanie początkowego rekordu (ID = 2) na starcie aplikacji
window.addEventListener('DOMContentLoaded', () => {
  executeSearch();
});
