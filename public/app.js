const $ = (id) => document.getElementById(id);

async function api(path, method = 'GET', body) {
  const res = await fetch('/api' + path, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) throw new Error((data && data.error) || 'Erreur');
  return data;
}

function show(loggedIn) {
  $('auth').hidden = loggedIn;
  $('app').hidden = !loggedIn;
  if (loggedIn) loadNotes();
}

async function loadNotes() {
  const notes = await api('/notes');
  const list = $('notes');
  list.replaceChildren();
  for (const n of notes) {
    const li = document.createElement('li');
    const title = document.createElement('strong');
    title.textContent = n.title; // textContent : jamais innerHTML (anti-XSS)
    const text = document.createElement('p');
    text.textContent = n.content;
    const del = document.createElement('button');
    del.textContent = 'Supprimer';
    del.addEventListener('click', async () => {
      await api('/notes/' + n.id, 'DELETE');
      loadNotes();
    });
    li.append(title, text, del);
    list.append(li);
  }
}

async function authenticate(action) {
  try {
    await api('/auth/' + action, 'POST', { email: $('email').value, password: $('password').value });
    $('msg').textContent = '';
    $('password').value = '';
    show(true);
  } catch (e) {
    $('msg').textContent = e.message;
  }
}

$('auth-form').addEventListener('submit', (e) => { e.preventDefault(); authenticate('login'); });
$('register').addEventListener('click', () => authenticate('register'));

$('note-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  await api('/notes', 'POST', { title: $('title').value, content: $('content').value });
  e.target.reset();
  loadNotes();
});

$('logout').addEventListener('click', async () => {
  await api('/auth/logout', 'POST');
  show(false);
});

api('/auth/me').then(() => show(true)).catch(() => show(false));