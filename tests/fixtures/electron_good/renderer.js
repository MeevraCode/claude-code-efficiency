// Test fixture: text goes in as text, not as HTML.
window.notes.list().then((notes) => {
  const list = document.getElementById('list');
  for (const note of notes) {
    const p = document.createElement('p');
    p.textContent = note.text;
    list.appendChild(p);
  }
});
