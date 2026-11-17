// Test fixture: note text goes into the page as HTML.
window.api.invoke('notes:list').then((notes) => {
  document.getElementById('list').innerHTML = notes.map((n) => '<p>' + n.text + '</p>').join('');
});
