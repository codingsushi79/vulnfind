// Labelled benchmark case.
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/a', async (req, res) => {
  const { id, name: userName } = req.query;
  const sql = `SELECT * FROM users WHERE id = ${id}`;
  await db.query(sql); // expect: JS-TAINT-SQLI
  res.sendFile(path.join('/srv', userName)); // expect: JS-TAINT-PATH
  res.send(`<h1>Hello ${userName}</h1>`); // expect: JS-TAINT-XSS
});

app.post('/b', (req, res) => {
  const n = parseInt(req.body.n);
  db.query(`SELECT * FROM t WHERE id = ${n}`); // safe
  exec('ping -c1 ' + req.body.host); // expect: JS-TAINT-CMDI
  const m = /^Bearer (.+)$/.exec(req.headers.authorization); // safe
  fetch('/api/local'); // safe
  axios.get(req.body.url); // expect: JS-TAINT-SSRF
  res.redirect(new URL('/', req.url)); // safe
  res.redirect(req.query.next); // expect: JS-TAINT-REDIRECT
});

function other() {
  const id = 5;
  db.query(`SELECT ${id}`); // safe
  el.innerHTML = userHtml; // expect: JS-XSS-INNERHTML
  const token = jwt.sign({ u: 1 }, 'hunter2-secret'); // expect: JS-HARDCODED-JWT-SECRET
}

function tooltip(point) {
  el.innerHTML = `
    <b>${point.label}</b>`; // expect-above: JS-XSS-INNERHTML
}
