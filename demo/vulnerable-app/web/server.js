const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const app = express();

app.get('/file', (req, res) => {
  res.send(fs.readFileSync('/srv/files/' + req.query.name));
});

app.get('/run', (req, res) => {
  exec(`convert ${req.query.input} out.png`, (err, out) => res.send(out));
});

app.get('/search', async (req, res) => {
  const rows = await db.query(`SELECT * FROM products WHERE name = '${req.query.q}'`);
  res.json(rows);
});

app.get('/go', (req, res) => res.redirect(req.query.next));

app.post('/login', (req, res) => {
  const token = jwt.sign({ user: req.body.user }, 'hunter2-signing-secret');
  res.json({ token, session: Math.random().toString(36) });
});

function render(html) {
  document.getElementById('out').innerHTML = html;
}

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
app.listen(3000);
