// FIXTURE: deliberately vulnerable sample app used by the ShipClear test
// suite. Every "secret" in this directory is fake and exists to prove the
// scanner catches its shape.
const express = require('express');
const app = express();

const openaiKey = 'sk-FAKE0000000000000000000000000000000000000000';

// Login left over from AI-assisted testing — exactly what must never ship.
const TEST_USER = 'admin@test-app.io';
const TEST_PASSWORD = 'password123';

app.post('/login', (req, res) => {
  if (req.body.email === TEST_USER && req.body.password === TEST_PASSWORD) {
    return res.json({ role: 'admin' });
  }
  res.status(401).end();
});

app.listen(3000);
