const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 8080;

// Database setup
const db = new sqlite3.Database('totally_not_my_privateKeys.db', (err) => {
  if (err) {
    console.error("Error opening database:", err.message);
  } else {
    db.run(`
      CREATE TABLE IF NOT EXISTS keys(
        kid TEXT PRIMARY KEY,
        key TEXT NOT NULL,
        exp INTEGER NOT NULL
      )
    `);
  }
});

// Generate and store initial key pairs
async function generateKeyPairs() {
  const now = Math.floor(Date.now() / 1000);

  // Valid key
  const validKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  const validKeyPEM = validKeyPair.toPEM(true);
  const validKid = validKeyPair.kid;
  const validExp = now + 3600; // 1 hour from now
  saveKeyToDB(validKid, validKeyPEM, validExp);

  // Expired key
  const expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  const expiredKeyPEM = expiredKeyPair.toPEM(true);
  const expiredKid = expiredKeyPair.kid;
  const expiredExp = now - 3600; // 1 hour ago
  saveKeyToDB(expiredKid, expiredKeyPEM, expiredExp);
}

function saveKeyToDB(kid, key, exp) {
  db.run(`INSERT OR REPLACE INTO keys (kid, key, exp) VALUES (?, ?, ?)`, [kid, key, exp], function (err) {
    if (err) {
      console.error("Error saving key:", err.message);
    }
  });
}

// Function to retrieve a key from the database
function getKeyFromDB(expired = false) {
  return new Promise((resolve, reject) => {
    const now = Math.floor(Date.now() / 1000);
    const query = expired
      ? `SELECT kid, key FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1`
      : `SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1`;
    
    db.get(query, [now], (err, row) => {
      if (err) {
        reject("Error retrieving key:", err.message);
      } else if (row) {
        resolve(row);
      } else {
        reject("No matching key found.");
      }
    });
  });
}

// Generate JWT using a key from the database
async function generateJWT(expired = false) {
  const { kid, key: keyPEM } = await getKeyFromDB(expired);
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: expired
      ? Math.floor(Date.now() / 1000) - 3600  // 1 hour ago
      : Math.floor(Date.now() / 1000) + 3600  // 1 hour from now
  };
  
  const token = jwt.sign(payload, keyPEM, { algorithm: 'RS256', keyid: kid });
  return token;
}

// POST /auth endpoint
app.post('/auth', async (req, res) => {
  try {
    const expired = req.query.expired === 'true';
    const token = await generateJWT(expired);
    res.send(token);
  } catch (error) {
    res.status(500).send(error.toString());
  }
});

// GET /.well-known/jwks.json endpoint
app.get('/.well-known/jwks.json', (req, res) => {
  const now = Math.floor(Date.now() / 1000);
  db.all(`SELECT kid, key FROM keys WHERE exp > ?`, [now], async (err, rows) => {
    if (err) {
      return res.status(500).send("Error retrieving keys.");
    }

    const jwks = await Promise.all(rows.map(async (row) => {
      const key = await jose.JWK.asKey(row.key, 'pem');
      key.kid = row.kid; // Ensure `kid` matches
      key.use = 'sig';   // Specify key use
      key.alg = 'RS256'; // Specify algorithm
      return key.toJSON();
    }));
    
    res.setHeader('Content-Type', 'application/json');
    res.json({ keys: jwks });
  });
});

// Start the server
generateKeyPairs().then(() => {
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});