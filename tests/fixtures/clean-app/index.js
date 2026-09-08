// FIXTURE: a well-behaved app — secrets come from the environment.
const express = require('express');
const app = express();

const apiKey = process.env.OPENAI_API_KEY;
if (!apiKey) throw new Error('Set OPENAI_API_KEY in your .env file');

app.listen(process.env.PORT || 3000);
