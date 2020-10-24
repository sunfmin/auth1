const { Client } = require('pg');

const pgclient = new Client({
    host: process.env.POSTGRES_HOST,
    port: process.env.POSTGRES_PORT,
    user: 'auth1',
    password: '123',
    database: 'auth1_test'
});

pgclient.connect();
