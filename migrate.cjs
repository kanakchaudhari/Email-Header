const { Client } = require('pg');
const fs = require('fs');
const path = require('path');

const connectionString = 'postgresql://postgres.kvrkvxsicoqfkszjmxhd:i071AxO7c8gmVjSZ@aws-0-ap-northeast-1.pooler.supabase.com:6543/postgres';

async function migrate() {
    const client = new Client({
        connectionString,
        ssl: { rejectUnauthorized: false }
    });
    
    try {
        await client.connect();
        console.log('Connected to Supabase PostgreSQL database.');
        
        // 1. Run Schema Migrations
        const sqlPath = path.join(__dirname, 'supabase', 'migrations', '20260801000000_initial_schema.sql');
        const sql = fs.readFileSync(sqlPath, 'utf8');
        await client.query(sql);
        console.log('Schema migration executed successfully!');

        // 2. Run Seed File
        const seedPath = path.join(__dirname, 'supabase', 'seed.sql');
        if (fs.existsSync(seedPath)) {
            const seedSql = fs.readFileSync(seedPath, 'utf8');
            await client.query(seedSql);
            console.log('Seed data inserted successfully!');
        }
        
    } catch (err) {
        console.error('Error during migration/seeding:', err);
    } finally {
        await client.end();
    }
}

migrate();

