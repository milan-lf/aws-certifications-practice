/**
 * Seed test data on server startup if the database is empty.
 * Runs automatically when the server starts — idempotent (uses ON CONFLICT).
 */

const fs = require('fs');
const path = require('path');

const TEST_DATA_PATH = path.join(__dirname, '../test-data');

async function seedIfEmpty(pool) {
  const client = await pool.connect();

  try {
    // Check if tests already exist
    const { rows } = await client.query('SELECT COUNT(*) AS count FROM tests');
    const testCount = parseInt(rows[0].count, 10);

    if (testCount > 0) {
      console.log(`Database already has ${testCount} tests — skipping seed.`);
      return;
    }

    console.log('Database is empty — seeding test data...');

    const testsConfigPath = path.join(TEST_DATA_PATH, 'tests.json');
    if (!fs.existsSync(testsConfigPath)) {
      console.warn('No tests.json found in test-data/ — skipping seed.');
      return;
    }

    const testsConfig = JSON.parse(fs.readFileSync(testsConfigPath, 'utf8'));
    console.log(`Found ${testsConfig.tests.length} tests to seed.`);

    await client.query('BEGIN');

    // Insert test metadata
    for (const test of testsConfig.tests) {
      await client.query(
        `INSERT INTO tests (id, name, description, category, difficulty, total_questions, time_limit, passing_score)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (id) DO NOTHING`,
        [test.id, test.name, test.description, test.category, test.difficulty, test.totalQuestions, test.timeLimit, test.passingScore]
      );
    }

    // Insert questions for each test
    for (const test of testsConfig.tests) {
      const questionsFilePath = path.join(TEST_DATA_PATH, test.filename);
      if (!fs.existsSync(questionsFilePath)) {
        console.warn(`  Questions file not found: ${test.filename} — skipping.`);
        continue;
      }

      const questionsData = JSON.parse(fs.readFileSync(questionsFilePath, 'utf8'));
      const questions = questionsData.questions || [];
      let inserted = 0;

      for (const q of questions) {
        if (!q.question_id || !q.question_text || !q.choices || !q.correct_answer) continue;

        const hasValidChoices = Object.values(q.choices).some(
          (c) => typeof c === 'string' && c.trim().length > 0
        );
        if (!hasValidChoices && !q.question_text.includes('//IMG//')) continue;

        await client.query(
          `INSERT INTO questions (id, test_id, question_number, question_text, choices, correct_answer, is_multiple_choice, question_images, answer_images, discussion, discussion_count)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           ON CONFLICT (id) DO NOTHING`,
          [
            q.question_id,
            test.id,
            q.question_number || 0,
            q.question_text,
            JSON.stringify(q.choices),
            q.correct_answer,
            q.is_multiple_choice || false,
            q.question_images || null,
            q.answer_images || null,
            q.discussion ? JSON.stringify(q.discussion) : null,
            q.discussion_count || 0,
          ]
        );
        inserted++;
      }

      console.log(`  ${test.id}: ${inserted} questions seeded.`);
    }

    await client.query('COMMIT');

    const { rows: summary } = await client.query('SELECT COUNT(*) AS count FROM questions');
    console.log(`Seed complete: ${summary[0].count} total questions in database.`);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Seed failed:', err.message);
  } finally {
    client.release();
  }
}

module.exports = { seedIfEmpty };
