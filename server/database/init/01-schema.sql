-- AWS Practice Test Application Database Schema
-- Consolidated: includes all migrations (001–005)

-- Users table for authentication
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    cognito_sub VARCHAR(255) UNIQUE,
    deleted_at TIMESTAMP DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tests table for practice test metadata
CREATE TABLE tests (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),
    difficulty VARCHAR(50),
    total_questions INTEGER,
    time_limit INTEGER,
    passing_score INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Questions table for individual test questions
CREATE TABLE questions (
    id VARCHAR(50) PRIMARY KEY,
    test_id VARCHAR(50) REFERENCES tests(id) ON DELETE CASCADE,
    question_number INTEGER,
    question_text TEXT NOT NULL,
    choices JSONB NOT NULL,
    correct_answer VARCHAR(10) NOT NULL,
    is_multiple_choice BOOLEAN DEFAULT FALSE,
    question_images TEXT[],
    answer_images TEXT[],
    discussion JSONB,
    discussion_count INTEGER DEFAULT 0,
    search_vector tsvector,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User progress table for Study Mode individual question tracking
CREATE TABLE user_progress (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    test_id VARCHAR(50) REFERENCES tests(id) ON DELETE CASCADE,
    question_id VARCHAR(50) REFERENCES questions(id) ON DELETE CASCADE,
    user_answer VARCHAR(10),
    is_correct BOOLEAN,
    time_taken INTEGER,
    session_type VARCHAR(20) CHECK (session_type IN ('study')) DEFAULT 'study',
    deleted_at TIMESTAMP DEFAULT NULL,
    -- Spaced repetition fields
    correct_count INTEGER DEFAULT 0,
    incorrect_count INTEGER DEFAULT 0,
    ease_factor REAL DEFAULT 2.5,
    interval_days INTEGER DEFAULT 0,
    repetition_count INTEGER DEFAULT 0,
    next_review_at TIMESTAMP,
    mastery_level VARCHAR(20) DEFAULT 'new',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, question_id, session_type),
    CONSTRAINT chk_mastery_level CHECK (mastery_level IN ('new', 'learning', 'reviewing', 'mastered'))
);

-- Mock test results table for complete test sessions
CREATE TABLE mock_test_results (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    test_id VARCHAR(50) REFERENCES tests(id) ON DELETE CASCADE,
    score INTEGER NOT NULL,
    total_questions INTEGER NOT NULL,
    time_spent INTEGER NOT NULL,
    deleted_at TIMESTAMP DEFAULT NULL,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Mock test answers table for individual answers in mock tests
CREATE TABLE mock_test_answers (
    id SERIAL PRIMARY KEY,
    mock_test_result_id INTEGER REFERENCES mock_test_results(id) ON DELETE CASCADE,
    question_id VARCHAR(50) REFERENCES questions(id) ON DELETE CASCADE,
    user_answer VARCHAR(10),
    is_correct BOOLEAN,
    time_taken INTEGER
);

-- Audit logs table for tracking security and application events
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    user_identifier VARCHAR(255),
    ip_address VARCHAR(45),
    details JSONB,
    request_id UUID,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bookmarks table for user question bookmarks
CREATE TABLE bookmarks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    question_id VARCHAR(50) REFERENCES questions(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, question_id)
);

-- Archived mock test results (soft-deleted test result archival)
CREATE TABLE archived_mock_test_results (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    test_id VARCHAR(50),
    score INTEGER NOT NULL,
    total_questions INTEGER NOT NULL,
    time_spent INTEGER NOT NULL,
    completed_at TIMESTAMP,
    deleted_at TIMESTAMP,
    archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Archived mock test answers (soft-deleted test answer archival)
CREATE TABLE archived_mock_test_answers (
    id INTEGER PRIMARY KEY,
    mock_test_result_id INTEGER,
    question_id VARCHAR(50),
    user_answer VARCHAR(10),
    is_correct BOOLEAN,
    time_taken INTEGER,
    archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User settings table for per-user per-feature state
CREATE TABLE user_settings (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    setting_key VARCHAR(100) NOT NULL,
    setting_value TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, setting_key)
);

-- ============================================================================
-- Indexes
-- ============================================================================

CREATE INDEX idx_users_email ON users(email);
CREATE UNIQUE INDEX idx_users_cognito_sub ON users(cognito_sub);
CREATE INDEX idx_questions_test_id ON questions(test_id);
CREATE INDEX idx_questions_search ON questions USING GIN(search_vector);
CREATE INDEX idx_user_progress_user_id ON user_progress(user_id);
CREATE INDEX idx_user_progress_test_id ON user_progress(test_id);
CREATE INDEX idx_user_progress_user_test ON user_progress(user_id, test_id);
CREATE INDEX idx_mock_test_results_user_id ON mock_test_results(user_id);
CREATE INDEX idx_mock_test_results_test_id ON mock_test_results(test_id);
CREATE INDEX idx_mock_test_answers_result_id ON mock_test_answers(mock_test_result_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_identifier);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_bookmarks_user_id ON bookmarks(user_id);
CREATE INDEX idx_user_settings_user_key ON user_settings(user_id, setting_key);

-- ============================================================================
-- Functions and Triggers
-- ============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Auto-update search_vector on questions
CREATE OR REPLACE FUNCTION update_question_search_vector()
RETURNS TRIGGER AS $$
BEGIN
    NEW.search_vector = to_tsvector('english', NEW.question_text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_questions_search_vector
    BEFORE INSERT OR UPDATE OF question_text ON questions
    FOR EACH ROW EXECUTE FUNCTION update_question_search_vector();
