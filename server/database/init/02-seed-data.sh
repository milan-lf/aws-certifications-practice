#!/bin/bash
# This script runs inside the PostgreSQL container on first init.
# It only creates the schema (handled by 01-schema.sql).
# Test data seeding is handled by the server on startup (see server/database/seedOnStart.js).
echo "Schema initialized. Test data will be seeded by the server on first connection."
