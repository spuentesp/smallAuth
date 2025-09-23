#!/bin/bash
# Start a local PostgreSQL container for development

docker run --rm -d \
  --name smallauth-postgres \
  -e POSTGRES_DB=smallauth \
  -e POSTGRES_USER=your_db_user \
  -e POSTGRES_PASSWORD=your_db_password \
  -p 5432:5432 \
  -v $(pwd)/migrations:/docker-entrypoint-initdb.d \
  postgres:16

echo "PostgreSQL is running on port 5432."
