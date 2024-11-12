#!/bin/bash

echo "Checking PostgreSQL readiness..."
until pg_isready -h $GAME_HOST -U $GAME_USER -d $GAME_DB; do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 1
done

echo "PostgreSQL is up - executing migrations..."
python manage.py makemigrations game_files
python manage.py makemigrations
python manage.py migrate

echo "Starting Daphne server..."
exec daphne -b 0.0.0.0 -p 8002 game_files.asgi:application
