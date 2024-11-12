#!/bin/bash

python manage.py makemigrations main_files
python manage.py makemigrations
python manage.py migrate
# python manage.py collectstatic --noinput


# chmod -R 755 /app/static
# chown -R www-data:www-data /app/static

exec gunicorn --bind 0.0.0.0:8001 main_files.wsgi:application
# python manage.py runserver 0.0.0.0:8001