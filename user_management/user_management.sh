#!/bin/bash

# Attendre que la base de données PostgreSQL soit disponible
until pg_isready -h $UM_HOST -U $UM_USER -d $UM_DB; do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 1
done

python manage.py makemigrations user_management_files
python manage.py makemigrations
python manage.py migrate

# Créer le superuser Django
echo "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(login='$DJANGO_SUPERUSER_USERNAME').exists():
    user = User.objects.create_superuser('$DJANGO_SUPERUSER_USERNAME', '$DJANGO_SUPERUSER_EMAIL', '$DJANGO_SUPERUSER_PASSWORD')
    user.is_staff = True
    user.save()
" | python manage.py shell

echo "Superuser created"

python manage.py runserver 0.0.0.0:8003
# gunicorn --bind 0.0.0.0:8003 user_management_files.wsgi:application