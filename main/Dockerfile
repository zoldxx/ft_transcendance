# Utiliser une image de base officielle Python
FROM python:3.10-slim

# Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Installer les dépendances système nécessaires
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers de l'application dans le conteneur
COPY . /app

# Installer les dépendances Python
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# RUN python manage.py collectstatic --noinput
# RUN python manage.py migrate

# Exposer le port sur lequel l'application va s'exécuter
EXPOSE 8001

# Commande pour exécuter l'application
ENTRYPOINT [ "./main.sh" ]

# CMD ["python", "manage.py", "runserver", "0.0.0.0:8001"]
