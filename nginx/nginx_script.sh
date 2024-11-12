#!/bin/bash
# Définir les permissions des fichiers statiques
chmod -R 755 /app/static
chown -R www-data:www-data /app/static

# Exécuter le processus Nginx
exec nginx -g 'daemon off;'
