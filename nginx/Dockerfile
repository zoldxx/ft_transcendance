# Utiliser une image de base officielle Nginx
FROM nginx:latest

WORKDIR /app

# Installer les dépendances nécessaires
RUN apt-get update && apt-get install -y openssl

# Crée les répertoires manquants
RUN mkdir -p /etc/nginx/ssl/private /etc/nginx/ssl/certs

# Copier les fichiers de configuration Nginx
COPY /conf/nginx.conf /etc/nginx/nginx.conf
COPY /conf/openssl.cnf /etc/ssl/openssl.cnf
COPY nginx_script.sh /nginx_script.sh

# Créer les certificats SSL
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
	-keyout /etc/nginx/ssl/private/nginx-selfsigned.key \
	-out /etc/nginx/ssl/certs/nginx-selfsigned.crt \
	-config /etc/ssl/openssl.cnf -extensions v3_req

# Définir les permissions du script
RUN chmod +x /nginx_script.sh

# Définir le script d'entrée comme point d'entrée
ENTRYPOINT ["/nginx_script.sh"]

# Exposer le port 443
EXPOSE 443
