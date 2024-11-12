#!/bin/bash

service postgresql start
# Check if the database directory exists
if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "${POSTGRES_DB}"; then
    echo "==> database ${POSTGRES_DB} already exists"
else
    # Start the PostgreSQL service
    sleep 1

    # Create the database and user
    echo "creating database: ${POSTGRES_DB}"
    sudo -u postgres psql -c "CREATE DATABASE ${POSTGRES_DB};"
    sudo -u postgres psql -c "CREATE USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${POSTGRES_DB} TO ${POSTGRES_USER};"
    sudo -u postgres psql -c "GRANT ALL ON SCHEMA public TO ${POSTGRES_USER}";
    sudo -u postgres psql -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ${POSTGRES_USER}";
    # Grant superuser privileges to the postgres user
    sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD '${POSTGRES_ROOT_PASSWORD}';"

    sleep 1

    # Shutting down PostgreSQL so it can be restarted using exec
    # sudo -u postgres psql pg_ctlcluster $(pg_lsclusters -h | awk '{print $1, $2}') stop
fi

    # Start PostgreSQL using exec
# sudo -u postgres exec -D /var/lib/postgresql/14/main
service postgresql stop
service postgresql start
echo "RUN THE SERVER"
# python manage.py makemigrations
# python manage.py migrate
python manage.py runserver