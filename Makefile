COMPOSE=docker-compose
COMPOSE_FILE=srcs/docker-compose.yml

#Django rules

django:
	$(COMPOSE) build --no-cache
	$(COMPOSE) up -d

front:
	$(COMPOSE) front build
	$(COMPOSE) up -d

down:
	$(COMPOSE) down --remove-orphans

clean: down
	@if [ "$$(docker ps -a -q)" != "" ]; then docker stop $$(docker ps -a -q); fi
	@if [ "$$(docker ps -a -q)" != "" ]; then docker rm $$(docker ps -a -q); fi
	@if [ "$$(docker images -q)" != "" ]; then docker rmi $$(docker images -q); fi
	@if [ "$$(docker volume ls -q)" != "" ]; then docker volume rm $$(docker volume ls -q); fi

fclean: clean
	@docker container prune -f
	@docker image prune -a -f
	@docker volume prune -f
	@docker network prune -f
	@docker system prune -a -f

re: fclean django

venv:
	bash -c "cd srcs"
	bash -c "python -m venv srcs/transcendence_venv"
	bash -c "source srcs/transcendence_venv/bin/activate"
	bash -c "pip install -r srcs/tools/requirements.txt"