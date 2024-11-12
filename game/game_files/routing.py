# # game/routing.py

# from django.urls import re_path
# from . import consumers

# websocket_urlpatterns = [
#     re_path(r'ws/game/$', consumers.GameConsumer.as_asgi()),
# ]

# game/routing.py

from django.urls import path
from . import consumers
from django.conf import settings

websocket_urlpatterns = [
    path('ws/game/<str:room_name>/', consumers.GameConsumer.as_asgi()),
    path('ws/rooms/', consumers.RoomsConsumer.as_asgi()),
    path('ws/tournament/<str:tournament_room_name>/', consumers.TournamentConsumer.as_asgi()),

]
