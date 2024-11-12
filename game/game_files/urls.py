from django.urls import path
from . import views

urlpatterns = [
	# path('get_rooms/', views.get_rooms, name='get_rooms'),
	# path('start/', views.start_game, name='start_game'),
    # path('update/', views.update_game, name='update_game'),
    # path('stop/', views.stop_game, name='stop_game'),
    path('historic/', views.historic, name='historic'),
    path('historic_profile/<int:id>/', views.historic_profile, name='historic_profile'),
]
