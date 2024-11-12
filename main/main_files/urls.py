from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.base, name='base'),
    path('login/', views.login_view, name='login'),	
    path('photo/', views.photo, name='photo'),
    path('home/', views.base, name='home'),
    path('about/', views.about, name='about'),
    path('activea2f/', views.activea2f, name='a2f'),
    path('addFriend/', views.addFriend, name='addFriend'),
    path('friendlist/', views.friendlist, name='friendlist'),
    path('handleRequest/', views.handleRequest, name='handleRequest'),
    path('logout/', views.logout_view, name='logout'),
    # path('game/get_rooms/', views.get_rooms, name='get_rooms'),
    path('game/online/room/', views.online_room, name='game_online_room'),
    path('game/online/<str:roomName>/', views.online_game, name='game_online_game'),
    path('game/tournament/room/', views.tournament_room, name='game_tournament_room'),
    path('game/tournament/<str:roomTournamentName>/', views.tournament_display, name='game_tournament_display'),
    path('game/tournament/local/', views.local_tournament, name='game_tournament_local'),
    path('game/local/', views.local, name='game_local'),
    path('users/', views.userList, name='user_list'),
    path('register/', views.register_view, name='register'),
    path('login-with-42/', views.login_with_42, name='login_with_42'),
    path('callback-42/', views.callback_42, name='callback_42'),
    path('generate-qr-code/', views.generate_qr_code, name='generate_qr_code'),
    path('refresh-token/', views.refreshToken, name='refresh_token'),
    path('profile/', views.profile, name='profile'),
    path('historic/', views.historic, name='historic'),
    path('profile/change_nickname/', views.change_nickname, name='change_nickname'),
    path('profile/change_avatar/', views.change_avatar, name='change_avatar'),
    path('profile/change_password/', views.change_password, name='change_password'),
    path('users/<int:id>/', views.user_detail, name='profile'),
    path('users/<int:id>/change_nickname/', views.change_nickname, name='change_nickname'),
    path('users/<int:id>/change_avatar/', views.change_avatar, name='change_avatar'),
    # path('login/', views.LoginPageView.as_view(), name='login'),
    path('login_code.', views.login_code, name='login_code'),
    path('logout_view/', views.logout_view, name='logout_view'),
    path('generate-qr-code/', views.generate_qr_code, name='generate_qr_code'),
    path('verify_code/', views.verify_code, name='verify_code'),
    path('verify_login_code/', views.verify_login_code, name='verify_login_code'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
