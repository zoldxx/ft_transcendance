from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from rest_framework.routers import DefaultRouter
# from .views import UserViewSet
from . import views
from .views import MyTokenObtainPairView, MyTokenRefreshView

#*******
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from rest_framework.routers import DefaultRouter
# from .views import UserViewSet
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from rest_framework_simplejwt import views as jwt_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('getUserList/', views.getUserList, name='getUserList'),
    path('handleRequest/', views.handleRequest, name='handleRequest'),
    path('getFriendsUserList/', views.getFriendsUserList, name='getFriendsUserList'),
    path('addFriend/', views.addFriend, name='addFriend'),
    path('set_offline/', views.set_offline, name='set_offline'),
    path('get_auth_key/', views.get_auth_key, name='get_auth_key'),
    path('checkLogin/', views.checkLogin, name='checkLogin'),
	path('register_api/', views.register_api, name='register_api'),
	path('register_42_api/', views.register_42_api, name='register_42_api'),
    path('api-auth/', include('rest_framework.urls')),
    path('api/token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/token/', MyTokenRefreshView.as_view(), name='token_refresh'),
    path('save_key/<int:user_id>/', views.save_key, name='save_key'),
    path('send_key/', views.send_key, name='send_key'),
    path('get_user/<int:user_id>/', views.get_user, name='get_user'),
    path('getUserDetail/<int:id>/', views.getUserDetail, name='getUserDetail'),
    path('checkLogin/', views.checkLogin, name='checkLogin'),
    path('editnickname/<int:id>/', views.editnickname, name='editnickname'),
    path('editavatar/<int:id>/', views.editavatar, name='editavatar'),
    path('editpassword/<int:id>/', views.editpassword, name='editpassword'),
    path('set_double_auth/<int:user_id>/', views.set_double_auth, name='set_double_auth'),
    path('get_key/<int:user_id>/', views.get_key, name='get_key'),
    path('winrate/', views.winrate, name='winrate'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
