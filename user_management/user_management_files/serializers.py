# Dans user_management_files/serializers.py
from rest_framework import serializers
from .models import User, Friend
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from typing import Dict, Any

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        # Obtenir le token de base en appelant la méthode du parent
        token = super().get_token(user)

        # Ajouter des claims personnalisés
        token['username'] = user.login
        token['nickname'] = user.nickname
        token['email'] = user.email
        token['profile_image_url'] = user.avatar.url # Supposons que 'avatar' est le champ de l'image de profil
        token['a2f_auth'] = user.double_auth_activate

        return token


class UserSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField(use_url=True)
    class Meta:
        model = User
        fields = ['login', 'nickname', 'email', 'avatar', 'nombre_victoire', 'nombre_defaite', 'friends', 'status', 'id', 'double_auth_activate']

class FriendSerializer(serializers.ModelSerializer):
    from_user = UserSerializer()
    to_user = UserSerializer()
    class Meta:
        model = Friend
        fields = ['from_user', 'to_user', 'status']
