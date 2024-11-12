from django.http import JsonResponse
from django.http import HttpResponse
from .models import User, Friend
from django.views.decorators.csrf import csrf_protect
from .serializers import UserSerializer
import json
from django.contrib.auth import get_user_model, logout as django_logout
from django.contrib.auth import login, authenticate, login as auth_login
from django.contrib.auth import get_user_model
from django.middleware.csrf import get_token
from django.shortcuts import get_object_or_404
from django.http import request
import requests, logging
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.views import TokenRefreshView
from django.conf import settings
import qrcode, jwt, os
from io import BytesIO
import pyotp
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import MyTokenObtainPairSerializer, FriendSerializer
from django.db.models import Q
from django.db import models  # Importez models de Django
from django.template.loader import render_to_string

#***
from django.http import JsonResponse
from django.http import HttpResponse
from .models import User
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from .serializers import UserSerializer
import json
from django.contrib.auth import login, authenticate, login as auth_login
from django.contrib.auth import get_user_model
from django.middleware.csrf import get_token
from django.shortcuts import get_object_or_404
from django.http import request
import requests
import secrets
import jwt
from django.conf import settings
import qrcode
from io import BytesIO
import pyotp
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import logging
logger = logging.getLogger(__name__)
#****

User = get_user_model()

@csrf_protect
def set_offline(request):    
    # Vérifier que la méthode de la requête est POST
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    # Extraire les données JSON de la requête
    try:
        data = json.loads(request.body)
        user_id = data.get('user_id')
        status = data.get('status')
        if not user_id:
            return JsonResponse({'error': 'user_id is required'}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': 'Internal server error'}, status=500)

    # Mettre à jour le statut de l'utilisateur dans la base de données
    try:
        user = User.objects.get(id=user_id)
        user.status = status
        user.save()
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'status': 'success'})

def get_user(request, user_id):
    # Vérifiez si le jeton d'accès est présent dans les en-têtes
    authorization_header = request.headers.get('Authorization')
    if not authorization_header:
        return JsonResponse({'message': 'Access token missing'}, status=401)

    try:
        # Récupérer l'utilisateur par ID
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return JsonResponse({'message': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'message': 'Internal server error'}, status=500)

    # Construire la réponse JSON avec les détails de l'utilisateur
    user_data = {
        'id': user.id,
        'username': user.login,
        'email': user.email,
        'is_api_user': user.is_api_user,
    }
    return JsonResponse(user_data)

def send_key(request):
    # Vérifiez si le jeton d'accès est présent dans les en-têtes
    authorization_header = request.headers.get('Authorization')
    if not authorization_header:
        return JsonResponse({'message': 'Access token missing'}, status=401)

    # Extraire le jeton d'accès de l'en-tête
    #token = authorization_header.split(' ')[1]

    # Optionnel: Vous pouvez ajouter des vérifications pour le jeton ici

    # Obtenir la clé secrète des paramètres (settings)
    secret_key = settings.SECRET_KEY

    # Retourner la clé secrète dans la réponse JSON
    return JsonResponse({'key': secret_key})


def getUserList(request):
    users = User.objects.all()
    users_serializer = UserSerializer(users, many=True)
    return JsonResponse(users_serializer.data, safe=False)

def getFriendsUserList(request):
    access_token = request.COOKIES.get('access_token')
    if not access_token:
        return JsonResponse({'error': 'Access token is required'}, status=401)
     

    try:
        # Décoder le token JWT
        decoded_token = jwt.decode(access_token, os.getenv('DJANGO_SECRET_KEY'), algorithms=['HS256'])
        user_id = decoded_token.get('user_id')
        
        if not user_id:
            return JsonResponse({'error': 'Invalid token'}, status=401)
        # Récupérer l'utilisateur à partir de l'ID
        user = User.objects.get(id=user_id)
    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Invalid token'}, status=401)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    friend = Friend.objects.filter(
        models.Q(from_user=user) | models.Q(to_user=user),
        status='accepted'
    )
    request_send = Friend.objects.filter(
        models.Q(from_user=user),
        status='pending'
    )
    request_received = Friend.objects.filter(
        models.Q(to_user=user),
        status='pending'
    )    

    users = UserSerializer(User.objects.all())
    serializer_friends = FriendSerializer(friend, many=True)
    serializer_requests_s = FriendSerializer(request_send, many=True)
    serializer_requests_r = FriendSerializer(request_received, many=True)
    response_data = {
        'myId': user_id,
        'users': str(users),
        'friends': serializer_friends.data,
        'requests_sent': serializer_requests_s.data,
        'requests_received': serializer_requests_r.data
    }
    return JsonResponse(response_data, safe=False)

def addFriend(request):
    data = json.loads(request.body)
    from_user_id = data['from_user_id']
    to_user_id = data['to_user_id']
    created = None

    from_user = get_object_or_404(User, id=from_user_id)
    to_user = get_object_or_404(User, id=to_user_id)
    try:
        existing_friendship = Friend.objects.get(
            (Q(from_user=from_user, to_user=to_user) | Q(from_user=to_user, to_user=from_user))
        )
    except Friend.DoesNotExist:
        existing_friendship = None
    if (not existing_friendship):
        friend, created = Friend.objects.get_or_create(
            from_user=from_user,
            to_user=to_user,
            defaults={'status': 'pending'}
        )
    if created:
        return JsonResponse({'status': 'Request send'}, status=201)
    if existing_friendship and existing_friendship.status == 'decline':
        existing_friendship.status = 'pending'
        if existing_friendship.from_user == to_user:
            existing_friendship.from_user = from_user
            existing_friendship.to_user = to_user
        existing_friendship.save()
        return JsonResponse({'status': 'Request send'}, status=201)
    elif (existing_friendship and existing_friendship.status == 'pending'):
        return JsonResponse({'status': 'Request already send'}, status=200)
    else:
        return JsonResponse({'status': 'You are already friends'}, status=200)


def handleRequest(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            action = data.get('action')
            from_user_id = data.get('from_user_id')
            to_user_id = data.get('to_user_id')
            
            friend = get_object_or_404(Friend, from_user_id=from_user_id, to_user_id=to_user_id)

            if action == 'accept':
                friend.status = 'accepted'
            else:
                friend.status = 'decline'

            friend.save()


            return JsonResponse({'status': 'success'}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer
    

class MyTokenRefreshView(APIView):
    permission_classes = (AllowAny,)
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh')
        if refresh_token is None:
            return HttpResponse({"error": "Refresh token is required {refresh_token}"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            refresh = RefreshToken(refresh_token)
            access= refresh.access_token
            user = User.objects.get(id=refresh['user_id'])
            access['nickname'] = user.nickname
            access['profile_image_url'] = user.avatar.url
            response = JsonResponse ({
                "user_id":refresh['user_id'],
                "access":str(access),
                "refresh": str(refresh)
                }, status = 200)
            response.set_cookie('access_token', str(access))
            return response 
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'message': 'Internal server error'}, status=500)

def getUserDetail(request, id):
    user = User.objects.get(id=id)
    user_serializer = UserSerializer(user)
    return JsonResponse(user_serializer.data, safe=False)

@csrf_protect
def checkLogin(request):
    if request.method == 'POST':
        user_authenticated = False
        message = 'Invalid username or password.'
        is_api_user = False
        double_auth = False
        double_auth_key = None
        nickname = None
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(
            login=username,
            password=password
        )
        
        if user is not None and user.is_staff is not True:
            login(request, user)
            payload = {
                "login": username,
                "password": password,
            }
            token_request = requests.post(
                "http://127.0.0.1:8003/api/token/",
                json=payload,
            )
            access_token = token_request.json().get('access')
            refresh_token = token_request.json().get('refresh')
            message = 'Connected'
            user_authenticated = True
            try:
                user_profile = User.objects.get(login=username)
                login(request, user)
                payload = {
                    "login": username,
                    "password": password,
                }                    
                token_request = requests.post(
                    "http://127.0.0.1:8003/api/token/",
                    json=payload,
                )
                access_token = token_request.json().get('access')
                refresh_token = token_request.json().get('refresh')
                message = 'Connected'
                user_authenticated = True
                nickname = user_profile.nickname
                is_api_user = user_profile.is_api_user
                double_auth = user_profile.double_auth_activate
                double_auth_key = user_profile.double_auth_key
                if double_auth is not True :
                    user_profile.status = 'online'
                    user_profile.save()
            except User.DoesNotExist:
                message = 'Invalid username or password.'
        response = JsonResponse({
            'username': username,
            'message': message,
            'nickname': nickname,
            'is_api_user': is_api_user,
            'connectionStatus': user_authenticated,
            'double_auth': double_auth,
            'double_auth_key': double_auth_key
        }, status=200)
        
        if user_authenticated:
            response.set_cookie('access_token', access_token)
            response.set_cookie('refresh_token', refresh_token)
        
        return response
    else:
        return JsonResponse({'message': 'Only POST requests are accepted'}, status=405)
    

# EDIT PROFILE
# EDIT PROFILE
# EDIT PROFILE

@csrf_protect
def editnickname(request, id):
    user = User.objects.get(id=id)
    csrf_token = request.headers.get('X-CSRFToken')
    user_serializer = UserSerializer(user)
    if request.method == 'GET':
        return JsonResponse(user_serializer.data, safe=False)
    elif request.method == 'POST':
        new_nickname = request.POST.get('newNickname')
        if User.objects.filter(nickname=new_nickname).exists():
            message = 'This nickname already exist.'
        elif len(new_nickname) == 0 :
            message = 'This field is required.'
        elif len(new_nickname) >= 10 :
            message = 'your nickname can\'t exceed 10 characters.'
        # elif ne respecte pas les regles de nickname
        else:
            message = 'Nickname changed.'
            user.nickname = new_nickname
            user.save()
            user_serializer = UserSerializer(user)

    response = JsonResponse({
        'message': message,
        'user_serializer' : user_serializer.data,
    })
    response.set_cookie('csrftoken', get_token(request))
    return response

@csrf_protect
def winrate(request):
    users = User.objects.all()
    csrf_token = request.headers.get('X-CSRFToken')
    data = json.loads(request.body)
    if request.method == 'POST':

        winner_id =data.get('winner_id')
        logger.error(winner_id)
        winner = User.objects.get(id=winner_id)
        winner.nombre_victoire += 1
        winner.save()

        loser_id =data.get('loser_id')
        loser = User.objects.get(id=loser_id)
        loser.nombre_defaite += 1
        loser.save()

    response = JsonResponse({})
    response.set_cookie('csrftoken', get_token(request))
    return response

@csrf_protect
def editavatar(request, id):
    user = User.objects.get(id=id)
    csrf_token = request.headers.get('X-CSRFToken')
    user_serializer = UserSerializer(user)
    message = 'avatar changed.'
    if request.method == 'GET':
        return JsonResponse(user_serializer.data, safe=False)
    elif request.method == 'POST':
        new_avatar = request.POST.get('new_avatar')
        user.avatar = new_avatar
        user.save()
        user_serializer = UserSerializer(user)
    response = JsonResponse({
        'message': message,
        'user_serializer' : user_serializer.data,
    })
    response.set_cookie('csrftoken', get_token(request))
    return response

@csrf_protect
def editpassword(request, id):
    user = User.objects.get(id=id)
    csrf_token = request.headers.get('X-CSRFToken')
    user_serializer = UserSerializer(user)
    message = 'aa'
    if request.method == 'GET':
        return JsonResponse(user_serializer.data, safe=False)
    elif request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password1 = request.POST.get('new_password1')
        new_password2 = request.POST.get('new_password2')
        if not user.check_password(old_password):
            message = 'Incorrect password.'
        elif new_password1 != new_password2 :
            message = 'The new password and its confirmation do not match.'
        elif len(new_password1) >= 20 or len(new_password1) <= 8 :
            message = 'The new password is too long or too short.'
        else:
            message = 'Password changed.'
            user.set_password(new_password1)
            user.save()
            user_serializer = UserSerializer(user)

    response = JsonResponse({
        'message': message,
        'user_serializer' : user_serializer.data,
    })
    response.set_cookie('csrftoken', get_token(request))
    return response

# REGISTER
# REGISTER
# REGISTER

    
@csrf_protect
def register_api(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_login = data.get('login')
            password = data.get('password')
            email = data.get('email')
            confirm_password = data.get('confirm_password')

            User = get_user_model()

            # Vérification des champs requis
            if not user_login:
                return JsonResponse({'message': 'Login field is required'}, status=400)
            if not password:
                return JsonResponse({'message': 'Password field is required'}, status=400)
            if not email:
                return JsonResponse({'message': 'Email field is required'}, status=400)
            if not confirm_password:
                return JsonResponse({'message': 'Confirm password field is required'}, status=400)

            # Validation du format de l'email
            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({'message': 'Email must be a valid email address'}, status=400)

            # Vérification de l'existence de l'utilisateur ou de l'email
            if User.objects.filter(login=user_login).exists():
                return JsonResponse({'message': 'User already exists'}, status=400)
            
            if User.objects.filter(email=email).exists():
                return JsonResponse({'message': 'Email already used'}, status=400)

            # Vérification de la longueur du mot de passe
            if len(password) < 8:
                return JsonResponse({'message': 'Password must be at least 8 characters long'}, status=400)

            # Vérification de la correspondance des mots de passe
            if password != confirm_password:
                return JsonResponse({'message': 'Passwords do not match'}, status=400)

            # Création de l'utilisateur
            user = User.objects.create_user(login=user_login, password=password, email=email)
            user.save()
            # Authentifier l'utilisateur
            user_authenticated = authenticate(request, username=user_login, password=password)

            if user_authenticated:
                login(request, user_authenticated)  # Authentification réussie, login l'utilisateur
                payload = {
                    "login": user_login,
                    "password": password,
                }
                token_request = requests.post(
                    "http://127.0.0.1:8003/api/token/",
                    json=payload,
                    verify=False
                )

                if token_request.status_code == 200:
                    token_data = token_request.json()
                    access_token = token_data.get('access')
                    refresh_token = token_data.get('refresh')
                    user.status = 'online'
                    user.save()
                    response_data = {
                        'message': 'User registered successfully',
                        'connectionStatus': True,
                        'access_token': access_token,
                        'refresh_token': refresh_token
                    }
                    response = JsonResponse(response_data, status=200)
                    response.set_cookie('access_token', access_token, httponly=True, samesite='Strict')
                    response.set_cookie('refresh_token', refresh_token, httponly=True, samesite='Strict')
                    return response
                else:
                    return JsonResponse({'message': 'Error generating token'}, status=400)
            else:
                return JsonResponse({'message': 'Authentication failed'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'message': str(e)}, status=500)

    else:
        return JsonResponse({'message': 'Only POST requests are accepted'}, status=405)        

def get_auth_key(request):
    if request.method == 'POST':
        try:
            # Charger les données de la requête
            print("Requeswdst method: POST")
            data = json.loads(request.body)
            print(f"Request data: {data}")

            login = data.get('login')
            print(f"Login: {login}")

            if not login:
                print("Login is missing")
                return JsonResponse({'message': 'Login is required'}, status=400)

            # Rechercher l'utilisateur par son login
            user = User.objects.filter(login=login).first()
            print(f"User found: {user}")

            if not user:
                print("User not found")
                return JsonResponse({'message': 'User not found'}, status=404)

            if not user.double_auth_key:
                print("Double authentication not enabled for this user")
                return JsonResponse({'message': 'Double authentication not enabled for this user'}, status=404)

            # Retourner la clé de double authentification
            print(f"Double auth key: {user.double_auth_key}")
            return JsonResponse({'double_auth_key': user.double_auth_key}, status=200)

        except json.JSONDecodeError:
            print("Invalid JSON")
            return JsonResponse({'message': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'message': 'Internal server error'}, status=500)
    else:
        print("Invalid request method")
        return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_protect
def get_key(request, user_id):
    authorization_header = request.headers.get('Authorization')
    if not authorization_header:    
        return JsonResponse({'message': 'Access token missing1'}, status=401)
    access_token = authorization_header.split(' ')[1] if authorization_header.startswith('Bearer ') else None
    if not access_token:
        return JsonResponse({'message': 'Access token missing'}, status=401)
    try:
        decoded_token = jwt.decode(access_token, os.getenv("DJANGO_SECRET_KEY") , algorithms=['HS256'])
        user_id_from_token = decoded_token['user_id']
        if user_id != user_id_from_token:
            return JsonResponse({'message': 'Unauthorized access'}, status=403)
        user = get_object_or_404(User, pk=user_id)
        if not user.double_auth_key:
            return JsonResponse({'message': 'Double authentication not enabled for this user'}, status=404)
        return JsonResponse({'key': user.double_auth_key})
    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token expired'}, status=401)
    except jwt.InvalidTokenError as e:
        return JsonResponse({'message': 'Invalid token'}, status=401)
    except User.DoesNotExist:
        return JsonResponse({'message': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'message': 'Internal server error'}, status=500)


@csrf_protect
def register_42_api(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_login = data.get('login')
            password = data.get('login')  # Utilisation du login comme mot de passe temporaire
            email = data.get('email')
            if not user_login or not email:
                return JsonResponse({'message': 'Invalid data'}, status=400)


            User = get_user_model()
            try:
                user = User.objects.get(login=user_login)
                if user['is_api_user']:
                    message = 'User already exists'
                else:
                    message = 'User login'
            except User.DoesNotExist:
                # Créer un utilisateur avec le login comme username et mot de passe temporaire
                user = User.objects.create_user(login=user_login, password=password, email=email)
                user.is_api_user = True
                user.save()
                message = 'User created'

            # Authentifier l'utilisateur
            auth_login(request, user)

            # Préparer le payload pour la requête JWT
            payload = {
                "login": user_login,
                "password": password,  # Utilisation du mot de passe temporaire en clair dans le payload
            }

            # Préparer la réponse avec les détails de l'utilisateur
            response = JsonResponse({
                'username': user_login,
                'message': message,
                'connectionStatus': True
            }, status=200)

            # Définir les cookies dans la réponse
            response.set_cookie('csrftoken', get_token(request))

            return response

        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'message': str(e)}, status=500)

    else:
        return JsonResponse({'message': 'Only POST requests are accepted'}, status=405)
    
def set_double_auth(request, user_id):
    if request.method == 'POST':
        try:
        #    data = json.loads(request.body)
       #     user_key = data.get('key')
          #  if not user_key:
             #   return JsonResponse({'message': 'Invalid data: Key is required'}, status=400)
            user = get_object_or_404(User, pk=user_id)
            user.double_auth_activate = True
            user.save()
            return JsonResponse({'message': 'Key double auth set successfully', 'username': user.login}, status=200)
        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON'}, status=400)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)

@csrf_protect
def save_key(request, user_id):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_key = data.get('key')
            if not user_key:
                return JsonResponse({'message': 'Invalid data: Key is required'}, status=400)
            user = get_object_or_404(User, pk=user_id)
            user.double_auth_key = user_key
            user.save()
            return JsonResponse({'message': 'Key saved successfully', 'username': user.login}, status=200)
        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON'}, status=400)
    else:
        return JsonResponse({'message': 'Invalid request method'}, status=405)

# @csrf_exempt
# def logout_view(request):
#     if request.method == 'POST':
#         authorization_header = request.headers.get('Authorization')
#         if not authorization_header or not authorization_header.startswith('Bearer '):
#             return JsonResponse({'message': 'Access token missing or malformed'}, status=401)

#         access_token = authorization_header.split(' ')[1]

#         try:
#             # Décoder le token JWT
#             decoded_token = jwt.decode(access_token, os.getenv('DJANGO_SECRET_KEY'), algorithms=['HS256'])
#             user_id = decoded_token.get('user_id')

#             if not user_id:
#                 return JsonResponse({'message': 'Invalid token'}, status=401)

#             # Récupérer l'utilisateur et mettre à jour son statut
#             user = User.objects.get(pk=user_id)
#             user.status = 'offline'
#             user.save()

#             # Effacer la session Django
#             django_logout(request)

#             return JsonResponse({'message': 'User status updated to offline'}, status=200)
#         except jwt.ExpiredSignatureError:
#             return JsonResponse({'message': 'Token has expired'}, status=401)
#         except jwt.InvalidTokenError:
#             return JsonResponse({'message': 'Invalid token'}, status=401)
#         except User.DoesNotExist:
#             return JsonResponse({'message': 'User not found'}, status=404)
#         except Exception as e:
#             return JsonResponse({'message': str(e)}, status=500)
#     else:
#         return JsonResponse({'message': 'Only POST requests are accepted'}, status=405)