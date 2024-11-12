from django import forms
from django.views.generic import View
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from . import forms
import requests
import bleach
from django.contrib.auth import logout as django_logout
from .forms import LoginForm, UpdateNicknameForm, AvatarForm
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.http import JsonResponse, HttpResponse, HttpResponseServerError, request
from django.contrib.auth import login, authenticate # import des fonctions login et authenticate
from django.contrib.auth import login as auth_login
from . import forms
from .forms import LoginForm, UpdateNicknameForm, RegisterForm, UpdatePasswordForm
from django.http import HttpResponse
from django.conf import settings as settings_py
from django.contrib.auth.decorators import login_required
import requests
import logging
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt, csrf_protect
import qrcode, os
from io import BytesIO
import pyotp
from .decorators import login_is_required
import jwt
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
import json
#*******************
from django import forms
from django.views.generic import View
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.http import JsonResponse
from django.shortcuts import render
import requests
#from user_management.models import User, Game
from django.contrib.auth import login, authenticate # import des fonctions login et authenticate
from django.contrib.auth import login as auth_login
from . import forms
from .forms import LoginForm, RegisterForm
from django.http import HttpResponse
from django.conf import settings as settings_py
from django.contrib.auth.decorators import login_required
from django.http import request
import requests
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt, csrf_protect
import qrcode
from io import BytesIO
import pyotp
import json
import jwt
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.shortcuts import render
import requests
from urllib.parse import urlencode
from django.contrib import messages
from jose import jwt, JWTError
from django.contrib.auth import logout
from django.http import JsonResponse, HttpResponseRedirect
#****
from django.db import models  # Importez models de Django
import logging
logger = logging.getLogger(__name__)

# PROFIL ET MODIF DU PROFIL

@login_is_required
def historic(request):
    content_template = 'main/historic.html'
    try:
        response = requests.get('http://game:8002/historic/')
        response.raise_for_status()  # Lève une exception pour les codes d'erreur HTTP
        historic_data = response.json()

		# Vérifie si la liste des utilisateurs est vide
        if not historic_data:
            message = "Aucun utilisateur trouvé."
            historic = []
        else:
            historic = historic_data  # Utilise directement les données JSON comme liste d'utilisateurs
            message = f"{len(historic)} utilisateurs trouvés."

    except requests.RequestException as e:
        historic = []  # Assurez-vous que 'users' est une liste vide en cas d'erreur
        message = f"Erreur lors de la récupération des utilisateurs: {e}"

    context = {
		'content_template': content_template,
		'historic': historic,
	}
    return render(request, 'main/base.html', context)



def change_nickname(request):
    content_template = 'main/profile.html'
    user = 1
    change = 'change_nickname'
    form = UpdateNicknameForm()
    message = ''

    access_token = request.COOKIES.get('access_token')
    send_secret_key = os.getenv("DJANGO_SECRET_KEY")
    decoded_token = jwt.decode(access_token, send_secret_key, algorithms=['HS256'])
    id = decoded_token['user_id']

    url = 'http://usermanagement:8003/editnickname/' + str(id) + '/'

    if request.method == 'GET':
        try:
            response = requests.get(url)
            response.raise_for_status()
            user_data = response.json()
            if not user_data:
                user = []
            else:
                user = user_data
        except requests.RequestException as e:
            user = []

    elif request.method == 'POST':
            try:
                form = UpdateNicknameForm(request.POST)
                if form.is_valid():
                    newnickname1=form.cleaned_data['newnickname']
                    newnickname=bleach.clean(newnickname1)
                    headers = {'X-CSRFToken': request.headers.get('X-CSRFToken'),}
                    cookies = {'csrftoken': request.COOKIES.get('csrftoken')}
                    response = requests.post(
                        url,
                        data={'newNickname': newnickname},
                        headers=headers,
                        cookies=cookies
                    )
                    response.raise_for_status()  # Lève une exception pour les codes d'erreur HTTP
                    data = response.json()
                    user = data.get('user_serializer')
                    message = data.get('message')
                    if message == 'Nickname changed.':
                        change = 'nickname changed'
            except requests.RequestException as e:
                message = "Erreur lors de la récupération des utilisateurs"

    total_games = user['nombre_victoire'] + user['nombre_defaite']
    if total_games > 0:
        winrate = int((user['nombre_victoire'] / total_games) * 100)
    else:
        winrate = 0
    a2f = user['double_auth_activate']
    context = {
        'content_template': content_template,
        'user' : user,
        'change' : change,
        'a2f' : a2f,
        'form' : form,
        'message' : message,
        'winrate' : winrate
    }
    return render(request, 'main/base.html', context)

def change_avatar(request):
    content_template = 'main/profile.html'
    user = 1
    change = 'change_avatar'
    form = AvatarForm()
    message = ''

    access_token = request.COOKIES.get('access_token')
    send_secret_key = os.getenv("DJANGO_SECRET_KEY")
    decoded_token = jwt.decode(access_token, send_secret_key, algorithms=['HS256'])
    id = decoded_token['user_id']

    url = 'http://usermanagement:8003/editavatar/' + str(id) + '/'

    if request.method == 'GET':
        try:
            response = requests.get(url)
            response.raise_for_status()
            user_data = response.json()
            if not user_data:
                user = []
            else:
                user = user_data
        except requests.RequestException as e:
            user = []

    elif request.method == 'POST':
            try:
                form = AvatarForm(request.POST, request.FILES)
                if form.is_valid():
                    new_avatar = form.save(commit=False)
                    new_avatar.save()
                    headers = {'X-CSRFToken': request.headers.get('X-CSRFToken'),}
                    cookies = {'csrftoken': request.COOKIES.get('csrftoken')}
                    response = requests.post(
                        url,
                        data={'new_avatar': new_avatar.url},
                        headers=headers,
                        cookies=cookies
                    )
                    response.raise_for_status()  # Lève une exception pour les codes d'erreur HTTP
                    data = response.json()
                    user = data.get('user_serializer')
                    message = data.get('message')
                    if message == 'avatar changed.':
                        change = 'avatar changed'
            except requests.RequestException as e:
                message = "Erreur lors de la récupération des utilisateurs"
    total_games = user['nombre_victoire'] + user['nombre_defaite']
    if total_games > 0:
        winrate = int((user['nombre_victoire'] / total_games) * 100)
    else:
        winrate = 0
    a2f = user['double_auth_activate']
    context = {
        'content_template': content_template,
        'user' : user,
        'change' : change,
        'a2f' : a2f,
        'form' : form,
        'message_avatar' : message,
        'winrate' : winrate
    }
    return render(request, 'main/base.html', context)

def change_password(request):
    content_template = 'main/edit_password.html'
    user = 1
    change = 'change_password'
    form = UpdatePasswordForm()
    message = ''

    access_token = request.COOKIES.get('access_token')
    send_secret_key = os.getenv("DJANGO_SECRET_KEY")
    decoded_token = jwt.decode(access_token, send_secret_key, algorithms=['HS256'])
    id = decoded_token['user_id']

    url = 'http://usermanagement:8003/editpassword/' + str(id) + '/'

    if request.method == 'GET':
        try:
            response = requests.get(url)
            response.raise_for_status()
            user_data = response.json()
            if not user_data:
                user = []
            else:
                user = user_data
        except requests.RequestException as e:
            user = []

    elif request.method == 'POST':
            try:
                form = UpdatePasswordForm(request.POST)
                if form.is_valid():
                    old_passwordd=form.cleaned_data['old_password']
                    new_password11=form.cleaned_data['new_password1']
                    new_password22=form.cleaned_data['new_password2']
                    old_password=bleach.clean(old_passwordd)
                    new_password1=bleach.clean(new_password11)
                    new_password2=bleach.clean(new_password22)
                    headers = {'X-CSRFToken': request.headers.get('X-CSRFToken'),}
                    cookies = {'csrftoken': request.COOKIES.get('csrftoken')}
                    response = requests.post(
                        url,
                        data={'old_password': old_password,
                              'new_password1' : new_password1,
                              'new_password2' : new_password2},
                        headers=headers,
                        cookies=cookies
                    )
                    response.raise_for_status()  # Lève une exception pour les codes d'erreur HTTP
                    data = response.json()
                    user = data.get('user_serializer')
                    message = data.get('message')
                    if message == 'Password changed.':
                        change = 'password changed'
                        content_template = 'main/profile.html'
            except requests.RequestException as e:
                message = "Erreur lors de la récupération des utilisateurs"

    total_games = user['nombre_victoire'] + user['nombre_defaite']
    if total_games > 0:
        winrate = int((user['nombre_victoire'] / total_games) * 100)
    else:
        winrate = 0
    a2f = user['double_auth_activate']
    context = {
        'content_template': content_template,
        'user' : user,
        'change' : change,
        'a2f' : a2f,
        'form' : form,
        'message_password' : message,
        'winrate' : winrate
    }
    return render(request, 'main/base.html', context)

@login_is_required
def profile(request):
    content_template = 'main/profile.html'
    change = 'no_change'

    access_token = request.COOKIES.get('access_token')
    send_secret_key = os.getenv("DJANGO_SECRET_KEY")
    decoded_token = jwt.decode(access_token, send_secret_key, algorithms=['HS256'])
    id = decoded_token['user_id']
    historic = ''
    
    try:
        url = 'http://usermanagement:8003/getUserDetail/' + str(id) + '/'
        response = requests.get(url)
        response.raise_for_status()  # Lève une exception pour les codes d'erreur HTTP
        user_data = response.json()
        if not user_data:
            message = "Aucun utilisateur trouvé."
            user = []
        else:
            user = user_data  # Utilise directement les données JSON comme liste d'utilisateurs
            message = f"{len(user)} utilisateurs trouvés."

    except requests.RequestException as e:
        user = []  # Assurez-vous que 'users' est une liste vide en cas d'erreur
        message = f"Erreur lors de la récupération des utilisateurs: {e}"
    
    try:
        url = 'http://game:8002/historic_profile/' + str(id) + '/'
        response = requests.get(url)
        response.raise_for_status()  # Lève une exception pour les codes d'erreur HTTP
        historic = response.json()
    except requests.RequestException as e:
        message = "Erreur lors de la récupération des utilisateurs"

    if user :
        total_games = user['nombre_victoire'] + user['nombre_defaite']
    else :
        total_games = 0
    if total_games > 0:
        winrate = int((user['nombre_victoire'] / total_games) * 100)
    else:
        winrate = 0
    a2f = user['double_auth_activate']
    context = {
        'content_template': content_template,
        'user' : user,
        'change' : change,
        'a2f' : a2f,
        'winrate' : winrate,
        'historic' : historic,
    }
    return render(request, 'main/base.html', context)

def user_detail(request, id):
    content_template = 'main/profile.html'
    change = 'no_change'
    try:
        url = 'http://usermanagement:8003/getUserDetail/' + str(id) + '/'
        response = requests.get(url)
        response.raise_for_status()  # Lève une exception pour les codes d'erreur HTTP
        user_data = response.json()
        if not user_data:
            message = "Aucun utilisateur trouvé."
            user = []
        else:
            user = user_data  # Utilise directement les données JSON comme liste d'utilisateurs
            message = f"{len(user)} utilisateurs trouvés."

    except requests.RequestException as e:
        user = []  # Assurez-vous que 'users' est une liste vide en cas d'erreur
        message = f"Erreur lowrs de la récupération des utilisateurs: {e}"
    a2f = user['double_auth_activate']

    context = {
        'content_template': content_template,
        'user' : user,
        'change' : change,
        'a2f' : a2f,
    }
    return render(request, 'main/base.html', context)

@login_is_required
def userList(request, id=None):
    content_template = 'main/user_list.html'
    try:
        # Utilisation de l'API modifiée pour récupérer les utilisateurs
        response = requests.get('http://usermanagement:8003/getUserList/')
        response.raise_for_status()  # Lève une exception pour les codes d'erreur HTTP

		# La réponse de l'API est directement utilisable, pas besoin de chercher une clé spécifique
        users_data = response.json()

		# Vérifie si la liste des utilisateurs est vide
        if not users_data:
            message = "Aucun utilisateur trouvé."
            users = []
        else:
            users = users_data  # Utilise directement les données JSON comme liste d'utilisateurs
            message = f"{len(users)} utilisateurs trouvés."

    except requests.RequestException as e:
        users = []  # Assurez-vous que 'users' est une liste vide en cas d'erreur
        message = f"Erreur lors de la récupération des utilisateurs: {e}"

    context = {
		'content_template': 'main/user_list.html',
		'users': users,  # Ajoutez les ut        response.set_cookie('csrftoken', get_token(request))ilisateurs au contexte pour les rendre accessibles dans le template
		'message': message,  # Vous pouvez également passer le message au template si vous souhaitez l'afficher
	}
    return render(request, 'main/base.html', context)


# LOGIN ET LOGOUT
# LOGIN ET LOGOUT
# LOGIN ET LOGOUT


def logout_view(request):
    # Vérifier que la méthode de la requête est POST
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    # Récupérer le token d'accès depuis les cookies
    access_token = request.COOKIES.get('access_token')
    
    if not access_token:
        return JsonResponse({'error': 'Access token missing'}, status=401)
    
    try:
        # Décoder le token JWT
        payload = jwt.decode(access_token, os.getenv("DJANGO_SECRET_KEY"), algorithms=['HS256'])
        user_id = payload.get('user_id')
        
        if not user_id:
            return JsonResponse({'error': 'Invalid token'}, status=401)
    except ExpiredSignatureError:
        return JsonResponse({'error': 'Token has expired'}, status=401)
    except InvalidTokenError:
        return JsonResponse({'error': 'Invalid token'}, status=401)
    except Exception as e:
        return JsonResponse({'error': 'Token decoding failed'}, status=401)
    
    csrf_token = get_token(request)
    # Envoyer une requête au service utilisateur pour mettre le statut à offline
    headers = {
        'X-CSRFToken': csrf_token,
    }
    cookies = {'csrftoken': get_token(request)}
    usermanagement_url = 'http://usermanagement:8003/set_offline/'

    usermanagement_response = requests.post(usermanagement_url, json={'user_id': user_id, 'status': 'offline'}, headers=headers, cookies=cookies)

    
    if usermanagement_response.status_code != 200:
        return JsonResponse({'error': 'Failed to update user status'}, status=500)
    
    # Déconnecter l'utilisateur
    logout(request)
    
    # Supprimer les cookies d'accès et de rafraîchissement
    response = HttpResponseRedirect('/login/')
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
        
    return response

def generate_qr_code(request):
    access_token = request.COOKIES.get('access_token')
    if not access_token:
        return JsonResponse({'message': 'Access token missing'}, status=401)
    secret_key = os.getenv("DJANGO_SECRET_KEY")
    try:
        decoded_token = jwt.decode(access_token, secret_key, algorithms=['HS256'])
        user_id = decoded_token['user_id']
    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token expired'}, status=401)
    except jwt.InvalidTokenError as e:
        return JsonResponse({'message': 'Invalid token'}, status=401)
    response = requests.get(
        f'http://usermanagement:8003/get_user/{user_id}/',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    if response.status_code != 200:
        return JsonResponse({'message': 'Failed to retrieve user data'}, status=response.status_code)
    user_data = response.json()
    username = user_data.get('username')
    secret_key = pyotp.random_base32()
    cookies = {'csrftoken': get_token(request)}
    # Envoyer une requête au service utilisateur pour mettre le statut à offline
    payload = {'key': secret_key, 'user_id': user_id}
    save_key_response = requests.post(
        f'http://usermanagement:8003/save_key/{user_id}/',
        json=payload,
        headers={'Authorization': f'Bearer {access_token}', 'X-CSRFToken': get_token(request)},
        cookies=cookies
    )
    if save_key_response.status_code != 200:
        return JsonResponse({'message': 'Failed to save key'}, status=save_key_response.status_code)
    google_auth_url = f"otpauth://totp/{username}?secret={secret_key}&issuer=Transcendence"
    qr = qrcode.make(google_auth_url)
    buffer = BytesIO()
    qr.save(buffer, format='PNG')
    qr_bytes = buffer.getvalue()
    return HttpResponse(qr_bytes, content_type="image/png")

def photo(request):
    form = forms.PhotoForm()
    if request.method == 'POST':
        form = forms.PhotoForm(request.POST, request.FILES)
        if form.is_valid():
            Photo = form.save(commit=False)
            Photo.save()
            return redirect('home')
    return render(request, 'main/photo_upload.html', context={'form': form})

def login_code(request):
    form = LoginForm()
    if (request.COOKIES.get('access_token')):
        context = {
        'content_template': 'main/settings.html'
    }
    else:
        context = {
        'form': form,
		'content_template': 'main/home.html',
		'url': 'home'
	}
    return render(request, 'main/base.html', context)

def verify_login_code(request):
    if request.method == 'POST':        
        try:
            data = json.loads(request.body)            
            submitted_code = data.get('code')
            accessToken = data.get('accessToken')
            secret_key = data.get('secret_key')
            if not submitted_code or not accessToken or not secret_key:
                return JsonResponse({'message': 'Code and login are required'}, status=400)
            # Vérifier le code de double authentification
            totp = pyotp.TOTP(secret_key)

            if totp.verify(submitted_code):
                send_secret_key = os.getenv("DJANGO_SECRET_KEY")
                decoded_token = jwt.decode(accessToken, send_secret_key, algorithms=['HS256'])
                user_id = decoded_token['user_id']
                usermanagement_url = 'http://usermanagement:8003/set_offline/'
                csrf_token = get_token(request)
                headers = {
                    'X-CSRFToken': csrf_token,
                }
                usermanagement_response = requests.post(usermanagement_url, json={'user_id': user_id, 'status': 'online'}, headers=headers, cookies = {'csrftoken': get_token(request)})
                if usermanagement_response.status_code != 200:
                    return JsonResponse({'success': False,'message': 'Failed to update user status'}, status=500)
                return JsonResponse({'success': True, 'message': 'Code verified successfully'}, status=200)
            else:
                return JsonResponse({'success': False, 'message': 'Invalid code'}, status=400)
        
        except requests.exceptions.RequestException as e:
            return JsonResponse({'message': f'Error: {str(e)}'}, status=500)
        except Exception as e:
            return JsonResponse({'message': 'Internal server error'}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
def verify_code(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        submitted_code = data.get('code')
        access_token = request.COOKIES.get('access_token')
        if not access_token:
            return JsonResponse({'message': 'Access token missing'}, status=401)
        try:
            key_response = requests.get('http://usermanagement:8003/send_key/',
                                        headers={'Authorization': f'Bearer {access_token}'})
            if key_response.status_code != 200:
                return JsonResponse({'message': 'Failed to retrieve secret key'}, status=key_response.status_code)
            send_secret_key = os.getenv("DJANGO_SECRET_KEY")
            decoded_token = jwt.decode(access_token, send_secret_key, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            key_response = requests.post(f'http://usermanagement:8003/get_key/{user_id}/',
                                        headers={'Authorization': f'Bearer {access_token}', 'X-CSRFToken': get_token(request)}, cookies = {'csrftoken': get_token(request)})
            if key_response.status_code != 200:
                return JsonResponse({'message': 'Failed to retrieve secret key'}, status=key_response.status_code)
            secret_key = key_response.json().get('key')
            totp = pyotp.TOTP(secret_key)
            if totp.verify(submitted_code):
                key_response = requests.post(f'http://usermanagement:8003/set_double_auth/{user_id}/',
                                        headers={'Authorization': f'Bearer {access_token}', 'X-CSRFToken': get_token(request)}, cookies = {'csrftoken': get_token(request)})
                return JsonResponse({'success': True, 'message': 'Code verified successfully'})
            else:
                return JsonResponse({'success': False, 'message': 'Invalid code'}, status=400)
        except jwt.ExpiredSignatureError as e:
            return JsonResponse({'message': 'Token expired'}, status=401)
        except jwt.InvalidTokenError as e:
            return JsonResponse({'message': 'Invalid token'}, status=401)
        except requests.exceptions.RequestException as e:
            return JsonResponse({'message': f'Error: {str(e)}'}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_protect
def refreshToken(request):
    backend_url = f'http://usermanagement:8003/refresh/token/'
    headers={'Content-Type': 'application/json', 'X-CSRFToken': request.COOKIES.get('csrftoken')}
    data = json.loads(request.body)
    refresh_token=data.get('refresh_token')
    cookies =  {
				"refresh": refresh_token,
			}
    try:
        response = requests.post(backend_url, headers=headers, cookies=cookies)
        return HttpResponse(content=response, status=200)
    except requests.HTTPError as e:
        return HttpResponseServerError(f"Erreur lors de la requête vers le back-end : {str(e)}")
    except requests.RequestException as e:
        return HttpResponseServerError(f"Erreur lors de la requête vers le back-end : {str(e)}")

@csrf_protect
def login_view(request):
    form = LoginForm()
    content_template = 'main/login.html'
    connectionStatus = False
    login_data = None
    message = None
    double_auth = None
    double_auth_key = None
    response = None
    double_auth_log = None
    if request.method == 'GET':
        context = {
            'form': form,
            'content_template': content_template,
        }
        return render(request, 'main/base.html', context)

    elif request.method == 'POST':
        try:
            form = LoginForm(request.POST)
            if form.is_valid():
                username1 = form.cleaned_data['username']
                password2 = form.cleaned_data['password']
                username = bleach.clean(username1)
                password = bleach.clean(password2)
                cleaned_username = username
                print("cleaned_username", username)
                double_auth_log = username
                cleaned_password = password
                headers = {'X-CSRFToken': get_token(request)}
                cookies = {'csrftoken': get_token(request)}
                response = requests.post(
                    'http://usermanagement:8003/checkLogin/',
                    data={'username': cleaned_username, 'password': cleaned_password},
                    headers=headers,
                    cookies=cookies
                )
                response.raise_for_status()
                login_data = response.json()
                connectionStatus = login_data.get('connectionStatus')
                message = login_data.get('message')
                if message == 'Connected':
                    double_auth = login_data.get('double_auth')
                    double_auth_key = login_data.get('double_auth_key')
                    request.session['username'] = cleaned_username
                    request.session.save()

                    if double_auth:
                        content_template = 'main/login_code.html'
                    else:
                        content_template = 'main/home.html'
                else:
                    content_template = 'main/login.html'

            else:
                message = 'Form is not valid.'
                content_template = 'main/login.html'

        except requests.RequestException as e:
            message = "Please connect with 42 API"
        #logger du nickname :
        nick = login_data.get('nickname')
        context = {
            'double_auth_active': double_auth,
            'double_auth_key': double_auth_key,
            'double_auth_log': double_auth_log,
            'nickname': nick,
            'username': cleaned_username,
            'login': cleaned_username,
            'access_token': response.cookies.get('access_token') if response else None,
            'refresh_token': response.cookies.get('refresh_token') if response else None,
            'form': form,
            'registerStatus': connectionStatus,
            'content_template': content_template,
            'is_api_user': request.POST.get('is_api_user'),
            'message': message
        }
        return render(request, 'main/base.html', context) 
			
@csrf_protect
def register_view(request):
    # Initialisation des variables
    form = RegisterForm()
    connectionStatus = False
    content_template = 'main/register.html'
    error_message = None
    user_login = None
    access_token = None
    refresh_token = None
    message = None
    cleaned_username = None
    
    print("Starsting register_view function.")
    
    if request.method == 'POST':
        print("POST redquest received.")
        form = RegisterForm(request.POST)
        
        if form.is_valid():
            user_login = form.cleaned_data['login']
            password = form.cleaned_data['password1']
            confirm_password = form.cleaned_data['password2']
            email = form.cleaned_data['email']
            
            print("Raw form data:")
            print("user_login = ", user_login)
            print("password = ", password)
            print("confirm_password = ", confirm_password)
            print("email = ", email)
            
            # Nettoyage des données
            cleaned_username = bleach.clean(user_login)
            cleaned_password = bleach.clean(password)
            cleaned_confirm_password = bleach.clean(confirm_password)
            cleaned_email = bleach.clean(email)
            payload = {
                'login': cleaned_username,
                'password': cleaned_password,
                'confirm_password': cleaned_confirm_password,
                'email': cleaned_email
            }
            
            headers = {'X-CSRFToken': request.headers.get('X-CSRFToken')}
            cookies = {'csrftoken': request.COOKIES.get('csrftoken')}
            
            print("Sending request to usermanagement service.")
            response = requests.post(
                'http://usermanagement:8003/register_api/',
                json=payload,
                headers=headers,
                cookies=cookies
            )
            register_data = response.json()
            message = register_data.get('message')
            access_token = register_data.get('access_token')
            refresh_token = register_data.get('refresh_token')
            if response.status_code == 200:
                connectionStatus = register_data.get('connectionStatus')
                print("Connection status: ", connectionStatus)
                
                #if message == 'userok':
                print("isci")
                content_template = 'main/home.html'
            else:
                message = register_data.get('message', 'An error occurred')
                error_message = message
                print("Error message: ", error_message)
        else:
            message = "Please fill in all the fields"
    context = {
        'form': form,
        'nickname': cleaned_username,
        'username': cleaned_username,
        'content_template': content_template,
        'registerStatus': connectionStatus,
        'access_token': access_token,
        'message': message,
        'refresh_token': refresh_token,
        'error_message': error_message
    }
    return render(request, 'main/base.html', context)
	
# regiser with api

@csrf_protect
def login_with_42(request):
	authorize_url = 'https://api.intra.42.fr/oauth/authorize'
	params = {
		'client_id': settings_py.CLIENT_ID,
		'redirect_uri': "http://127.0.0.1:8001/callback-42/",
		'response_type': 'code',
		'scope': 'public',
	}
	auth_url = f"{authorize_url}?client_id={params['client_id']}&redirect_uri={params['redirect_uri']}&response_type={params['response_type']}&scope={params['scope']}"
	return redirect(auth_url)

@csrf_protect
def callback_42(request):
    token_url = 'https://api.intra.42.fr/oauth/token'
    data = {
        'grant_type': 'authorization_code',
        'client_id': settings_py.CLIENT_ID,
        'client_secret': settings_py.CLIENT_SECRET,
        'code': request.GET.get('code'),
        'redirect_uri': "http://127.0.0.1:8001/callback-42/",
    }
    cookies = {
        'csrftoken': request.COOKIES.get('csrftoken')
    }

    try:
        response = requests.post(token_url, json=data)
        response.raise_for_status()
        response_data = response.json()
        access_token = response_data.get('access_token')

        if not access_token:
            return redirect('/register/?error=Access token not found')

        user_info_url = 'https://api.intra.42.fr/v2/me'
        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        user_response = requests.get(user_info_url, headers=headers)
        user_response.raise_for_status()
        user_data = user_response.json()

        payload = {
            'login': user_data['login'],
            'email': user_data['email'],
            'access_token': access_token
        }
        csrf_token = request.COOKIES.get('csrftoken')
        headers = {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrf_token
        }

        register_response = requests.post(
            'http://usermanagement:8003/register_42_api/',
            json=payload,
            headers=headers,
            cookies=cookies
        )

        response_json = register_response.json()
        response_message = response_json.get('message')

        if register_response.status_code == 200:
            if response_message != "User already exists":
                return redirect('/home/')
            else:
                return redirect('/register/')
        else:
            return redirect('/home/')
    except requests.exceptions.RequestException as e:
        return redirect('/register/?error=Error with 42 API')
        
@login_is_required
def activate_2fa(request):
	if not request.user.is_authenticated:
		return JsonResponse({'message': 'User not authenticated'}, status=401)
	# Générer une clé secrète unique pour l'utilisateur
	
	secret_key = pyotp.random_base32()
	
	# Stocker la clé secrète dans la base de données de l'utilisateur
	payload = {'key': secret_key}
	headers = {'X-CSRFToken': request.headers.get('X-CSRFToken')}
	cookies = {'csrftoken': request.COOKIES.get('csrftoken')}
	response = requests.post(
		'http://usermanagement:8003/save_key/',
		json=payload,
		headers=headers,
		cookies=cookies
	)
	
	if response.status_code != 200:
		return JsonResponse({'message': 'Failed to save key'}, status=response.status_code)
	
	# Extraire le nom d'utilisateur de la réponse
	
	response_data = response.json()
	username = response_data.get('username')
	
	# Créer l'URL pour Google Authenticator
	google_auth_url = f"otpauth://totp/{username}?secret={secret_key}&issuer=Transcendence"
	
	# Créer le QR code
	qr = qrcode.make(google_auth_url)
	
	# Convertir l'image en bytes pour l'afficher dans la réponse
	buffer = BytesIO()
	qr.save(buffer, format='PNG')
	qr_bytes = buffer.getvalue()
	
	# Retourner le QR code sous forme de réponse HTTP
	return HttpResponse(qr_bytes, content_type="image/png")

@login_is_required
def base(request):
	context = {
		'content_template': 'main/home.html'
	}
	return render(request, 'main/base.html', context)

@login_is_required
def activea2f(request):
    form = LoginForm()
    if (request.COOKIES.get('access_token')):
        context = {
        'content_template': 'main/activea2f.html'
    }
    else:
        context = {
        'form': form,
		'content_template': 'main/login.html',
		'url': 'login'
	}
    return render(request, 'main/base.html', context)
        

@login_is_required
def about(request):
	
	context = {
		'content_template': 'main/about.html'
	}
	return render(request, 'main/base.html', context)

def handleRequest(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            # Relancer une requête vers le backend avec les données reçues et les headers
            response = requests.post('http://usermanagement:8003/handleRequest/',
                json=data,
                headers=request.headers
            )

            # Vérifiez la réponse du backend
            if response.status_code == 200:
                return JsonResponse({'status': 'success', 'data': response.json()}, status=200)
            else:
                return JsonResponse({'status': 'error', 'message': 'Backend request failed'}, status=500)

        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)


def addFriend(request):
    data = json.loads(request.body)
    nickname_to_find = data.get('name')
    response = requests.get('http://usermanagement:8003/getUserList/', headers=request.headers)
    response.raise_for_status()
    users = response.json()
    user = next((user for user in users if user['nickname'] == nickname_to_find), None)
    if not (user):
          return JsonResponse({'result': 'false'})
    myId = jwt.decode(request.COOKIES.get('access_token'), os.getenv('DJANGO_SECRET_KEY'), algorithms=['HS256'])['user_id']
    jsons= {'to_user_id' : user.get('id'), 'from_user_id' : myId}
    response = requests.post('http://usermanagement:8003/addFriend/', headers=request.headers, json = jsons)
    return JsonResponse({'data':response.json()})

def friendlist(request):
    try:
        response = requests.get('http://usermanagement:8003/getFriendsUserList/', cookies={'access_token':request.COOKIES.get('access_token')})
        response.raise_for_status()
        data= response.json()
    except requests.RequestException as e:
        return JsonResponse({'error': 'Error fetching user list'}, status=500)

    context = {
        'myId': data['myId'],
		'friends': data['friends'],
        'users': data['users'],
        'friends_requests_sends': data['requests_sent'],
        'friends_requests_receiveds': data['requests_received'],
        'content_template': 'main/friendlist.html'
    }
    return render(request, 'main/base.html', context)

@login_is_required
def online_room(request):
	context = {
		'content_template': 'main/game_online_room.html'
	}
	return render(request, 'main/base.html', context)

@login_is_required
def online_game(request, roomName):
	context = {
		'content_template': 'main/game_online_game.html',
		'roomName': roomName
	}
	return render(request, 'main/base.html', context)

@login_is_required
def tournament_room(request):
	context = {
		'content_template': 'main/game_tournament_room.html'
	}
	return render(request, 'main/base.html', context)

@login_is_required
def tournament_display(request, roomTournamentName):
    data = json.loads(request.body)
    context = {
		'content_template': 'main/game_tournament_display.html',
		'roomTournamentName': roomTournamentName,
        'Players':data.get('Players'),
        'Round2Players':data.get('Round2Players'),
        'Round3Players':data.get('Round3Players'),
        'Winner':data.get('Winner'),
        'Scores':data.get('Scores')

	}
    return render(request, 'main/base.html', context)

@login_is_required
def local(request):
	context = {
		'content_template': 'main/game_local.html'
	}
	return render(request, 'main/base.html', context)

@login_is_required
def local_tournament(request):
	context = {
		'content_template': 'main/game_tournament_game.html'
	}
	return render(request, 'main/base.html', context)



# @csrf_protect
# def get_rooms(request):
# 	if request.method == 'GET':
# 			headers = {'X-CSRFToken': request.headers.get('X-CSRFToken')}
# 			cookies = {'csrftoken': request.COOKIES.get('csrftoken')}
# 			response = requests.get(
# 				'http://game:8002/get_rooms/',
# 				headers=headers,
# 				cookies=cookies,
# 				json = {'room_exists': True}
# 			)
# 			response_data = response.json()
# 			room_exists = response_data.get('room_exists')
# 	return JsonResponse({'room_exists': room_exists})