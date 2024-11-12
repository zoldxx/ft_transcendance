from django.contrib.auth import REDIRECT_FIELD_NAME
from django.shortcuts import redirect, resolve_url
from main_files import settings
from functools import wraps
from urllib.parse import urlencode
import jwt, logging, requests

logger = logging.getLogger(__name__)

def login_is_required(
    function=None, login_url=None, redirect_field_name='next'
):
    def decorator(view_func):
        @wraps(view_func)
        def wrap(request, *args, **kwargs):
            access_token = request.COOKIES.get('access_token')
            refresh_token = request.COOKIES.get('refresh_token')
            if not access_token:
                return redirect_to_login(request, login_url, redirect_field_name)
            decoded_token=""
            try:
                decoded_token = jwt.decode(access_token, settings.SECRET_KEY, algorithms=['HS256'])
                return view_func(request, *args, **kwargs)
            except jwt.ExpiredSignatureError:
                new_access_token = refresh_access_token(refresh_token)
                if new_access_token:
                    response = view_func(request, *args, **kwargs)
                    response.set_cookie('access_token', new_access_token)
                    return response
                else:
                    return redirect_to_login(request, login_url, redirect_field_name)
            except jwt.InvalidTokenError as e:
                return redirect_to_login(request, login_url, redirect_field_name)
        
        def redirect_to_login(request, login_url, redirect_field_name):
            path = request.build_absolute_uri()
            resolved_login_url = resolve_url(login_url or settings.LOGIN_URL)
            if request.method == 'GET':
                redirect_url = resolved_login_url + '?' + urlencode({redirect_field_name: path})
            elif request.method == 'POST':
                redirect_url = resolved_login_url + '?' + urlencode({redirect_field_name: path}) + '&' + request.POST.urlencode()
            return redirect(redirect_url)

        def refresh_access_token(refresh_token):
            if not refresh_token:
                return None
            try:
                backend_url = f'http://usermanagement:8003/refresh/token/'
                headers={'Content-Type': 'application/json'}
                cookies =  {
                    "refresh": refresh_token,
                }
                response = requests.post(backend_url, headers=headers, cookies=cookies)
                response_data = response.json()
                response_data.access['user_id']=response_data.user_id
                response_data.access['username']=response_data.username
                response_data.access['email']=response_data.email
                response_data.access['profile_image_url']=response_data.profile_image_url
                return response_data.get('access')
            except Exception as e:
                return None
             
        wrap.__doc__ = function.__doc__
        wrap.__name__ = function.__name__
        return wrap

    if function is None:
        return decorator
    else:
        return decorator(function)