# authentication/forms.py
from django import forms
from django.views.generic import View
from django.shortcuts import render, redirect
from django.http import JsonResponse
from user_management_files.models import User
from django.contrib.auth import login, authenticate # import des fonctions login et authenticate
from django.contrib.auth.forms import UserCreationForm, UserChangeForm


  
class LoginForm(forms.Form):
	username = forms.CharField(
		max_length=100, 
		widget=forms.TextInput(attrs={'class': 'custom-input', 'placeholder': 'Username'})
	)
	password = forms.CharField(
		widget=forms.PasswordInput(attrs={'class': 'custom-input', 'placeholder': 'Password'})
	)

class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('login', 'email')
    def __init__(self, *args, **kwargs):
        super(CustomUserCreationForm, self).__init__(*args, **kwargs)
        for field_name in self.fields:
            self.fields[field_name].widget.attrs.update({'class': 'custom-input'})



class CustomUserChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = User
        fields = ('login', 'email', 'nickname', 'avatar', 'nombre_victoire', 'nombre_defaite', 'is_active', 'is_staff')
    def __init__(self, *args, **kwargs):
        super(CustomUserChangeForm, self).__init__(*args, **kwargs)
        for field_name in self.fields:
            self.fields[field_name].widget.attrs.update({'class': 'custom-input'})
       

