# authentication/forms.py
from django import forms
from django.views.generic import View
from django.shortcuts import render, redirect
from django.http import JsonResponse
from main_files.models import Avatar
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm, UserChangeForm # import des fonctions login et authenticate
from django.core.validators import FileExtensionValidator, MinLengthValidator



class LoginForm(forms.Form):
    username = forms.CharField(
        max_length=100,
        label='',
        widget=forms.TextInput(
            attrs={'class': 'custom-input', 'placeholder': 'Username'}
        )
    )
    password = forms.CharField(
        label='',
        widget=forms.PasswordInput(
            attrs={'class': 'custom-input', 'placeholder': 'Password'}
        )
    )

class RegisterForm(forms.Form):
    login = forms.CharField(
        label='',
        validators=[
            MinLengthValidator(3, message='Login must be at least 3 characters long.')
        ],
        max_length=20,
        required=True,
        widget=forms.TextInput(
            attrs={'class': 'form-control white-text custom-input', 'placeholder' : 'Username'}
        )
    )
    email = forms.EmailField(
        label='',
        required=True,
        widget=forms.EmailInput(
            attrs={'class': 'form-control white-text custom-input', 'placeholder' : 'Email'}
        )
    )
    password1 = forms.CharField(
        label='',
        widget=forms.PasswordInput(
            attrs={'class': 'form-control white-text custom-input', 'placeholder' : 'Password'}
        )
    )
    password2 = forms.CharField(
        label='',
        widget=forms.PasswordInput(
            attrs={'class': 'form-control white-text custom-input', 'placeholder' : 'Confirm Password'}
        )
    )

class UpdateNicknameForm(forms.Form):
    newnickname = forms.CharField(
        max_length=50,
        label='',
        widget=forms.TextInput(
            attrs={'class': 'form-control white-text custom-input', 'placeholder' : 'New Nickname'}
        ),
        required=False
    )

class AvatarForm(forms.ModelForm):
    class Meta:
        model = Avatar
        fields = ['avatar',]

class UpdatePasswordForm(forms.Form):
    old_password = forms.CharField(
        label="",
        widget=forms.PasswordInput(attrs={'class': 'form-control white-text custom-input', 'placeholder' : 'Old Password'}),
    )
    new_password1 = forms.CharField(
        label="",
        widget=forms.PasswordInput(attrs={'class': 'form-control white-text custom-input', 'placeholder' : 'New Password'}),
        # help_text="Le mot de passe doit avoir au moins 8 caractères et ne doit pas être trop similaire à vos autres informations personnelles.",
    )
    new_password2 = forms.CharField(
        label="",
        widget=forms.PasswordInput(attrs={'class': 'form-control white-text custom-input', 'placeholder' : 'Confirm New Password'}),
    )
