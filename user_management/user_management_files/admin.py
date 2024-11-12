from django.contrib import admin
from user_management_files.models import  User, Friend
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .forms import CustomUserCreationForm, CustomUserChangeForm

# class GameAdmin(admin.ModelAdmin): 
#         list_display = ('score_joueur_1', 'score_joueur_2', )
# admin.site.register(Game, GameAdmin)

class CustomUserAdmin(BaseUserAdmin):
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = User
    list_display = ['login', 'email', 'is_staff', 'is_active']
    list_filter = ('is_staff', 'is_active',)	
    fieldsets = (
        (None, {'fields': ('login', 'email', 'password')}),
        ('Personal info', {'fields': ('nickname', 'avatar', 'nombre_victoire', 'nombre_defaite', 'friends', 'status')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'is_superuser', 'user_permissions')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('login', 'email', 'password1', 'password2', 'is_staff', 'is_active')}
        ),
    )
    search_fields = ('email', 'login',)
    ordering = ('email',)

admin.site.register(User, CustomUserAdmin)

class FriendAdmin(admin.ModelAdmin):
    list_display = ('nickname', 'status')