from django.db import models
# from django.core.validators import MaxValueValidator, MinValueValidator
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin, Group, Permission
from django.utils.translation import gettext_lazy as _
import bleach

ALLOWED_TAGS = ['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'br', 'span']
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title'],
    'span': ['class']
}

def clean_html(value):
    return bleach.clean(value, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)

class UserManager(BaseUserManager):
    def create_user(self, login, email, password=None):
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(
            login=login,
            email=self.normalize_email(email),
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_user_from_api(self, login, email):
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(
            login=login,
            email=self.normalize_email(email),
        )
        user.is_api_user = True
        user.save(using=self._db)
        return user

    def create_superuser(self, login, email, password=None):
        user = self.create_user(
            login=login,
            email=email,
            password=password,
        )
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user
    
class User(AbstractBaseUser, PermissionsMixin):
    login = models.CharField(max_length=150, unique=True)
    nickname = models.CharField(max_length=143, unique=True, blank=True, null=True)
    email = models.EmailField(unique=True)
    avatar = models.ImageField(upload_to='avatars', default="/media/avatars/iop.png")
    nombre_victoire = models.IntegerField(default=0)
    nombre_defaite = models.IntegerField(default=0)
    status = models.CharField(default = 'offline')
    # historique_de_jeu = models.ManyToManyField('other_app.Game', related_name='parties', blank=True)
    friends = models.ManyToManyField('self', symmetrical=False, verbose_name='Amis', related_name='amis', blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_api_user = models.BooleanField(default=False)
    double_auth_activate = models.BooleanField(default=False)
    double_auth_key = models.CharField(max_length=1000, blank=True, null=True)
    
    objects = UserManager()
        
    USERNAME_FIELD = 'login'
    REQUIRED_FIELDS = ['email']

    groups = models.ManyToManyField(
        Group,
        verbose_name=_('groups'),
        blank=True,
        help_text=_(
            'The groups this user belongs to. A user will get all permissions '
            'granted to each of their groups.'
        ),
        related_name="customuser_set",
        related_query_name="user",
    )

    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('user permissions'),
        blank=True,
        help_text=_('Specific permissions for this user.'),
        related_name="customuser_set",
        related_query_name="user",
    )

    def save(self, *args, **kwargs):
        self.login = clean_html(self.login)
        self.nickname = clean_html(self.nickname) if self.nickname else self.login
        self.email = clean_html(self.email)
        # self.avatar.url = clean_html(self.avatar.url)
        self.status = clean_html(self.status)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.login

class Friend(models.Model):
    from_user = models.ForeignKey(User, related_name='friendships_sent', on_delete=models.CASCADE)
    to_user = models.ForeignKey(User, related_name='friendships_received', on_delete=models.CASCADE)
    status = models.CharField(default = 'pending')

    class Meta:
        unique_together = ('from_user', 'to_user')
        verbose_name = "Friend"
        verbose_name_plural = "Friends"

    def save(self, *args, **kwargs):
        self.status = clean_html(self.status)
        super().save(*args, **kwargs)

    def __str__(self):
            return f"{self.from_user} -> {self.to_user} ({self.status})"

