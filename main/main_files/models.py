from django.conf import settings
from django.db import models
from django.core.validators import FileExtensionValidator

class Avatar(models.Model):
    avatar = models.ImageField(upload_to='avatars', default="avatars/iop.png", validators=[
            FileExtensionValidator(['jpg', 'jpeg', 'png']),
            # MaxFileSizeValidator(2 * 1024 * 1024)  # 2 MB (adjust size as needed)
        ]
    )
    caption = models.CharField(max_length=123, blank=True, verbose_name='légende')
    date_created = models.DateTimeField(auto_now_add=True)

    @property
    def url(self):
        if self.avatar and hasattr(self.avatar, 'url'):
            return self.avatar.url
        return ''
    
    def filename(self):
        if self.avatar and hasattr(self.avatar, 'name'):
            return self.avatar.name.split('/')[-1]
        return ''


