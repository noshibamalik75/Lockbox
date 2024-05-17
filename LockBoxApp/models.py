from django.db import models
from django.contrib.auth.models import User
from django.urls import reverse


class File(models.Model):
    name = models.CharField(max_length=100)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.FileField(upload_to='files/%Y/%m/%d/')
    shared_with = models.ManyToManyField(User, related_name='shared_files', blank=True)
    
class SecurityKey(models.Model):
    key = models.CharField(max_length=100)
    user = models.ForeignKey(User, on_delete=models.CASCADE)




class EncryptedFile(models.Model):
    file_path = models.CharField(max_length=1024)
    access_key = models.CharField(max_length=1024)  # This should be securely generated

    def get_absolute_url(self):
        return reverse('encrypted_file', kwargs={'pk': self.pk})