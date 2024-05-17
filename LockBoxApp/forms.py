from django import forms
from .models import File

class FileForm(forms.ModelForm):
    class Meta:
        model = File
        fields = ['name', 'content']  # Fields you want to include in the form


class FileUploadForm(forms.Form):
    file = forms.FileField()