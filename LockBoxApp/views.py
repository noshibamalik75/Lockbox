from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.contrib.auth.models import User  # Import the User model
from .models import File, SecurityKey
from .forms import *
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from django.contrib.messages import constants as message_constants
from django.contrib.auth.password_validation import validate_password
from django.http import HttpResponse
from .forms import FileUploadForm
from .models import EncryptedFile
from .utils import encrypt_file, decrypt_file, generate_access_key
from django.views import View

def index(request):
    if request.user.is_authenticated:
        return render(request, 'LockBoxApp/index.html')
    else:
        return redirect('login')

def file_list(request):
    if request.user.is_authenticated:
        files = File.objects.filter(owner=request.user)
        return render(request, 'LockBoxApp/file_list.html', {'files': files})
    else:
        return redirect('login')

def security_key_list(request):
    keys = SecurityKey.objects.filter(user=request.user)
    return render(request, 'LockBoxApp/security_key_list.html', {'keys': keys})

def upload_file(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            form = FileForm(request.POST, request.FILES)
            if form.is_valid():
                file_instance = form.save(commit=False)
                file_instance.owner = request.user
                file_instance.save()
                return redirect('file_list')
        else:
            form = FileForm()
        return render(request, 'LockBoxApp/upload_file.html', {'form': form})
    else:
        return redirect('login')
    new_filename = f'{filename}{extension}'
    
def delete_files(request):
    if request.method == 'POST':
        file_ids = request.POST.getlist('file_ids')  # Get the list of selected file IDs
        files_to_delete = File.objects.filter(id__in=file_ids)
        files_to_delete.delete()  # Delete the selected files
        return redirect('file_list')  # Redirect to the file list page
    files = File.objects.all()
    return render(request, 'LockBoxApp/delete_files.html', {'files': files})




def manage_access(request, file_id):
    try:
        file = File.objects.get(id=file_id)
    except File.DoesNotExist:
        raise Http404("File does not exist")

    users = User.objects.all()  # Get all users
    if request.method == 'POST':
        shared_users = request.POST.getlist('shared_users')
        file.shared_with.set(shared_users)
    
    return render(request, 'LockBoxApp/manage_access.html', {'file': file, 'users': users})


def manage_access_settings(request, file_id):
    file = File.objects.get(id=file_id)
    users = User.objects.all()
    
    if request.method == 'POST':
        shared_user_id = request.POST.get('shared_user')
        permission = request.POST.get('permission')
        
        try:
            shared_user = User.objects.get(id=shared_user_id)
            if permission == 'read-only':
                file.shared_with.add(shared_user)
            elif permission == 'read-write':
                file.shared_with.add(shared_user)
            elif permission == 'no-access':
                file.shared_with.remove(shared_user)
            file.save()
            return redirect('manage_access_settings', file_id=file_id)
        except User.DoesNotExist:
            # Handle user not found error
            pass
        except File.DoesNotExist:
            # Handle file not found error
            pass
    
    return render(request, 'LockBoxApp/manage_access_settings.html', {'file': file, 'users': users})

#view for signup user
def SignUp(request):
    if request.user.is_authenticated:
        return redirect('index')
    else:
        if request.method == 'POST':
            username = request.POST['username']
            email = request.POST['email']
            password = request.POST['password']
            cpassword = request.POST['cpassword']
            firstname = request.POST['fname']
            lname = request.POST['lname']
            if username and password and email and cpassword and firstname and lname:
                if password == cpassword:
                    validate_password(password, user=None, password_validators=None)
                    user = User.objects.create_user(username,email,password)
                    user.first_name = firstname
                    user.last_name = lname
                    user.save()
                    if user:
                        messages.success(request,"User Account Created")
                        return redirect("login")
                    else:
                        messages.error(request,"User Account Not Created")
                else:
                    messages.error(request,"Password Not Matched")
                    redirect("signup")
        return render(request,'LockBoxApp/signup.html')
    
# View For Log in the user
def Login(request):
    if request.user.is_authenticated:
        return redirect("login")
    else:
        if request.method == 'POST':
            username = request.POST['username']
            password = request.POST['password']
            if username and password:
                user = authenticate(username=username,password=password)
                if user is not None:
                    login(request,user)
                    return redirect('index')
        return render(request,'LockBoxApp/login.html')
    
# User logout function
def Logout(request):
    logout(request)
    return redirect('login')


class FileEncryptView(View):
    def get(self, request):
        form = FileUploadForm()
        return render(request, 'upload.html', {'form': form})

    def post(self, request):
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            file_path, encrypted_path = encrypt_file(uploaded_file)
            access_key = generate_access_key()
            encrypted_file = EncryptedFile.objects.create(file_path=encrypted_path, access_key=access_key)
            return HttpResponse(encrypted_file.get_absolute_url())
        return HttpResponse('Invalid form', status=400)

class FileDecryptView(View):
    def get(self, request, pk):
        encrypted_file = EncryptedFile.objects.get(pk=pk)
        if request.GET.get('access_key') == encrypted_file.access_key:
            file_path = decrypt_file(encrypted_file.file_path)
            with open(file_path, 'rb') as f:
                response = HttpResponse(f.read(), content_type='application/octet-stream')
                response['Content-Disposition'] = 'attachment; filename="{}"'.format(file_path)
                return response
        return HttpResponse('Unauthorized', status=401)

