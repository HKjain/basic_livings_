from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from .models import City, Area, User
from .forms import AddUserForm
from django.contrib.auth.models import auth

from django.contrib.auth.password_validation import get_password_validators
import json
# Create your views here.

next_path = '/'


def index(request):
    addForm = AddUserForm()
    cities = City.objects.all()
    global next_path
    next_path = request.GET.get('next', '/')
    datas = {'cities': cities, 'add': addForm}
    return render(request, 'accounts/index.html', datas)


def register(request):
    cities = City.objects.all()
    if request.method == 'POST':
        form = AddUserForm(request.POST or None)
        if form.is_valid():
            print(form.errors)
            myuser = form.save()
            messages.success(request, "Registered Successfully !!")
            return redirect('login')
        else:
            for err in form.errors:
                print(err)
            return render(request, 'accounts/index.html', {'add': form, 'cities': cities})

    else:
        return render(request, 'accounts/index.html')


def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = auth.authenticate(email=email, password=password)

        if user is not None:
            auth.login(request, user)
            return redirect(next_path)
        else:
            messages.info(request, 'Invalid Credentials!!')
            return redirect('/accounts/')
    else:
        addForm = AddUserForm()
        return render(request, 'accounts/index.html', {'add': addForm})


@login_required
def logout(request):
    auth.logout(request)
    return redirect('/')


def area_handle(request):
    id = int(request.POST['id'])
    areas_list = Area.objects.filter(city_id=id)
    myList = []
    for area in areas_list:
        tup = (area.area_id, area.area_name)
        myList.append(tup)

    json_data = json.dumps(myList)
    return HttpResponse(json_data)


