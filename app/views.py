from django.shortcuts import render
from django.http import HttpResponse
from .models import IP,ReverseShell,ShellType
from .forms import CreateForm
from rest_framework import serializers
from rest_framework.renderers import JSONRenderer
from django.core import serializers as core_serializers
import json
from .reverseShellCommands import dataFunction,myListener
import random



def index(request):
    if request.method == 'POST':
        form = CreateForm(request.POST)
        if form.is_valid():
            form.save()            
        else:
            print(form.errors)  
            all_ip = IP.objects.filter().order_by('-id')[:1]
            data2 = ReverseShell.objects.all()
            reverse_shell = ReverseShell.objects.all()
            key = dataFunction(request)
            listner = myListener()
            shelltype = ShellType.objects.all()

            return render(request, "app/index.html", {"shelltype":shelltype,"listner":listner,"key":key,"data2":data2,"form":form, "all_ip":all_ip,"reverse_shell":reverse_shell})
    
 
    shelltype = ShellType.objects.all()
    key = dataFunction(request) # command data 
    listner = myListener() # listener data
    all_ip = IP.objects.filter().order_by('-id')[:1]
    data2 = ReverseShell.objects.all()
    reverse_shell = ReverseShell.objects.all()    


    form = CreateForm()
    return render(request, "app/index.html", {"shelltype":shelltype,"listner":listner,"key":key,"data2":data2,"form":form,"all_ip":all_ip,"reverse_shell":reverse_shell})