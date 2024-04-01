from django.shortcuts import render
from django.http import HttpResponse

# Create your views here.

def processPCAP(request):
    return render(request, 'index.html')

def scanPCAP(request):
    return HttpResponse('Hello World')