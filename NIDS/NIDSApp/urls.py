from django.urls import path
from . import views

urlpatterns = [
    path('', views.processPCAP, name='processPCAP'),
    path('scan', views.scanPCAP, name='scan')
]
