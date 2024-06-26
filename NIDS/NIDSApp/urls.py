from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.home, name='home'),
    path('scanNetwork/', views.gotoScan, name='gotoScan'),
    path('scanPCAPFile/', views.scanPCAP, name='scanPCAPFile'),
    path('scanLiveTraffic/', views.scanLiveTraffic, name='scanLiveTraffic'),
    path('about/', views.about, name='about'),
    path('live/', views.liveTraf, name='liveTraf')
]

# if settings.DEBUG:
#     urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
