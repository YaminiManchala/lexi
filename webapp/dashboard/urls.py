from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('scan/', views.output_view, name='scan'), 
    path('download/', views.download_report, name='download'),
]