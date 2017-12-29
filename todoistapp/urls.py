"""urls for the todoist module"""
from django.urls import path

from . import views

urlpatterns = [  # pragma pylint: disable=invalid-name
    path('authorize/', views.authorize, name='authorize'),
    path('authorize/callback/', views.authorize, name='callback'),
]
