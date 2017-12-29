"""Manages the admin for the todoist module"""
from django.contrib import admin

from . import models

admin.register(models.OAuthToken)
admin.register(models.OAuthTokenRequest)

# Register your models here.
