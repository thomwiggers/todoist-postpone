from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render


def index(request):
    """Index view"""
    return render(request, 'interface/index.html')


@login_required
def profile(request):
    """Show the profile page"""

    return render(request, 'interface/profile.html', {
        'user': request.user,
    })
