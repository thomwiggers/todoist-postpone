"""Views for the todoist interface"""
import base64
import binascii
import hmac
import json

import requests
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import (Http404, HttpResponseBadRequest,
                         HttpResponseNotAllowed, JsonResponse)
from django.shortcuts import redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_variables
from django.views.decorators.http import require_GET

from .models import OAuthToken, OAuthTokenRequest


def cant_have_token(function):
    """Makes sure that the user doesn't have a token already"""
    def _wrapper(request, *args, **kwargs):
        if ((not request.user.is_authenticated) or
                OAuthToken.objects.filter(user=request.user).count() > 0):
            raise Http404
        return function(request, *args, **kwargs)

    return _wrapper

@csrf_exempt
def _validate_todoist_hmac(function):
    """Validate the HMAC sent by Todoist"""
    def _wrapper(request, *args, **kwargs):
        if request.method != 'POST':
            return HttpResponseNotAllowed(['POST'])
        if request.content_type != 'application/json':
            return HttpResponseBadRequest('Needs to be json')
        request_hmac = request.META.get('HTTP_X_TODOIST_HMAC_SHA256')
        if not request_hmac:
            raise PermissionDenied('HMAC not specified')
        try:
            request_hmac = base64.b64decode(request_hmac)
        except binascii.Error as error:
            raise PermissionDenied('HMAC invalid format') from error
        hashresult = hmac.new(settings.TODOIST_CLIENT_SECRET,
                              request.body,
                              digestmod='SHA256')
        if hmac.compare_digest(hashresult.digest(), request_hmac):
            return function(request, *args, **kwargs)
        else:
            raise PermissionDenied('HMAC does not match')

    return _wrapper


@require_GET
@login_required
def authorize(request):
    """Authorize with todoist"""
    state = OAuthTokenRequest.new_state(request.user)
    todoist_url = (f'https://todoist.com/oauth/authorize?'
                   f'client_id={settings.TODOIST_CLIENT_ID}&'
                   f'scope=data:read_write,data:delete&'
                   f'state={state}')

    return redirect(todoist_url)


@sensitive_variables('code')
@require_GET
@login_required
def callback(request):
    """Handle the Todoist OAuth2 callback"""
    error = request.GET.get('error')
    error_message = None
    if error == 'access_denied':
        error_message = _("You need to allow access to use Postpone")
    elif error:
        raise Exception(error)
    else:
        code = request['code']
        state = request['state']
        if not OAuthTokenRequest.verify_state(state):
            error_message = _('Invalid token specified')
        else:
            response = requests.post(
                'https://todoist.com/oauth/access_token',
                data={
                    'client_id': settings.TODOIST_CLIENT_ID,
                    'client_secret':
                    settings.TODOIST_CLIENT_SECRET.decode('utf-8'),
                    'code': code,
                },
            ).json()
            if 'error' in response:
                raise Exception(response['error'])

    return render(request, 'todoist/authorized.html', {
        'error_message': error_message,
        })


@_validate_todoist_hmac
def webhook(request):
    """Handle incoming requests from todoist"""
    try:
        json_data = json.loads(request.body)
    except json.decoder.JSONDecodeError as error:
        return HttpResponseBadRequest(str(error))

    # FIXME handle event data
    del json_data

    return JsonResponse({
        'status': 'ok',
        })
