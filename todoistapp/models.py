"""
Models for postponed tasks
"""
import logging

from django.conf import settings
from django.core import signing
from django.core.exceptions import SuspiciousOperation
from django.db import models
from django.utils import crypto
from django.utils.translation import gettext_lazy as _

TASK_PRIORITIES = (
    (1, _('natural')),
    (2, _('medium priority')),
    (3, _('high priority')),
    (4, _('urgent priority')),
)

TASK_INDENTATIONS = (
    (1, _('no indentation')),
    (2, _('1 level indented')),
    (3, _('2 levels indented')),
    (4, _('3 levels indented'))
)


logger = logging.getLogger(__name__)  # pragma pylint: disable=invalid-name


class Task(models.Model):
    """Represent Todoist Tasks"""
    data = models.TextField(_('task content in json'))

    postponed_date = models.DateTimeField(_('postponed to date'))


class OAuthToken(models.Model):
    """OAuth tokens for users"""
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        models.CASCADE,
        unique=True,
    )

    token = models.CharField(max_length=100)


class OAuthTokenRequest(models.Model):
    """Models the state we pass around for oauth"""
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        models.CASCADE,
    )

    nonce = models.CharField(max_length=40)

    @classmethod
    def new_state(cls, user):
        """Return a signed record of a new token in the database"""
        nonce = crypto.get_random_string(length=40)
        data = {
            'user_id': user.id,
            'nonce': nonce,
        }
        try:
            record = cls.objects.get(user=user)
            record.nonce = nonce
            record.save()
        except cls.DoesNotExist:
            cls.objects.create(**data)

        return signing.dumps(data)

    @classmethod
    def verify_state(cls, state):
        """Verify a state has a correct nonce"""
        try:
            record = signing.loads(state, max_age=3600)
        except signing.SignatureExpired:
            logger.info("tried to use an expired state")
            return False
        except signing.BadSignature as error:
            raise SuspiciousOperation("Invalid state signature") from error

        try:
            row = cls.objects.get(**record)
            row.delete()
        except cls.DoesNotExist:
            logger.info("Tried to re-use a state")
            return False

        return True
