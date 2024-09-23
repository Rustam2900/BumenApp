import random

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractUser

from common.models import BaseModel, Media
from account.managers import CustomUserManager


class User(AbstractUser, BaseModel):
    class AuthType(models.TextChoices):
        GOOGLE = "GOOGLE", _("Google Account")
        FACEBOOK = "FACEBOOK", _("Facebook Account")
        TELEGRAM = "TELEGRAM", _("Telegram Account")
        WITH_PHONE = "WITH PHONE", _("Phone Number")

    username = models.CharField(max_length=123, unique=True, null=True, blank=True)
    birth_date = models.DateField(_("birth_date"), null=True, blank=True)
    photo = models.ForeignKey(
        Media, on_delete=models.SET_NULL, null=True, blank=True
    )
    email = models.EmailField(_("email address"), unique=True, null=True, blank=True)
    phone_number = models.CharField(
        _("phone number"), unique=True, max_length=20, null=True, blank=True
    )
    auth_type = models.CharField(
        _("auth type"), choices=AuthType.choices, max_length=244
    )
    telegram_id = models.CharField(_("telegram id"), max_length=55, null=True, blank=True)
    objects = CustomUserManager()

    USERNAME_FIELD = "phone_number"
    REQUIRED_FIELDS = []

    def __str__(self) -> str:
        return self.phone_number or self.email or self.username

    def generate_verify_code(self):
        code = ''.join([str(random.randint(0, 100) % 10) for _ in range(5)])
        UserOtpCode.objects.create(
            user=self,
            code=code, # codeni testlash uchun 5 ta 1 sonini qoydim, default code deb qoyilishi kerak
            expires_at=timezone.now() + timezone.timedelta(minutes=5),
        )
        return code

    class Meta:
        verbose_name = _("User")
        verbose_name_plural = _("Users")


class UserOtpCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="otp_codes")
    code = models.CharField(max_length=5)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return f'{self.user.phone_number} opt code is {self.code}'

    class Meta:
        verbose_name = _("User OTP Code")
        verbose_name_plural = _("User OTP Codes")

