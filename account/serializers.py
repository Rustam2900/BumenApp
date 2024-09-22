import re
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _

from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

from account import models


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.User
        fields = ('phone_number', 'password')

    def validate_phone_number(self, value):
        regex = r'^998\d{9}$'
        if not re.match(regex, value):
            raise serializers.ValidationError(_("Invalid phone number format for SNG countries."))
        return value

    def create(self, validated_data):
        user = models.User.objects.create_user(
            phone_number=validated_data['phone_number'],
            password=validated_data['password'],
            is_active=False,
        )
        user.generate_verify_code()
        return {
            'success': True,
            'message': 'Telefon raqamingizga sms orqali kod jonatildi'
        }


class RegisterVerifySerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=100)
    code = serializers.CharField(max_length=5)


class ResetPasswordRequestSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=15)


class ResetPasswordVerifySerializer(serializers.Serializer):
    code = serializers.CharField(max_length=5)


class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(max_length=100)
    new_password_confirmation = serializers.CharField(max_length=100)

    def validate(self, data):
        if data['new_password'] != data['new_password_confirmation']:
            raise serializers.ValidationError("Parollar mos emas")
        return data


