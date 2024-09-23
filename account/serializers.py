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
        code = user.generate_verify_code()
        return {
            'success': True,
            'message': 'Telefon raqamingizga sms orqali kod jonatildi',
            'code': code,
        }


class RegisterVerifySerializer(serializers.Serializer):
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


class UserQuestionChoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.UserQuestionChoice
        fields = ('option', )

    def create(self, validated_data):
        question = models.Question.objects.get(id=self.context['question_id'])
        option = validated_data['option']
        user = self.context['request'].user

        user_choice = models.UserQuestionChoice.objects.create(
            question=question,
            option=option,
            user=user,
        )
        return user_choice


class OptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Option
        fields = ('id', 'text')


class QuestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Question
        fields = ('text', 'description')


class UserQuestionGetSerializer(serializers.Serializer):
    question = QuestionSerializer()
    option = OptionSerializer(many=True)
