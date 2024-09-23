from django.utils import timezone
from rest_framework import generics, views, status, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken

from account import models, serializers


class RegisterApiView(generics.GenericAPIView):
    serializer_class = serializers.RegisterSerializer

    def post(self, request):
        serializer = serializers.RegisterSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            data = serializer.save()
            return Response(data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterVerifyApiView(generics.GenericAPIView):
    serializer_class = serializers.RegisterVerifySerializer

    def post(self, request):
        serializer = serializers.RegisterVerifySerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            phone_number = serializer.data['phone_number']
            code = serializer.data['code']
            try:
                user = models.User.objects.get(phone_number=phone_number)
                otp_code = models.UserOtpCode.objects.get(code=code)
            except models.User.DoesNotExist and models.UserOtpCode.DoesNotExist:
                return Response(status=status.HTTP_404_NOT_FOUND)
            if otp_code.expires_at > timezone.now() and otp_code.is_used == False:
                user.is_active = True
                otp_code.is_used = True
                user.save()
                otp_code.save()
                return Response({'success': True, 'message': 'User is activated'}, status=status.HTTP_200_OK)
            else:
                return Response(
                    {'success': False, 'messages': 'User is not activated, Code is incorrect'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordRequestApiView(generics.GenericAPIView):
    serializer_class = serializers.ResetPasswordRequestSerializer

    def post(self, request):
        serializer = serializers.ResetPasswordRequestSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            phone_number = serializer.data['phone_number']
            try:
                user = models.User.objects.get(phone_number=phone_number)
                code = user.generate_verify_code()
                return Response({"message": serializer.data, "code": code}, status=status.HTTP_200_OK)
            except models.User.DoesNotExist:
                return Response(status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordVerifyApiView(generics.GenericAPIView):
    serializer_class = serializers.ResetPasswordVerifySerializer

    def post(self, request):
        serializer = serializers.ResetPasswordVerifySerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            code = serializer.data['code']
            try:
                otp_code = models.UserOtpCode.objects.get(code=code)
                if otp_code.is_used != False or otp_code.expires_at < timezone.now():
                    return Response({''},status=status.HTTP_404_NOT_FOUND)
                otp_code.is_used = True



                user = otp_code.user

                if user:
                    return Response({"message": 'code tasdiqlandi', 'user_id': user.id}, status=status.HTTP_200_OK)
                else:
                    return Response({"message": 'code tasdiqlanmadi'}, status=status.HTTP_400_BAD_REQUEST)
            except models.UserOtpCode.DoesNotExist:
                return Response({'message': 'code is invalid'},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordApiView(generics.GenericAPIView):
    serializer_class = serializers.ResetPasswordSerializer

    def post(self, request, *args, **kwargs):
        user_id = kwargs.get('user_id')
        if not user_id:
            return Response({'message': 'user id topilmadi topilmadi'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = models.User.objects.get(id=user_id)
        except Exception as e:
            return Response({"detail": "Token noto'g'ri yoki muddati o'tgan"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = serializers.ResetPasswordSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            new_password = serializer.data['new_password']
            user.set_password(new_password)
            user.save()

            return Response({'message': 'Parol muvaffaqiyatli ozgartirildi'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class InterestsApiView(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.InterestSerializer
    def get_queryset(self):
        return models.Interest.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
