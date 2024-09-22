from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from account import views


urlpatterns = [
    path('register/', views.RegisterApiView.as_view(), name='register'),
    path('register/verify/', views.RegisterVerifyApiView.as_view(), name='register-verify'),
    path('login/', TokenObtainPairView.as_view(), name='login'),
    path('refresh/', TokenRefreshView.as_view(), name='refresh'),
    path('password-reset/request/', views.ResetPasswordRequestApiView.as_view(), name='password-reset-request'),
    path('password-reset/verify/', views.ResetPasswordVerifyApiView.as_view(), name='password-reset-verify'),
    path('password-reset/password/<str:token>/', views.ResetPasswordApiView.as_view(), name='password-reset-password'),
]
