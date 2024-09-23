from django.contrib import admin
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _

from account import models


@admin.register(models.User)
class CustomUserAdmin(UserAdmin):
    fieldsets = (
        (None, {"fields": ("phone_number", "password")}),
        (_("Personal info"), {"fields": ("first_name", "last_name", "email")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                ),
            },
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("phone_number", "password1", "password2"),
            },
        ),
    )
    list_display = ("phone_number", "email", "is_staff")
    list_filter = ("is_staff", "is_superuser", "is_active")
    search_fields = ("phone_number", "first_name", "last_name", "email")
    ordering = ("phone_number", 'username', 'email', 'date_joined')


@admin.register(models.UserOtpCode)
class UserOtpCodeAdmin(admin.ModelAdmin):
    list_display = ("user", "code")
    list_display_links = list_display

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(models.Option)
class OptionAdmin(admin.ModelAdmin):
    pass

@admin.register(models.Question)
class QuestionAdmin(admin.ModelAdmin):
    pass

@admin.register(models.UserQuestionChoice)
class UserQuestionChoiceAdmin(admin.ModelAdmin):
    pass



admin.site.unregister(Group)