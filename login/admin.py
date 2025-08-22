from django.contrib import admin
from .models import UserProfile, LoginHistory, UserRole, Department, SystemSettings, UserActivity, UserSession

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'employee_id', 'department', 'created_at']
    search_fields = ['user__username', 'employee_id', 'department']
    list_filter = ['department', 'created_at']

@admin.register(LoginHistory)
class LoginHistoryAdmin(admin.ModelAdmin):
    list_display = ['user', 'login_time', 'logout_time', 'ip_address', 'is_active']
    list_filter = ['is_active', 'login_time']
    search_fields = ['user__username', 'ip_address']

@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ['user', 'role', 'assigned_by', 'is_active']
    list_filter = ['role', 'is_active']
    search_fields = ['user__username']

@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ['name', 'manager', 'is_active', 'created_at']
    list_filter = ['is_active']
    search_fields = ['name']

@admin.register(SystemSettings)
class SystemSettingsAdmin(admin.ModelAdmin):
    list_display = ['key', 'value', 'data_type', 'updated_by', 'updated_at']
    list_filter = ['data_type']
    search_fields = ['key']

@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'model_name', 'timestamp']
    list_filter = ['action', 'timestamp']
    search_fields = ['user__username', 'model_name']

@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ['user', 'session_key', 'ip_address', 'is_active', 'last_activity']
    list_filter = ['is_active', 'last_activity']
    search_fields = ['user__username', 'session_key']
