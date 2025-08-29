from django.urls import path
from . import views
from .views import upload_plan, pending_plans_for_head, review_plan

urlpatterns = [
    # Authentication endpoints
    path('login/', views.user_login, name='user_login'),
    path('logout/', views.user_logout, name='user_logout'),
    path('register/', views.register_user, name='register_user'),

    # Dashboard endpoints
    path('user-dashboard/', views.user_dashboard, name='user_dashboard'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),

    # User management endpoints
    path('users/', views.get_all_users, name='get_all_users'),
    path('users/<int:user_id>/status/', views.update_user_status, name='update_user_status'),
    path('users/<int:user_id>/update/', views.update_user, name='update_user'),
    path('users/<int:user_id>/delete/', views.delete_user, name='delete_user'),

    # Profile endpoints
    path('profile/', views.get_profile, name='get_profile'),
    path('profile/update/', views.update_profile, name='update_profile'),

    # Plan upload endpoint
    path('upload-plan/', upload_plan, name='upload-plan'),
    path('pending-plans/', pending_plans_for_head, name='pending-plans'),
    path('review-plan/<int:plan_id>/', review_plan, name='review-plan'),
]
