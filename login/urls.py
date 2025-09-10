from django.urls import path
from . import views

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

    # Plan upload and review endpoints
    path('my-plans/', views.my_plans, name='my_plans'),
    path('upload-plan/', views.upload_plan, name='upload_plan'),
    path('review-plan/<int:plan_id>/', views.review_plan, name='review_plan'),
    path('pending-plans/', views.pending_plans_for_head, name='pending_plans'),
    path('approved-plans/', views.approved_plans, name='approved_plans'),
    path('hod-processed-plans/', views.hod_processed_plans, name='hod_processed_plans'),

    # Statistics upload and review endpoints
    path('my-statistics/', views.my_statistics, name='my_statistics'),
    path('upload-statistic/', views.upload_statistic, name='upload_statistic'),
    path('review-statistic/<int:stat_id>/', views.review_statistic, name='review_statistic'),
    path('pending-statistics/', views.pending_statistics, name='pending_statistics'),
    path('approved-statistics/', views.approved_statistics, name='approved_statistics'),

    # Budget endpoints
    path('budget/', views.budget_view, name='budget_view'),
    path('budget-history/', views.budget_history, name='budget_history'),
]

