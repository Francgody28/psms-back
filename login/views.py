from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .serializers import LoginSerializer, UserRegistrationSerializer, UserSerializer, AdminDashboardSerializer, PlanSerializer
from .models import Plan
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.db.models import Q
from .models import Statistic
from .serializers import StatisticSerializer
from .models import Budget, BudgetHistory
from decimal import Decimal
from django.http import FileResponse, Http404
import mimetypes, os
from django.core.files.storage import default_storage
from django.conf import settings
from django.utils.encoding import smart_str
from django.utils import timezone

@api_view(['POST'])
@permission_classes([AllowAny])
def user_login(request):
    """Login endpoint with role-based dashboard routing"""
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        # Authenticate user
        user = authenticate(username=username, password=password)
        
        if user and user.is_active:
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            
            # Get user role from profile
            user_role = getattr(getattr(user, 'profile', None), 'role', '')
            
            # Determine dashboard URL based on role
            dashboard_url = '/dashboard'  # default
            if user.is_staff or user.is_superuser:
                dashboard_url = '/admin-dashboard'
                user_role = 'admin'
            elif user_role == 'head_of_division':
                dashboard_url = '/head-of-division-dashboard'
            elif user_role == 'head_of_department':
                dashboard_url = '/head-of-department-dashboard'
            elif user_role == 'planning_officer':
                dashboard_url = '/planning-dashboard'
            elif user_role == 'statistics_officer':
                dashboard_url = '/statistics-dashboard'
            elif user_role == 'director_general':
                dashboard_url = '/director-general-dashboard'  # added
            
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_admin': user.is_staff or user.is_superuser,
                'is_active': user.is_active,
                'date_joined': user.date_joined,
                'role': user_role
            }
            
            return Response({
                'message': 'Login successful',
                'token': token.key,
                'user': user_data,
                'dashboard_url': dashboard_url
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'error': 'Invalid credentials or inactive account'
            }, status=status.HTTP_401_UNAUTHORIZED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def user_logout(request):
    """Logout endpoint"""
    try:
        # Delete the user's token
        if hasattr(request.user, 'auth_token'):
            request.user.auth_token.delete()
        logout(request)
        return Response({
            'message': 'Successfully logged out'
        }, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({
            'error': 'Error during logout'
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def register_user(request):
    """Admin-only endpoint to register new users"""
    # Check if user is admin
    if not (request.user.is_staff or request.user.is_superuser):
        return Response({
            'error': 'Permission denied. Admin access required.'
        }, status=status.HTTP_403_FORBIDDEN)
    
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({
            'message': 'User registered successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_active': user.is_active
            }
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_dashboard(request):
    """Regular user dashboard"""
    if request.user.is_staff or request.user.is_superuser:
        return Response({
            'error': 'Access denied. This is for regular users only.'
        }, status=status.HTTP_403_FORBIDDEN)
    
    user = request.user
    user_info = {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': getattr(getattr(user, 'profile', None), 'role', '')  # ensure role is returned
    }
    return Response({'user_info': user_info, 'dashboard_type': 'user', 'available_features': [
        'View Profile',
        'Update Profile',
        'View History',
        'Settings'
    ]}, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_dashboard(request):
    """Admin dashboard with user management capabilities"""
    if not (request.user.is_staff or request.user.is_superuser):
        return Response({
            'error': 'Access denied. Admin privileges required.'
        }, status=status.HTTP_403_FORBIDDEN)
    
    # Get all users for admin management
    all_users = User.objects.all().order_by('-date_joined')
    users_data = []
    
    for user in all_users:
        users_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'is_admin': user.is_staff or user.is_superuser,
            'date_joined': user.date_joined,
            'last_login': user.last_login,
            'role': getattr(getattr(user, 'profile', None), 'role', '')
        })
    
    admin_data = {
        'admin_info': {
            'id': request.user.id,
            'username': request.user.username,
            'email': request.user.email,
            'first_name': request.user.first_name,
            'last_name': request.user.last_name,
        },
        'dashboard_type': 'admin',
        'total_users': User.objects.count(),
        'active_users': User.objects.filter(is_active=True).count(),
        'admin_users': User.objects.filter(Q(is_staff=True) | Q(is_superuser=True)).count(),
        'users': users_data,
        'available_features': [
            'User Management',
            'Register New Users',
            'View All Users',
            'Deactivate/Activate Users',
            'System Settings',
            'Reports'
        ]
    }
    
    return Response(admin_data, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_users(request):
    """Admin endpoint to get all users"""
    if not (request.user.is_staff or request.user.is_superuser):
        return Response({
            'error': 'Access denied. Admin privileges required.'
        }, status=status.HTTP_403_FORBIDDEN)
    
    users = User.objects.all().order_by('-date_joined')
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user_status(request, user_id):
    """Admin endpoint to activate/deactivate users"""
    if not (request.user.is_staff or request.user.is_superuser):
        return Response({
            'error': 'Access denied. Admin privileges required.'
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        user = User.objects.get(id=user_id)
        is_active = request.data.get('is_active', user.is_active)
        user.is_active = is_active
        user.save()
        
        return Response({
            'message': f'User {user.username} status updated successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'is_active': user.is_active
            }
        }, status=status.HTTP_200_OK)
    
    except User.DoesNotExist:
        return Response({
            'error': 'User not found'
        }, status=status.HTTP_404_NOT_FOUND)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user(request, user_id):
    """Admin endpoint to update user information"""
    if not (request.user.is_staff or request.user.is_superuser):
        return Response({
            'error': 'Access denied. Admin privileges required.'
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        user = User.objects.get(id=user_id)
        data = request.data

        # Use new value if provided, else keep old value
        username = data.get('username', '').strip() or user.username
        email = data.get('email', '').strip() or user.email
        password = data.get('password', '').strip()
        role = data.get('role', '').strip() or (user.profile.role if hasattr(user, 'profile') else '')

        # Validation: Check if username already exists (excluding current user)
        if username != user.username and User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        # Validation: Check if email already exists (excluding current user)
        if email != user.email and User.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        # Validation: Email format
        import re
        email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_pattern, email):
            return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

        # Update user fields
        user.username = username
        user.email = email

        # Update password only if provided
        if password:
            if len(password) < 8:
                return Response({'error': 'Password must be at least 8 characters long'}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(password)
        user.save()

        # Update role in UserProfile if provided
        if hasattr(user, 'profile') and role:
            user.profile.role = role
            user.profile.save()

        return Response({
            'message': f'User {user.username} updated successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.profile.role if hasattr(user, 'profile') else '',
                'is_active': user.is_active,
                'is_admin': user.is_staff or user.is_superuser
            }
        }, status=status.HTTP_200_OK)
    
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': f'Error updating user: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_user(request, user_id):
    """Admin endpoint to delete a user"""
    if not (request.user.is_staff or request.user.is_superuser):
        return Response({
            'error': 'Access denied. Admin privileges required.'
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        user = User.objects.get(id=user_id)
        
        # Prevent deletion of the requesting admin
        if user.id == request.user.id:
            return Response({
                'error': 'You cannot delete your own account'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        username = user.username
        user.delete()
        
        return Response({
            'message': f'User {username} deleted successfully'
        }, status=status.HTTP_200_OK)
    
    except User.DoesNotExist:
        return Response({
            'error': 'User not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'error': f'Error deleting user: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_profile(request):
    """Get current user profile"""
    serializer = UserSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_profile(request):
    """Update current user profile"""
    serializer = UserSerializer(request.user, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response({
            'message': 'Profile updated successfully',
            'user': serializer.data
        }, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upload_plan(request):
    """Endpoint for planning officer to upload a plan document"""
    try:
        user = request.user
        print(f"Upload request from user: {user.username}")  # Debug log
        
        # Get user role safely
        user_role = ''
        try:
            if hasattr(user, 'profile') and user.profile:
                user_role = getattr(user.profile, 'role', '')
        except Exception as profile_error:
            print(f"Profile error: {str(profile_error)}")
            user_role = ''
        
        print(f"User role: '{user_role}'")  # Debug log
        
        # Allow upload for admins, superusers, and specific roles
        allowed_roles = ['planning_officer', 'head_of_division', 'head_of_department']
        
        if not (user.is_staff or user.is_superuser or user_role in allowed_roles):
            print(f"Access denied for user {user.username} with role '{user_role}'")
            return Response({'error': f'Access denied. Only planning officers and heads can upload plans. Your role: {user_role}'}, 
                           status=status.HTTP_403_FORBIDDEN)
        
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        uploader_name = f"{user.first_name} {user.last_name}".strip() or user.username
        
        plan = Plan.objects.create(
            file=file,
            uploaded_by=user,
            uploader_name=uploader_name,
            status='pending',
            reviewed_by=None
        )
        
        print(f"Plan created with ID: {plan.id}")  # Debug log
        
        serializer = PlanSerializer(plan)
        return Response({
            'message': 'Plan uploaded successfully',
            'plan': serializer.data
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        print(f"Error in upload_plan: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response({'error': f'Upload error: {str(e)}'}, 
                       status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def pending_plans_for_head(request):
    """List plans for heads:
       - head_of_division: plans with status='pending'
       - head_of_department: plans with status='reviewed' (approved by division, awaiting department)
       - admins: default to pending
    """
    user = request.user
    allowed_roles = ['head_of_division', 'head_of_department', 'director_general']  # include DG
    user_role = getattr(getattr(user, 'profile', None), 'role', '')
    
    if not (user.is_staff or user.is_superuser or user_role in allowed_roles):
        return Response({'error': 'Access denied. Only heads can view pending plans.'}, 
                       status=status.HTTP_403_FORBIDDEN)
    
    # Role-based queue
    if user_role == 'head_of_department':
        # items approved by HoDivision (reviewed) awaiting HoDepartment
        plans = Plan.objects.filter(status='reviewed', reviewed_by__profile__role='head_of_division')
    elif user_role == 'director_general' or user.is_staff or user.is_superuser:
        # items approved by HoDepartment (still reviewed) awaiting DG
        plans = Plan.objects.filter(status='reviewed', reviewed_by__profile__role='head_of_department')
    else:
        # head_of_division
        plans = Plan.objects.filter(status='pending')
    
    serializer = PlanSerializer(plans, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def review_plan(request, plan_id):
    """Heads review a plan:
       - head_of_division: approve => 'reviewed', reject => 'rejected'
       - head_of_department: approve => 'reviewed' (forward to DG), reject => 'rejected'
    """
    user = request.user
    allowed_roles = ['head_of_division', 'head_of_department', 'director_general']  # include DG
    user_role = getattr(getattr(user, 'profile', None), 'role', '')
    
    if not (user.is_staff or user.is_superuser or user_role in allowed_roles):
        return Response({'error': 'Access denied. Only heads can review plans.'}, 
                       status=status.HTTP_403_FORBIDDEN)
    
    try:
        plan = Plan.objects.get(id=plan_id)
        action = request.data.get('action', 'approve').strip().lower()
        
        if action == 'reject':
            plan.status = 'rejected'
        else:
            if user_role == 'head_of_division' and not (user.is_staff or user.is_superuser):
                plan.status = 'reviewed'  # stays reviewed, next HoDepartment
                plan.approved_by_hod = user
                plan.approved_at_hod = timezone.now()
            elif user_role == 'head_of_department' and not (user.is_staff or user.is_superuser):
                plan.status = 'reviewed'  # stays reviewed, next DG
                plan.approved_by_hod_dept = user
                plan.approved_at_hod_dept = timezone.now()
            else:
                # DG or admins finalize approval
                plan.status = 'approved'
                plan.approved_by_dg = user
                plan.approved_at_dg = timezone.now()
        
        plan.reviewed_by = user
        plan.save()
        
        return Response({'message': f"Plan {plan.status} successfully.", 'status': plan.status}, status=status.HTTP_200_OK)
        
    except Plan.DoesNotExist:
        return Response({'error': 'Plan not found.'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def my_plans(request):
    """Return all plans uploaded by the current user (for recent activity)"""
    try:
        user = request.user
        print(f"User {user.username} requesting my_plans")  # Debug log
        
        # Get user role safely
        user_role = ''
        try:
            if hasattr(user, 'profile') and user.profile:
                user_role = getattr(user.profile, 'role', '')
        except Exception as profile_error:
            print(f"Profile error in my_plans: {str(profile_error)}")
            user_role = ''
        
        print(f"User role: '{user_role}'")  # Debug log
        
        # Allow admins and users with planning-related roles, or if no role is set (for testing)
        allowed_roles = ['planning_officer', 'head_of_division', 'head_of_department']
        
        # For now, allow users without roles (for testing purposes)
        if not (user.is_staff or user.is_superuser or user_role in allowed_roles or user_role == ''):
            print(f"Access denied for user {user.username} with role '{user_role}'")
            return Response({'error': f'Access denied. Only planning-related roles can view plans. Your role: {user_role}'}, 
                           status=status.HTTP_403_FORBIDDEN)
        
        plans = Plan.objects.filter(uploaded_by=user).order_by('-upload_date')  # Changed from created_at to upload_date
        print(f"Found {plans.count()} plans for user {user.username}")  # Debug log
        
        plans_data = []
        
        for plan in plans:
            try:
                # Safely get file name
                file_name = ''
                if plan.file:
                    file_name = plan.file.name
                
                # Safely get upload_date
                upload_date = ''
                if hasattr(plan, 'upload_date') and plan.upload_date:
                    upload_date = plan.upload_date.isoformat()
                
                plan_data = {
                    'id': plan.id,
                    'file': file_name,
                    'status': getattr(plan, 'status', 'pending'),
                    'created_at': upload_date,  # Changed from created_at to upload_date
                    'uploaded_at': upload_date,  # Changed from created_at to upload_date
                    'uploader_name': getattr(plan, 'uploader_name', user.username),
                    'reviewed_by': plan.reviewed_by.username if plan.reviewed_by else None
                }
                plans_data.append(plan_data)
                print(f"Plan data: {plan_data}")  # Debug log
                
            except Exception as plan_error:
                print(f"Error processing plan {plan.id}: {str(plan_error)}")
                continue
        
        print(f"Returning {len(plans_data)} plans")  # Debug log
        return Response(plans_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"Error in my_plans: {str(e)}")  # Debug log
        import traceback
        traceback.print_exc()
        return Response({'error': f'Internal server error: {str(e)}'}, 
                       status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def upload_statistic(request):
    """Endpoint for statistics officer to upload a statistic document (Word/Excel/PDF)"""
    try:
        user = request.user
        user_role = getattr(getattr(user, 'profile', None), 'role', '')
        allowed_roles = ['statistics_officer', 'head_of_division', 'head_of_department']
        if not (user.is_staff or user.is_superuser or user_role in allowed_roles):
            return Response({'error': f'Access denied. Only statistics officers and heads can upload statistics. Your role: {user_role}'},
                            status=status.HTTP_403_FORBIDDEN)

        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)

        uploader_name = f"{user.first_name} {user.last_name}".strip() or user.username

        stat = Statistic.objects.create(
            file=file,
            uploaded_by=user,
            uploader_name=uploader_name,
            status='pending',
            reviewed_by=None
        )
        serializer = StatisticSerializer(stat)
        return Response({'message': 'Statistic uploaded successfully', 'statistic': serializer.data}, status=status.HTTP_201_CREATED)
    except Exception as e:
        return Response({'error': f'Upload error: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def pending_statistics_for_head(request):
    """List statistics for heads and DG based on role"""
    user = request.user
    user_role = getattr(getattr(user, 'profile', None), 'role', '')
    allowed_roles = ['head_of_division', 'head_of_department', 'director_general']
    if not (user.is_staff or user.is_superuser or user_role in allowed_roles):
        return Response({'error': 'Access denied. Only heads and DG can view pending statistics.'}, status=status.HTTP_403_FORBIDDEN)

    if user_role == 'head_of_department':
        stats = Statistic.objects.filter(status='reviewed', reviewed_by__profile__role='head_of_division')
    elif user_role == 'director_general' or user.is_staff or user.is_superuser:
        stats = Statistic.objects.filter(status='reviewed', reviewed_by__profile__role='head_of_department')
    else:
        stats = Statistic.objects.filter(status='pending')

    serializer = StatisticSerializer(stats, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([JSONParser, FormParser])
def review_statistic(request, stat_id):
    """Heads review a statistic:
       - head_of_division: approve => 'reviewed', reject => 'rejected'
       - head_of_department: approve => 'reviewed' (forward to DG), reject => 'rejected'
       - director_general/admin: approve => 'approved', reject => 'rejected'
    """
    user = request.user
    user_role = getattr(getattr(user, 'profile', None), 'role', '')
    allowed_roles = ['head_of_division', 'head_of_department', 'director_general']  # include DG
    if not (user.is_staff or user.is_superuser or user_role in allowed_roles):
        return Response({'error': 'Access denied. Only heads/DG can review statistics.'}, status=status.HTTP_403_FORBIDDEN)

    try:
        stat = Statistic.objects.get(id=stat_id)
        action = request.data.get('action', 'approve').strip().lower()

        if action == 'reject':
            stat.status = 'rejected'
        else:
            if user_role == 'head_of_division' and not (user.is_staff or user.is_superuser):
                stat.status = 'reviewed'  # to HoDepartment
                stat.approved_by_hod = user
                stat.approved_at_hod = timezone.now()
            elif user_role == 'head_of_department' and not (user.is_staff or user.is_superuser):
                stat.status = 'reviewed'  # to Director General
                stat.approved_by_hod_dept = user
                stat.approved_at_hod_dept = timezone.now()
            else:
                stat.status = 'approved'  # DG or admins
                stat.approved_by_dg = user
                stat.approved_at_dg = timezone.now()
        stat.reviewed_by = user
        stat.save()

        return Response({'message': f"Statistic {stat.status} successfully.", 'status': stat.status}, status=status.HTTP_200_OK)
    except Statistic.DoesNotExist:
        return Response({'error': 'Statistic not found.'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def my_statistics(request):
    """Return all statistics uploaded by the current user"""
    try:
      user = request.user
      print(f"DEBUG: my_statistics called by user: {user.username} (ID: {user.id})")
      
      user_role = getattr(getattr(user, 'profile', None), 'role', '')
      print(f"DEBUG: User role: '{user_role}'")
      
      allowed_roles = ['statistics_officer', 'head_of_division', 'head_of_department']
      # Allow admins and optionally users without a role (for testing)
      if not (user.is_staff or user.is_superuser or user_role in allowed_roles or user_role == ''):
          return Response({'error': f'Access denied. Only statistics-related roles can view statistics. Your role: {user_role}'},
                          status=status.HTTP_403_FORBIDDEN)

      stats = Statistic.objects.filter(uploaded_by=user).order_by('-upload_date')
      print(f"DEBUG: Found {stats.count()} statistics for user {user.username}")
      
      data = []
      for s in stats:
          print(f"DEBUG: Processing statistic ID {s.id}, uploaded_by: {s.uploaded_by.username}")
          file_name = s.file.name if s.file else ''
          upload_date = s.upload_date.isoformat() if s.upload_date else ''
          data.append({
              'id': s.id,
              'file': file_name,
              'status': s.status,
              'uploaded_at': upload_date,
              'created_at': upload_date,
              'uploader_name': s.uploader_name,
              'reviewed_by': s.reviewed_by.username if s.reviewed_by else None
          })
      
      print(f"DEBUG: Returning {len(data)} statistics: {data}")
      return Response(data, status=status.HTTP_200_OK)
    except Exception as e:
      print(f"DEBUG: Error in my_statistics: {str(e)}")
      return Response({'error': f'Internal server error: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def approved_plans(request):
    """Return all approved plans (visible to heads and DG/admin)."""
    user = request.user
    user_role = getattr(getattr(user, 'profile', None), 'role', '')
    if not (user.is_staff or user.is_superuser or user_role in ['head_of_division','head_of_department','director_general']):
        return Response({'error':'Access denied.'}, status=status.HTTP_403_FORBIDDEN)
    plans = Plan.objects.filter(status='approved').order_by('-upload_date')
    data = []
    for p in plans:
        data.append({
            'id': p.id,
            'file': p.file.name if p.file else '',
            'status': p.status,
            'uploaded_at': p.upload_date.isoformat() if p.upload_date else '',
            'uploader_name': p.uploader_name,
            'reviewed_by': p.reviewed_by.username if p.reviewed_by else None
        })
    return Response(data, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def approved_statistics(request):
    """Return all approved statistics (visible to heads and DG/admin)."""
    user = request.user
    user_role = getattr(getattr(user, 'profile', None), 'role', '')
    if not (user.is_staff or user.is_superuser or user_role in ['head_of_division','head_of_department','director_general']):
        return Response({'error':'Access denied.'}, status=status.HTTP_403_FORBIDDEN)
    stats = Statistic.objects.filter(status='approved').order_by('-upload_date')
    data = []
    for s in stats:
        data.append({
            'id': s.id,
            'file': s.file.name if s.file else '',
            'status': s.status,
            'uploaded_at': s.upload_date.isoformat() if s.upload_date else '',
            'uploader_name': s.uploader_name,
            'reviewed_by': s.reviewed_by.username if s.reviewed_by else None
        })
    return Response(data, status=status.HTTP_200_OK)

@api_view(['GET','PUT'])
@permission_classes([IsAuthenticated])
def budget_view(request):
    """Get or update current budget (single row approach)."""
    # single budget row (create if missing)
    budget, _ = Budget.objects.get_or_create(id=1)
    if request.method == 'GET':
        return Response({
            'received_budget': str(budget.received_budget),
            'used_budget': str(budget.used_budget),
            'projection': str(budget.projection),
            'updated_at': budget.updated_at,
            'updated_by': budget.updated_by.username if budget.updated_by else None
        }, status=status.HTTP_200_OK)
    # PUT: only heads, DG or admin can update
    user = request.user
    role = getattr(getattr(user,'profile',None),'role','')
    if not (user.is_staff or user.is_superuser or role in ['head_of_division','head_of_department','director_general']):
        return Response({'error':'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
    fields = ['received_budget','used_budget','projection']
    changed = []
    for f in fields:
        if f in request.data:
            try:
                new_val = Decimal(str(request.data.get(f)))
            except Exception:
                return Response({'error':f'Invalid value for {f}'}, status=status.HTTP_400_BAD_REQUEST)
            old_val = getattr(budget,f)
            if new_val != old_val:
                BudgetHistory.objects.create(budget=budget, field_name=f, old_value=old_val, new_value=new_val, changed_by=user)
                setattr(budget,f,new_val)
                changed.append(f)
    if changed:
        budget.updated_by = user
        budget.save()
    return Response({'message':'Budget updated','changed_fields':changed,'budget':{
        'received_budget': str(budget.received_budget),
        'used_budget': str(budget.used_budget),
        'projection': str(budget.projection),
        'updated_at': budget.updated_at,
        'updated_by': budget.updated_by.username if budget.updated_by else None
    }}, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def budget_history(request):
    """Return budget change history (latest first)."""
    user = request.user
    role = getattr(getattr(user,'profile',None),'role','')
    if not (user.is_staff or user.is_superuser or role in ['head_of_division','head_of_department','director_general']):
        return Response({'error':'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
    history = BudgetHistory.objects.select_related('changed_by').order_by('-changed_at')[:200]
    data = []
    for h in history:
        data.append({
            'field_name': h.field_name,
            'old_value': str(h.old_value),
            'new_value': str(h.new_value),
            'changed_at': h.changed_at,
            'changed_by': h.changed_by.username if h.changed_by else None
        })
    return Response(data, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def hod_processed_plans(request):
    """Plans already processed by Head of Department (reviewed forwarded to DG, and rejected)."""
    user = request.user
    role = getattr(getattr(user, 'profile', None), 'role', '')
    if not (user.is_staff or user.is_superuser or role == 'head_of_department'):
        return Response({'error': 'Access denied.'}, status=status.HTTP_403_FORBIDDEN)

    reviewed = Plan.objects.filter(status='reviewed', reviewed_by__profile__role='head_of_department').order_by('-upload_date')
    rejected = Plan.objects.filter(status='rejected', reviewed_by=user).order_by('-upload_date')

    def serialize(plans_qs):
        out = []
        for p in plans_qs:
            out.append({
                'id': p.id,
                'file': p.file.name if p.file else '',
                'status': p.status,
                'uploaded_at': p.upload_date.isoformat() if p.upload_date else '',
                'uploader_name': p.uploader_name,
                'reviewed_by': p.reviewed_by.username if p.reviewed_by else None
            })
        return out

    return Response({
        'reviewed_plans': serialize(reviewed),
        'rejected_plans': serialize(rejected)
    }, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def pending_statistics(request):
    """Get pending statistics for heads and DG based on role"""
    user = request.user
    user_role = getattr(getattr(user, 'profile', None), 'role', '')

    print(f"DEBUG: pending_statistics called by user: {user.username} (ID: {user.id}), role: '{user_role}'")

    if user_role == 'head_of_department':
        # HoDept sees stats approved by HoD (reviewed)
        stats = (Statistic.objects
                 .filter(status='reviewed', reviewed_by__profile__role='head_of_division')
                 .exclude(file__isnull=True).exclude(file=''))
    elif user_role == 'director_general' or user.is_staff or user.is_superuser:
        # DG sees stats approved by HoDept (reviewed)
        stats = (Statistic.objects
                 .filter(status='reviewed', reviewed_by__profile__role='head_of_department')
                 .exclude(file__isnull=True).exclude(file=''))
    elif user_role == 'head_of_division':
        # HoD sees pending stats
        stats = (Statistic.objects
                 .filter(status='pending')
                 .exclude(file__isnull=True).exclude(file=''))
    elif user_role == 'statistics_officer':
        # Statistics officers should only see their own pending statistics
        stats = (Statistic.objects
                 .filter(status='pending', uploaded_by=user)
                 .exclude(file__isnull=True).exclude(file=''))
    else:
        # For testing purposes, allow access to pending stats (you can remove this later)
        stats = (Statistic.objects
                 .filter(status='pending')
                 .exclude(file__isnull=True).exclude(file=''))

    print(f"DEBUG: Found {stats.count()} pending statistics for role '{user_role}'")
    for s in stats:
        print(f"DEBUG: Pending stat ID {s.id}, uploaded_by: {s.uploaded_by.username}, status: {s.status}, file: {s.file}")

    serializer = StatisticSerializer(stats, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

# Helper for unified file streaming
def _stream_model_file(instance, file_attr, label, obj_id):
    f = getattr(instance, file_attr, None)
    if not f:
        return Response({'error': f'{label} file field empty', f'{label}_id': obj_id}, status=status.HTTP_404_NOT_FOUND)
    rel_name = f.name
    abs_path = f.path  # Get absolute path from storage
    if not os.path.exists(abs_path):
        return Response({
            'error': 'File not found on disk',
            'detail': 'The file path does not exist. Check MEDIA_ROOT or re-upload the file.',
            'relative_name': rel_name,
            'absolute_path': abs_path,
            f'{label}_id': obj_id,
            'action': 'reupload'
        }, status=status.HTTP_410_GONE)
    try:
        fh = open(abs_path, 'rb')  # Open directly for streaming
    except Exception as e:
        return Response({
            'error': f'Error opening file: {str(e)}',
            'relative_name': rel_name,
            'absolute_path': abs_path,
            f'{label}_id': obj_id
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    content_type = mimetypes.guess_type(rel_name)[0] or 'application/octet-stream'
    resp = FileResponse(fh, content_type=content_type)
    filename = os.path.basename(rel_name)
    resp['Content-Disposition'] = f'attachment; filename="{smart_str(filename)}"'
    resp['X-File-Name'] = smart_str(filename)
    resp['X-File-Type'] = content_type
    return resp

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_plan(request, plan_id):
    try:
        plan = Plan.objects.filter(id=plan_id).first()
        if not plan:
            return Response({'error': 'Plan not found', 'plan_id': plan_id}, status=status.HTTP_404_NOT_FOUND)
        role = getattr(getattr(request.user, 'profile', None), 'role', '')
        if not (request.user.is_staff or request.user.is_superuser or role in [
            'planning_officer','head_of_division','head_of_department','director_general','statistics_officer']):
            return Response({'error': 'Permission denied', 'plan_id': plan_id}, status=status.HTTP_403_FORBIDDEN)
        return _stream_model_file(plan, 'file', 'plan', plan_id)
    except Exception as e:
        return Response({'error': str(e), 'plan_id': plan_id}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_statistic(request, stat_id):
    try:
        stat = Statistic.objects.filter(id=stat_id).first()
        if not stat:
            return Response({'error': 'Statistic not found', 'stat_id': stat_id}, status=status.HTTP_404_NOT_FOUND)
        role = getattr(getattr(request.user, 'profile', None), 'role', '')
        if not (request.user.is_staff or request.user.is_superuser or role in [
            'statistics_officer','head_of_division','head_of_department','director_general','planning_officer']):
            return Response({'error': 'Permission denied', 'stat_id': stat_id}, status=status.HTTP_403_FORBIDDEN)
        return _stream_model_file(stat, 'file', 'statistic', stat_id)
    except Exception as e:
        return Response({'error': str(e), 'stat_id': stat_id}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_pending_statistics(request):
    user = request.user
    if user.role == 'head_of_division':
        # HoD sees stats uploaded by stats officers (pending)
        statistics = Statistic.objects.filter(status='pending')
    elif user.role == 'head_of_department':
        # HoDept sees stats approved by HoD (reviewed)
        statistics = Statistic.objects.filter(status='reviewed')
    elif user.role == 'director_general':
        # DG sees stats approved by HoDept (approved)
        statistics = Statistic.objects.filter(status='approved')
    else:
        statistics = Statistic.objects.none()  # No access for other roles
    
    serializer = StatisticSerializer(statistics, many=True)
    return Response(serializer.data)
