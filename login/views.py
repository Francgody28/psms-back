from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .serializers import LoginSerializer, UserRegistrationSerializer, UserSerializer, AdminDashboardSerializer, PlanSerializer
from .models import Plan
from rest_framework.parsers import MultiPartParser, FormParser
from django.db.models import Q
from .models import Statistic
from .serializers import StatisticSerializer

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
       - head_of_department: approve => 'approved', reject => 'rejected'
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
            elif user_role == 'head_of_department' and not (user.is_staff or user.is_superuser):
                plan.status = 'reviewed'  # stays reviewed, next DG
            else:
                # DG or admins finalize approval
                plan.status = 'approved'
        
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
def upload_statistic(request):
    """Endpoint for statistics officer to upload a statistic document (Word/Excel)"""
    try:
        user = request.user
        # roles allowed to upload statistics
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
            elif user_role == 'head_of_department' and not (user.is_staff or user.is_superuser):
                stat.status = 'reviewed'  # to Director General
            else:
                stat.status = 'approved'  # DG or admins
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
      user_role = getattr(getattr(user, 'profile', None), 'role', '')
      allowed_roles = ['statistics_officer', 'head_of_division', 'head_of_department']
      # Allow admins and optionally users without a role (for testing)
      if not (user.is_staff or user.is_superuser or user_role in allowed_roles or user_role == ''):
          return Response({'error': f'Access denied. Only statistics-related roles can view statistics. Your role: {user_role}'},
                          status=status.HTTP_403_FORBIDDEN)

      stats = Statistic.objects.filter(uploaded_by=user).order_by('-upload_date')
      data = []
      for s in stats:
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
      return Response(data, status=status.HTTP_200_OK)
    except Exception as e:
      return Response({'error': f'Internal server error: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
