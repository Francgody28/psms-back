from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .serializers import LoginSerializer, UserRegistrationSerializer, UserSerializer, AdminDashboardSerializer
from django.db.models import Q

@api_view(['POST'])
@permission_classes([AllowAny])
def user_login(request):
    """Login endpoint for both admin and regular users"""
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        # Authenticate user
        user = authenticate(username=username, password=password)
        
        if user and user.is_active:
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            
            # Determine user role and redirect accordingly
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_admin': user.is_staff or user.is_superuser,
                'is_active': user.is_active,
                'date_joined': user.date_joined
            }
            
            return Response({
                'message': 'Login successful',
                'token': token.key,
                'user': user_data,
                'dashboard_url': '/admin-dashboard' if user.is_staff or user.is_superuser else '/user-dashboard'
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
    
    user_data = {
        'user_info': {
            'id': request.user.id,
            'username': request.user.username,
            'email': request.user.email,
            'first_name': request.user.first_name,
            'last_name': request.user.last_name,
            'date_joined': request.user.date_joined,
        },
        'dashboard_type': 'user',
        'available_features': [
            'View Profile',
            'Update Profile',
            'View History',
            'Settings'
        ]
    }
    
    return Response(user_data, status=status.HTTP_200_OK)

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
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_active': user.is_active,
            'is_admin': user.is_staff or user.is_superuser,
            'date_joined': user.date_joined,
            'last_login': user.last_login
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
