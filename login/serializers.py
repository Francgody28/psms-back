from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from .models import UserProfile  # If you have a profile model
from .models import Plan
from .models import Statistic  # new

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    role = serializers.CharField(required=True)  # Add this line
    
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'password', 'password_confirm', 'role']
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        role = validated_data.pop('role')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        # Save role to profile or custom user model
        UserProfile.objects.create(user=user, role=role)
        return user

class UserSerializer(serializers.ModelSerializer):
    is_admin = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 
                 'is_active', 'is_admin', 'date_joined', 'last_login']
        read_only_fields = ['id', 'date_joined', 'last_login', 'is_admin']
    
    def get_is_admin(self, obj):
        return obj.is_staff or obj.is_superuser

class AdminDashboardSerializer(serializers.Serializer):
    total_users = serializers.IntegerField()
    active_users = serializers.IntegerField()
    admin_users = serializers.IntegerField()
    recent_users = UserSerializer(many=True)

class PlanSerializer(serializers.ModelSerializer):
    approved_by_hod_username = serializers.CharField(source='approved_by_hod.username', read_only=True, required=False)
    approved_by_hod_dept_username = serializers.CharField(source='approved_by_hod_dept.username', read_only=True, required=False)
    approved_by_dg_username = serializers.CharField(source='approved_by_dg.username', read_only=True, required=False)
    
    class Meta:
        model = Plan
        fields = ['id', 'file', 'uploaded_by', 'uploader_name', 'status', 'reviewed_by', 'upload_date', 
                  'approved_by_hod', 'approved_at_hod', 'approved_by_hod_dept', 'approved_at_hod_dept', 
                  'approved_by_dg', 'approved_at_dg', 'approved_by_hod_username', 'approved_by_hod_dept_username', 'approved_by_dg_username']
        read_only_fields = ['id', 'upload_date', 'uploaded_by', 'uploader_name', 'status', 'reviewed_by']

class StatisticSerializer(serializers.ModelSerializer):
    approved_by_hod_username = serializers.CharField(source='approved_by_hod.username', read_only=True, required=False)
    approved_by_hod_dept_username = serializers.CharField(source='approved_by_hod_dept.username', read_only=True, required=False)
    approved_by_dg_username = serializers.CharField(source='approved_by_dg.username', read_only=True, required=False)
    class Meta:
        model = Statistic
        fields = ['id', 'file', 'uploaded_by', 'uploader_name', 'status', 'reviewed_by', 'upload_date', 
                  'approved_by_hod', 'approved_at_hod', 'approved_by_hod_dept', 'approved_at_hod_dept', 
                  'approved_by_dg', 'approved_at_dg', 'approved_by_hod_username', 'approved_by_hod_dept_username', 'approved_by_dg_username']
        read_only_fields = ['id', 'upload_date', 'uploaded_by', 'uploader_name', 'status', 'reviewed_by']
