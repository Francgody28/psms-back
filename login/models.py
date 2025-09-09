from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class UserProfile(models.Model):
    """Extended user profile information"""
    ROLE_CHOICES = [
        ('planning_officer', 'Planning Officer'),
        ('statistics_officer', 'Statistics Officer'),
        ('head_of_division', 'Head of Division'),
        ('head_of_department', 'Head of Department'),
        ('director_general', 'Director General'),  # added
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    department = models.CharField(max_length=100, blank=True, null=True)
    employee_id = models.CharField(max_length=50, unique=True, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    role = models.CharField(max_length=32, default='planning_officer', choices=ROLE_CHOICES)

    def __str__(self):
        return f"{self.user.username}'s Profile"
    
    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"

class LoginHistory(models.Model):
    """Track user login history"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='login_history')
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    session_key = models.CharField(max_length=40, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.login_time}"
    
    class Meta:
        verbose_name = "Login History"
        verbose_name_plural = "Login Histories"
        ordering = ['-login_time']

class UserRole(models.Model):
    """Define user roles and permissions"""
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('manager', 'Manager'),
        ('employee', 'Employee'),
        ('viewer', 'Viewer'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='role')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='employee')
    permissions = models.JSONField(default=dict, blank=True)
    assigned_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_roles')
    assigned_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.get_role_display()}"
    
    class Meta:
        verbose_name = "User Role"
        verbose_name_plural = "User Roles"

class Department(models.Model):
    """Company departments"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    manager = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='managed_departments')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = "Department"
        verbose_name_plural = "Departments"

class SystemSettings(models.Model):
    """System-wide settings"""
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    description = models.TextField(blank=True, null=True)
    data_type = models.CharField(max_length=20, choices=[
        ('string', 'String'),
        ('integer', 'Integer'),
        ('boolean', 'Boolean'),
        ('json', 'JSON'),
    ], default='string')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.key}: {self.value}"
    
    class Meta:
        verbose_name = "System Setting"
        verbose_name_plural = "System Settings"

class UserActivity(models.Model):
    """Track user activities in the system"""
    ACTION_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('create', 'Create'),
        ('read', 'Read'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('export', 'Export'),
        ('import', 'Import'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='activities')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    model_name = models.CharField(max_length=100, blank=True, null=True)
    object_id = models.PositiveIntegerField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.timestamp}"
    
    class Meta:
        verbose_name = "User Activity"
        verbose_name_plural = "User Activities"
        ordering = ['-timestamp']

class UserSession(models.Model):
    """Track active user sessions"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.session_key[:8]}..."
    
    class Meta:
        verbose_name = "User Session"
        verbose_name_plural = "User Sessions"
        ordering = ['-last_activity']

class Plan(models.Model):
    file = models.FileField(upload_to='plans/')
    upload_date = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    uploader_name = models.CharField(max_length=255)
    # include full lifecycle
    status = models.CharField(
        max_length=32,
        default='pending',
        choices=[('pending', 'Pending'), ('reviewed', 'Reviewed'), ('approved', 'Approved'), ('rejected', 'Rejected')]
    )
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_plans')

    def __str__(self):
        return f"{self.file.name} uploaded by {self.uploader_name}"

# New: statistics uploads with same lifecycle as plans
class Statistic(models.Model):
    file = models.FileField(upload_to='statistics/')
    upload_date = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    uploader_name = models.CharField(max_length=255)
    status = models.CharField(
        max_length=32,
        default='pending',
        choices=[('pending', 'Pending'), ('reviewed', 'Reviewed'), ('approved', 'Approved'), ('rejected', 'Rejected')]
    )
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_statistics')

    def __str__(self):
        return f"{self.file.name} uploaded by {self.uploader_name}"

# NEW: Budget models
class Budget(models.Model):
    received_budget = models.DecimalField(max_digits=18, decimal_places=2, default=0)
    used_budget = models.DecimalField(max_digits=18, decimal_places=2, default=0)
    projection = models.DecimalField(max_digits=18, decimal_places=2, default=0)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='updated_budgets')

    def __str__(self):
        return f"Budget (Received: {self.received_budget}, Used: {self.used_budget}, Projection: {self.projection})"

    class Meta:
        verbose_name = 'Budget'
        verbose_name_plural = 'Budgets'

class BudgetHistory(models.Model):
    budget = models.ForeignKey(Budget, on_delete=models.CASCADE, related_name='history')
    field_name = models.CharField(max_length=32)
    old_value = models.DecimalField(max_digits=18, decimal_places=2)
    new_value = models.DecimalField(max_digits=18, decimal_places=2)
    changed_at = models.DateTimeField(auto_now_add=True)
    changed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"{self.field_name}: {self.old_value} -> {self.new_value} at {self.changed_at}"

    class Meta:
        verbose_name = 'Budget History'
        verbose_name_plural = 'Budget History'
        ordering = ['-changed_at']
