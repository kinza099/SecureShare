from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from .forms import RegisterForm, LoginForm, ChangePasswordForm, ProfileForm
from .models import User, LoginHistory
from .services import get_client_ip, log_login_attempt
from monitoring.services import log_activity, evaluate_failed_logins, trigger_security_alert
from notifications.services import create_notification

def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:user_dashboard')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()

            ip = get_client_ip(request)
            log_activity(
                request=request,
                user=user,
                event_type='REGISTRATION',
                resource_id=user.username,
                description=f"New user account registered: {user.username} ({user.email})",
                status='SUCCESS',
                ip_address=ip
            )

            create_notification(
                user=user,
                title="Welcome to Secure File Sharing",
                message="Your account has been secured with Argon2id password hashing and RBAC.",
                notification_type='GENERAL'
            )

            messages.success(request, "Registration successful! You can now log in.")
            return redirect('accounts:login')
    else:
        form = RegisterForm()

    return render(request, 'accounts/register.html', {'form': form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:user_dashboard')

    ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username_or_email = form.cleaned_data['username_or_email'].strip()
            password = form.cleaned_data['password']
            remember_me = form.cleaned_data.get('remember_me', False)

            # Resolve user by username or email
            target_user = None
            if '@' in username_or_email:
                target_user = User.objects.filter(email__iexact=username_or_email).first()
            else:
                target_user = User.objects.filter(username__iexact=username_or_email).first()

            # Check if user exists
            if not target_user:
                log_login_attempt(None, username_or_email, ip, user_agent, 'FAILED_USER')
                log_activity(request=request, event_type='LOGIN_FAILED', resource_id=username_or_email,
                             description=f"Login attempt for non-existent user: {username_or_email}", status='FAILURE', ip_address=ip)
                evaluate_failed_logins(username_or_email, ip)
                messages.error(request, "Invalid username or password.")
                return render(request, 'accounts/login.html', {'form': form})

            # Check account suspension
            if target_user.is_suspended:
                log_login_attempt(target_user, username_or_email, ip, user_agent, 'SUSPENDED')
                log_activity(request=request, user=target_user, event_type='LOGIN_FAILED', resource_id=target_user.username,
                             description="Login rejected: account is suspended.", status='BLOCKED', ip_address=ip)
                messages.error(request, "Your account has been deactivated by the system administrator.")
                return render(request, 'accounts/login.html', {'form': form})

            # Check lockout
            if target_user.is_locked():
                log_login_attempt(target_user, username_or_email, ip, user_agent, 'LOCKED_OUT')
                log_activity(request=request, user=target_user, event_type='LOGIN_FAILED', resource_id=target_user.username,
                             description="Login rejected: account temporarily locked.", status='BLOCKED', ip_address=ip)
                trigger_security_alert(
                    rule_name="Access Attempt on Locked Account",
                    description=f"IP {ip} attempted login on locked account {target_user.username}",
                    severity='HIGH',
                    user=target_user,
                    ip_address=ip
                )
                remaining = int((target_user.lockout_until - timezone.now()).total_seconds() / 60) + 1
                messages.error(request, f"Account is temporarily locked due to multiple failed logins. Try again in {remaining} minute(s).")
                return render(request, 'accounts/login.html', {'form': form})

            # Authenticate credentials
            user = authenticate(request, username=target_user.username, password=password)

            if user is not None:
                # Login Success
                user.reset_failed_attempts()
                user.last_login_ip = ip
                user.save(update_fields=['last_login_ip'])

                login(request, user)
                if not remember_me:
                    request.session.set_expiry(0)  # Browser close

                log_login_attempt(user, user.username, ip, user_agent, 'SUCCESS')
                log_activity(request=request, user=user, event_type='LOGIN_SUCCESS', resource_id=user.username,
                             description=f"User logged in successfully from {ip}", status='SUCCESS', ip_address=ip)

                messages.success(request, f"Welcome back, {user.full_name or user.username}!")
                next_url = request.GET.get('next')
                if next_url and next_url.startswith('/'):
                    return redirect(next_url)
                return redirect('dashboard:user_dashboard')
            else:
                # Password incorrect
                target_user.increment_failed_attempts()
                log_login_attempt(target_user, target_user.username, ip, user_agent, 'FAILED_PASSWORD')
                log_activity(request=request, user=target_user, event_type='LOGIN_FAILED', resource_id=target_user.username,
                             description=f"Incorrect password attempt for {target_user.username}", status='FAILURE', ip_address=ip)
                evaluate_failed_logins(target_user.username, ip)

                if target_user.is_locked():
                    messages.error(request, "Too many failed attempts. Your account has been locked for 15 minutes.")
                else:
                    remaining_attempts = 5 - target_user.failed_login_attempts
                    messages.error(request, f"Invalid username or password. {remaining_attempts} attempt(s) remaining before temporary lockout.")
    else:
        form = LoginForm()

    return render(request, 'accounts/login.html', {'form': form})


@login_required
def logout_view(request):
    ip = get_client_ip(request)
    log_activity(
        request=request,
        user=request.user,
        event_type='LOGOUT',
        resource_id=request.user.username,
        description=f"User logged out from {ip}",
        status='SUCCESS',
        ip_address=ip
    )
    logout(request)
    messages.info(request, "You have been securely logged out.")
    return redirect('accounts:login')


@login_required
def profile_view(request):
    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Profile details updated successfully.")
            return redirect('accounts:profile')
    else:
        form = ProfileForm(instance=request.user)

    return render(request, 'accounts/profile.html', {'form': form})


@login_required
def change_password_view(request):
    if request.method == 'POST':
        form = ChangePasswordForm(request.POST)
        if form.is_valid():
            if not request.user.check_password(form.cleaned_data['current_password']):
                form.add_error('current_password', "Current password is incorrect.")
            else:
                request.user.set_password(form.cleaned_data['new_password'])
                request.user.save()
                update_session_auth_hash(request, request.user)
                log_activity(
                    request=request,
                    user=request.user,
                    event_type='PASSWORD_CHANGE',
                    resource_id=request.user.username,
                    description="Password successfully changed and updated with Argon2id hash",
                    status='SUCCESS'
                )
                messages.success(request, "Password changed successfully!")
                return redirect('accounts:profile')
    else:
        form = ChangePasswordForm()

    return render(request, 'accounts/change_password.html', {'form': form})


@login_required
def login_history_view(request):
    history = LoginHistory.objects.filter(user=request.user).order_by('-timestamp')[:50]
    return render(request, 'accounts/login_history.html', {'history': history})
