import base64
import mimetypes
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404, JsonResponse
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.contrib.auth.hashers import check_password
from django.db.models import F, Q
from django.utils import timezone

from .models import FileShare, SharingLink, FileDownloadAudit
from .forms import DirectShareForm, CreateSharingLinkForm, AccessLinkForm
from .services import (
    create_user_share,
    create_secure_sharing_link,
    generate_qr_code_png
)
from filemanager.models import FileRecord
from filemanager.services import retrieve_and_decrypt_file
from encryption.integrity import calculate_bytes_sha256
from encryption.services import DecryptionIntegrityError
from monitoring.services import log_activity, trigger_security_alert
from notifications.services import create_notification
from accounts.context_processors import get_lan_ip

@login_required
def share_file_view(request, pk):
    file_record = get_object_or_404(FileRecord, pk=pk, owner=request.user, is_deleted=False)

    if request.method == 'POST':
        form = DirectShareForm(request.POST)
        if form.is_valid():
            recipient = form.cleaned_data['recipient_identifier']
            permission = form.cleaned_data['permission']
            message = form.cleaned_data.get('message', '')
            exp_hours = form.cleaned_data.get('expiration_hours')

            try:
                create_user_share(
                    sender=request.user,
                    file_record=file_record,
                    recipient=recipient,
                    permission=permission,
                    message=message,
                    expiration_hours=exp_hours,
                    request=request
                )
                messages.success(request, f"File successfully shared with {recipient.username}!")
                return redirect('sharing:sharing_links')
            except Exception as e:
                messages.error(request, str(e))
    else:
        form = DirectShareForm()

    existing_shares = FileShare.objects.filter(file_record=file_record, is_revoked=False)
    return render(request, 'sharing/share_file.html', {
        'file': file_record,
        'form': form,
        'existing_shares': existing_shares
    })


@login_required
def revoke_share_view(request, pk):
    share = get_object_or_404(FileShare, pk=pk, sender=request.user)
    if request.method == 'POST':
        share.is_revoked = True
        share.save(update_fields=['is_revoked'])

        log_activity(
            request=request,
            user=request.user,
            event_type='SHARE_REVOKE',
            resource_id=str(share.file_record.id),
            description=f"Revoked share access to '{share.file_record.display_name}' for user '{share.recipient.username}'",
            status='SUCCESS'
        )

        # Notify the recipient that their access has been revoked
        create_notification(
            user=share.recipient,
            title="File Access Revoked",
            message=f"Your access to file '{share.file_record.display_name}' (shared by {request.user.username}) has been revoked.",
            notification_type='SECURITY_ALERT',
            link_url='/sharing/received/'
        )

        messages.success(request, f"Access for @{share.recipient.username} has been revoked. They can no longer access this file.")
    return redirect('sharing:sharing_links')


@login_required
def create_link_view(request, pk):
    file_record = get_object_or_404(FileRecord, pk=pk, owner=request.user, is_deleted=False)

    if request.method == 'POST':
        form = CreateSharingLinkForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data.get('password') if form.cleaned_data.get('enable_password') else None
            exp_hours = form.cleaned_data.get('expiration_hours')
            max_dl = form.cleaned_data.get('max_downloads')

            link, raw_token = create_secure_sharing_link(
                creator=request.user,
                file_record=file_record,
                password=password,
                expiration_hours=exp_hours,
                max_downloads=max_dl,
                request=request
            )

            # Store the token temporarily in session so the user can copy their generated URL once
            request.session[f'new_link_token_{link.id}'] = raw_token
            messages.success(request, "Secure sharing link created successfully!")
            return redirect('sharing:sharing_links')
    else:
        form = CreateSharingLinkForm()

    return render(request, 'sharing/create_link.html', {'file': file_record, 'form': form})


@login_required
def sharing_links_list_view(request):
    """
    List all sharing links and direct user shares managed by the current user.
    Shows both active and revoked/expired shares for full history.
    """
    links = SharingLink.objects.filter(creator=request.user).order_by('-created_at')
    # Show ALL direct shares (active + revoked) so sender always sees history
    direct_shares = FileShare.objects.filter(
        sender=request.user
    ).select_related('file_record', 'recipient').order_by('-created_at')
    files = FileRecord.objects.filter(owner=request.user, is_deleted=False)

    host_ip = get_lan_ip()
    port = request.get_port() or '8000'
    base_url = f"{request.scheme}://{host_ip}:{port}"

    # Prepare links with full URLs
    link_items = []
    for link in links:
        raw_token = request.session.get(f'new_link_token_{link.id}', '')
        full_url = f"{base_url}/sharing/access/{raw_token}/" if raw_token else f"{base_url}/sharing/access/[TOKEN_ACTIVE]/"
        link_items.append({
            'link': link,
            'raw_token': raw_token,
            'full_url': full_url,
            'is_valid': link.is_valid()[0],
            'status_msg': link.is_valid()[1],
        })

    return render(request, 'sharing/sharing_links.html', {
        'link_items': link_items,
        'direct_shares': direct_shares,
        'files': files,
        'base_url': base_url,
    })


@login_required
def revoke_link_view(request, pk):
    link = get_object_or_404(SharingLink, pk=pk, creator=request.user)
    if request.method == 'POST':
        link.is_revoked = True
        link.save(update_fields=['is_revoked'])

        log_activity(
            request=request,
            user=request.user,
            event_type='LINK_REVOKE',
            resource_id=str(link.file_record.id),
            description=f"Revoked public link for '{link.file_record.display_name}'",
            status='SUCCESS'
        )
        messages.success(request, "Sharing link was revoked.")
    return redirect('sharing:sharing_links')


def qr_code_view(request, token):
    """
    Generate QR code containing the full LAN-accessible link URL for mobile scanning.
    """
    host_ip = get_lan_ip()
    port = request.get_port() or '8000'
    full_url = f"{request.scheme}://{host_ip}:{port}/sharing/access/{token}/"

    png_bytes = generate_qr_code_png(full_url)
    return HttpResponse(png_bytes, content_type='image/png')


def access_link_view(request, token):
    """
    Public access point for sharing link.
    Validates token hash, expiration, revocation, password protection, and download limits.
    """
    token_hash = calculate_bytes_sha256(token.encode('ascii'))
    link = SharingLink.objects.filter(token_hash=token_hash).first()

    if not link:
        log_activity(
            request=request,
            event_type='UNAUTHORIZED_ACCESS',
            resource_id=token[:8] + '...',
            description="Attempted access to invalid sharing token",
            status='BLOCKED'
        )
        return render(request, 'sharing/access_link_error.html', {
            'error_title': 'Invalid Link',
            'error_message': 'This sharing link does not exist or is invalid.'
        }, status=404)

    is_valid, reason = link.is_valid()
    if not is_valid:
        log_activity(
            request=request,
            event_type='UNAUTHORIZED_ACCESS',
            resource_id=str(link.file_record.id),
            description=f"Attempted access to inactive sharing link: {reason}",
            status='BLOCKED'
        )
        trigger_security_alert(
            rule_name="Access Attempt on Inactive Sharing Link",
            description=f"Client IP {request.client_ip if hasattr(request, 'client_ip') else 'unknown'} attempted access on link: {reason}",
            severity='LOW',
            request=request
        )
        return render(request, 'sharing/access_link_error.html', {
            'error_title': 'Link Unavailable',
            'error_message': reason
        }, status=403)

    # Password check
    password_authenticated = False
    password_error = None

    if link.is_password_protected:
        session_key = f'link_auth_{link.id}'
        if request.session.get(session_key) == True:
            password_authenticated = True
        elif request.method == 'POST' and 'verify_password' in request.POST:
            form = AccessLinkForm(request.POST)
            if form.is_valid():
                input_pw = form.cleaned_data['password']
                if check_password(input_pw, link.password_hash):
                    request.session[session_key] = True
                    password_authenticated = True
                else:
                    password_error = "Incorrect password. Access denied."
                    log_activity(
                        request=request,
                        event_type='UNAUTHORIZED_ACCESS',
                        resource_id=str(link.file_record.id),
                        description="Failed password verification on protected sharing link",
                        status='FAILURE'
                    )
        else:
            form = AccessLinkForm()
            return render(request, 'sharing/access_link.html', {
                'link': link,
                'file': link.file_record,
                'requires_password': True,
                'form': form,
                'token': token,
            })

    # Download action
    if request.method == 'POST' and 'download_file' in request.POST:
        # Atomic increment download count
        SharingLink.objects.filter(pk=link.pk).update(download_count=F('download_count') + 1)
        link.refresh_from_db()

        try:
            plaintext = retrieve_and_decrypt_file(link.file_record, request=request)

            # Audit record
            FileDownloadAudit.objects.create(
                file_record=link.file_record,
                sharing_link=link,
                user=request.user if request.user.is_authenticated else None,
                download_type='SHARING_LINK',
                ip_address=request.client_ip if hasattr(request, 'client_ip') else '127.0.0.1',
                status='SUCCESS'
            )

            # Notify creator
            create_notification(
                user=link.creator,
                title="Shared File Downloaded",
                message=f"Someone downloaded your file '{link.file_record.display_name}' via sharing link (Download #{link.download_count}).",
                notification_type='FILE_DOWNLOADED',
                link_url=f"/files/details/{link.file_record.id}/"
            )

            log_activity(
                request=request,
                user=request.user if request.user.is_authenticated else None,
                event_type='LINK_DOWNLOAD',
                resource_id=str(link.file_record.id),
                description=f"Downloaded '{link.file_record.display_name}' via sharing link (#{link.download_count})",
                status='SUCCESS'
            )

            mime_type, _ = mimetypes.guess_type(link.file_record.original_filename)
            if not mime_type:
                mime_type = 'application/octet-stream'

            response = HttpResponse(plaintext, content_type=mime_type)
            response['Content-Disposition'] = f'attachment; filename="{link.file_record.original_filename}"'
            response['X-Content-Type-Options'] = 'nosniff'
            return response

        except DecryptionIntegrityError as e:
            return render(request, 'sharing/access_link_error.html', {
                'error_title': 'Decryption Integrity Error',
                'error_message': str(e)
            }, status=500)

    return render(request, 'sharing/access_link.html', {
        'link': link,
        'file': link.file_record,
        'requires_password': False,
        'password_error': password_error,
        'token': token,
    })


@login_required
def received_files_view(request):
    """
    List of files shared WITH the current user (active, non-revoked, non-expired).
    When a sender revokes access, is_revoked=True and this view filters it out automatically.
    """
    now = timezone.now()
    shares = FileShare.objects.filter(
        recipient=request.user,
        is_revoked=False,
        file_record__is_deleted=False
    ).filter(
        # Only non-expired shares (expires_at=None means never expires)
        Q(expires_at__isnull=True) | Q(expires_at__gt=now)    ).select_related('file_record', 'sender').order_by('-created_at')

    return render(request, 'sharing/received_files.html', {'shares': shares})
