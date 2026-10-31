import mimetypes
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404, JsonResponse
from django.contrib import messages
from django.core.exceptions import PermissionDenied

from .models import FileRecord, FileVersion
from .forms import FileUploadForm, FileVersionUploadForm, FileRenameForm
from .services import (
    process_file_upload,
    process_new_version,
    retrieve_and_decrypt_file,
    check_file_duplicate_for_user
)
from encryption.services import DecryptionIntegrityError, delete_encrypted_file
from encryption.integrity import calculate_bytes_sha256
from sharing.models import FileDownloadAudit, FileShare
from monitoring.services import log_activity, trigger_security_alert

@login_required
def upload_view(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.cleaned_data['file']
            display_name = form.cleaned_data.get('display_name')
            confirm_duplicate = request.POST.get('confirm_duplicate') == '1'

            file_bytes = uploaded_file.read()
            uploaded_file.seek(0)

            # Duplicate detection within user's account
            if not confirm_duplicate:
                duplicate = check_file_duplicate_for_user(request.user, file_bytes)
                if duplicate:
                    return render(request, 'filemanager/upload.html', {
                        'form': form,
                        'duplicate_warning': True,
                        'existing_file': duplicate,
                        'temp_display_name': display_name or uploaded_file.name,
                    })

            try:
                record = process_file_upload(request.user, uploaded_file, display_name, request=request)
                messages.success(request, f"File '{record.display_name}' successfully encrypted and uploaded!")
                return redirect('filemanager:my_files')
            except Exception as e:
                messages.error(request, f"Upload and encryption failed: {e}")
    else:
        form = FileUploadForm()

    return render(request, 'filemanager/upload.html', {'form': form})


@login_required
def my_files_view(request):
    query = request.GET.get('q', '').strip()
    files = FileRecord.objects.filter(owner=request.user, is_deleted=False)

    if query:
        files = files.filter(display_name__icontains=query)

    return render(request, 'filemanager/my_files.html', {'files': files, 'query': query})


@login_required
def file_details_view(request, pk):
    file_record = get_object_or_404(FileRecord, pk=pk, is_deleted=False)
    if file_record.owner != request.user and not request.user.is_admin:
        # Check if shared with user
        share = FileShare.objects.filter(file_record=file_record, recipient=request.user, is_revoked=False).first()
        if not share or not share.is_active():
            raise PermissionDenied("You do not have permission to view this file's details.")

    rename_form = FileRenameForm(instance=file_record)
    version_form = FileVersionUploadForm()
    versions = file_record.versions.all().order_by('-version_number')

    return render(request, 'filemanager/file_details.html', {
        'file': file_record,
        'rename_form': rename_form,
        'version_form': version_form,
        'versions': versions,
    })


@login_required
def download_file_view(request, pk):
    file_record = get_object_or_404(FileRecord, pk=pk, is_deleted=False)
    version_num = request.GET.get('version')
    if version_num:
        try:
            version_num = int(version_num)
        except ValueError:
            version_num = None

    # Permission check: owner or recipient with DOWNLOADER permission
    is_owner = (file_record.owner == request.user)
    has_download_perm = False

    if is_owner:
        has_download_perm = True
        download_type = 'OWNER'
    else:
        share = FileShare.objects.filter(file_record=file_record, recipient=request.user, is_revoked=False).first()
        if share and share.is_active() and share.permission == 'DOWNLOADER':
            has_download_perm = True
            download_type = 'SHARED_USER'

    if not has_download_perm:
        log_activity(
            request=request,
            user=request.user,
            event_type='UNAUTHORIZED_ACCESS',
            resource_id=str(file_record.id),
            description=f"Unauthorized download attempt for '{file_record.display_name}'",
            status='BLOCKED'
        )
        raise PermissionDenied("You do not have permission to download this file.")

    try:
        plaintext_bytes = retrieve_and_decrypt_file(
            file_record=file_record,
            version_number=version_num,
            request=request,
            audit_user=request.user
        )

        # Audit record
        FileDownloadAudit.objects.create(
            file_record=file_record,
            user=request.user,
            download_type=download_type,
            ip_address=request.client_ip if hasattr(request, 'client_ip') else '127.0.0.1',
            status='SUCCESS'
        )

        log_activity(
            request=request,
            user=request.user,
            event_type='FILE_DOWNLOAD',
            resource_id=str(file_record.id),
            description=f"Decrypted and downloaded '{file_record.display_name}' (v{version_num or file_record.current_version})",
            status='SUCCESS'
        )

        mime_type, _ = mimetypes.guess_type(file_record.original_filename)
        if not mime_type:
            mime_type = 'application/octet-stream'

        response = HttpResponse(plaintext_bytes, content_type=mime_type)
        response['Content-Disposition'] = f'attachment; filename="{file_record.original_filename}"'
        response['X-Content-Type-Options'] = 'nosniff'
        return response

    except DecryptionIntegrityError as e:
        messages.error(request, f"Security Violation: {e}")
        return redirect('filemanager:details', pk=file_record.id)


@login_required
def preview_file_view(request, pk):
    """
    Secure document preview for PDF, JPG, PNG, TXT.
    Decrypts in memory and streams with protective headers.
    """
    file_record = get_object_or_404(FileRecord, pk=pk, is_deleted=False)

    # Permission check: owner or recipient with VIEW permission
    is_owner = (file_record.owner == request.user)
    has_view_perm = is_owner

    if not is_owner:
        share = FileShare.objects.filter(file_record=file_record, recipient=request.user, is_revoked=False).first()
        if share and share.is_active():
            has_view_perm = True

    if not has_view_perm:
        raise PermissionDenied("You do not have permission to preview this document.")

    previewable_types = ['pdf', 'jpg', 'jpeg', 'png', 'txt']
    if file_record.file_type.lower() not in previewable_types:
        messages.info(request, f"Direct in-browser preview is not available for .{file_record.file_type} files. Please download to view.")
        return redirect('filemanager:details', pk=file_record.id)

    raw_stream = request.GET.get('raw') == '1'

    if raw_stream:
        # Stream the decrypted bytes directly for iframe / img tag
        try:
            plaintext = retrieve_and_decrypt_file(file_record, request=request, audit_user=request.user)
            mime_type, _ = mimetypes.guess_type(file_record.original_filename)
            if not mime_type:
                mime_type = 'text/plain' if file_record.file_type == 'txt' else 'application/octet-stream'

            response = HttpResponse(plaintext, content_type=mime_type)
            response['Content-Disposition'] = f'inline; filename="{file_record.original_filename}"'
            response['X-Content-Type-Options'] = 'nosniff'
            response['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline';"
            return response
        except DecryptionIntegrityError as e:
            raise Http404(str(e))

    # Render preview wrapper page
    return render(request, 'filemanager/preview.html', {
        'file': file_record,
        'preview_url': f"/files/preview/{file_record.id}/?raw=1",
        'is_text': file_record.file_type.lower() == 'txt',
        'is_image': file_record.file_type.lower() in ['jpg', 'jpeg', 'png'],
        'is_pdf': file_record.file_type.lower() == 'pdf',
    })


@login_required
def rename_file_view(request, pk):
    file_record = get_object_or_404(FileRecord, pk=pk, owner=request.user, is_deleted=False)
    if request.method == 'POST':
        form = FileRenameForm(request.POST, instance=file_record)
        if form.is_valid():
            form.save()
            messages.success(request, "Display name updated.")
    return redirect('filemanager:details', pk=file_record.id)


@login_required
def delete_file_view(request, pk):
    file_record = get_object_or_404(FileRecord, pk=pk, owner=request.user, is_deleted=False)
    if request.method == 'POST':
        file_record.is_deleted = True
        file_record.save(update_fields=['is_deleted'])

        # Remove physical encrypted storage file
        if hasattr(file_record, 'encryption_metadata'):
            delete_encrypted_file(file_record.encryption_metadata.stored_filename)

        log_activity(
            request=request,
            user=request.user,
            event_type='FILE_DELETE',
            resource_id=str(file_record.id),
            description=f"Deleted file '{file_record.display_name}'",
            status='SUCCESS'
        )
        messages.success(request, f"File '{file_record.display_name}' was deleted.")
        return redirect('filemanager:my_files')
    return redirect('filemanager:details', pk=file_record.id)


@login_required
def upload_version_view(request, pk):
    file_record = get_object_or_404(FileRecord, pk=pk, owner=request.user, is_deleted=False)
    if request.method == 'POST':
        form = FileVersionUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                version = process_new_version(
                    user=request.user,
                    file_record=file_record,
                    uploaded_file=form.cleaned_data['file'],
                    change_summary=form.cleaned_data.get('change_summary', ''),
                    request=request
                )
                messages.success(request, f"Version {version.version_number} uploaded and encrypted successfully!")
            except Exception as e:
                messages.error(request, f"Failed to upload new version: {e}")
        else:
            messages.error(request, "Invalid file for new version.")
    return redirect('filemanager:details', pk=file_record.id)


@login_required
def version_history_view(request, pk):
    file_record = get_object_or_404(FileRecord, pk=pk, owner=request.user, is_deleted=False)
    versions = file_record.versions.all().order_by('-version_number')
    return render(request, 'filemanager/version_history.html', {
        'file': file_record,
        'versions': versions
    })
