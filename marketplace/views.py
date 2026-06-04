from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.views import LoginView, LogoutView, PasswordChangeView
from django.contrib import messages
from django.views.generic import CreateView, UpdateView, DeleteView, DetailView, TemplateView
from django.urls import reverse_lazy, reverse
from django.db.models import Q

# Security & Email verification imports
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator

from .models import User, Listing, ItemImage, Report, ChatRoom, ChatMessage, Wishlist
from .forms import CustomUserCreationForm, ListingForm, CustomSetPasswordForm

# --- AUTHENTICATION & SECURITY PATCH (PHASE 3.5) ---

class SignupView(CreateView):
    """
    PHASE 3.5 SECURITY PATCH: Handles student registration with mandatory email verification.
    This view ensures that 1) Users are created as 'Inactive' and 2) A unique, 
    one-time-use secure token is sent via email for verification.
    """
    form_class = CustomUserCreationForm
    template_name = 'marketplace/signup.html'
    success_url = reverse_lazy('activation_sent')

    def form_valid(self, form):
        # 1. Save user but set as inactive to prevent unauthorized login before verification
        user = form.save(commit=False)
        user.is_active = False 
        user.save()

        # 2. Security: Generate a secure, one-time verification token and encoded UID
        current_site = get_current_site(self.request)
        subject = 'Activate Your Trollyfy Account'
        
        # We use urlsafe_base64_encode to securely pass the primary key in the URL
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        # default_token_generator creates a hash based on user state (timestamp, last login, etc.)
        token = default_token_generator.make_token(user)
        
        # Build the dynamic activation link pointing to our 'activate' route
        activation_link = f"http://{current_site.domain}{reverse('activate', kwargs={'uidb64': uid, 'token': token})}"

        # 3. Security Audit Note: Emails are sent via the backend configured in settings.py
        # In development, these are printed to the terminal console.
        message = f"Hi {user.username},\n\nPlease click the link below to verify your account and start trading on campus:\n\n{activation_link}"
        
        send_mail(
            subject,
            message,
            'noreply@trollyfy.com',
            [user.email],
            fail_silently=False,
        )
        
        return redirect('activation_sent')


def activate_account(request, uidb64, token):
    """
    PHASE 3.5 SECURITY PATCH: Verifies the email token and activates the student account.
    This logic prevents token spoofing and ensures only the intended recipient can activate.
    """
    try:
        # Decode the BASE64 User ID from the URL back to a primary key
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    # Security Verification: Use Django's internal state-based token generator
    if user is not None and default_token_generator.check_token(user, token):
        # Token is valid: Flip the 'is_active' switch to allow logins
        user.is_active = True
        user.save()
        messages.success(request, "Your account has been verified! You can now log in.")
        return redirect('login')
    else:
        # Security Note: If the token is invalid or already used, registration fails.
        return render(request, 'marketplace/activation_invalid.html')


# --- PREVIOUS VIEWS (INDEX, PROFILE, CRUD) ---

def index_view(request):
    listings = Listing.objects.filter(status='PUBLISHED').prefetch_related('images')
    query = request.GET.get('q')
    if query:
        listings = listings.filter(Q(title__icontains=query) | Q(description__icontains=query))
    category_filter = request.GET.get('category')
    if category_filter:
        listings = listings.filter(category=category_filter)
    
    # Dynamic Categories: Only show categories that actually have items
    used_category_codes = Listing.objects.values_list('category', flat=True).distinct()
    active_categories = [choice for choice in Listing.CATEGORY_CHOICES if choice[0] in used_category_codes]

    # Get the user's bookmarked IDs for the heart icon logic
    user_wishlist = []
    if request.user.is_authenticated:
        user_wishlist = request.user.wishlist.values_list('listing_id', flat=True)

    return render(request, 'marketplace/index.html', {
        'listings': listings,
        'categories': active_categories,
        'current_category': category_filter,
        'search_query': query,
        'user_wishlist': user_wishlist
    })

class ListingDetailView(DetailView):
    model = Listing
    template_name = 'marketplace/listing_detail.html'
    context_object_name = 'listing'
    def get_queryset(self):
        return super().get_queryset().select_related('seller').prefetch_related('images')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.user.is_authenticated:
            context['user_wishlist'] = self.request.user.wishlist.values_list('listing_id', flat=True)
        return context

@login_required
def profile_view(request):
    user_listings = request.user.listings.all()
    context = {'user': request.user, 'listings_count': user_listings.count(), 'listings': user_listings}
    return render(request, 'marketplace/profile.html', context)

class MarketplaceLoginView(LoginView):
    """
    ENHANCED LOGIN VIEW (Phase 3.5 UX upgrade)
    Extends Django's built-in LoginView to:
    1. On success → show a welcome message and redirect to the index page.
    2. On AJAX failure (wrong credentials) → return a JSON error payload so the
       frontend JavaScript can display an inline error without any page reload.
    """
    template_name = 'marketplace/login.html'

    def form_valid(self, form):
        """Called when credentials are correct. Add welcome message, then redirect."""
        messages.success(self.request, f"Welcome back, {form.get_user().username}! 👋")
        return super().form_valid(form)

    def form_invalid(self, form):
        """
        Called when credentials are WRONG.
        If this was an AJAX request (sent by our JS Fetch API with
        X-Requested-With header), return a 401 JSON response.
        The frontend JS reads this and shows the inline error banner.
        If it's a normal browser request, fall back to default behaviour.
        """
        from django.http import JsonResponse
        if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse(
                {'error': 'Invalid username or password. Please try again.'},
                status=401
            )
        return super().form_invalid(form)

class ListingCreateView(LoginRequiredMixin, CreateView):
    model = Listing
    form_class = ListingForm
    template_name = 'marketplace/listing_form.html'
    success_url = reverse_lazy('profile')
    def form_valid(self, form):
        # Mandatory Image Check
        uploaded_images = self.request.FILES.getlist('image_files')
        if not uploaded_images:
            form.add_error(None, "Image Attachment Required: Please upload at least 1 photo (and up to 3) to post your item.")
            return self.form_invalid(form)

        form.instance.seller = self.request.user
        
        # Handle Draft vs Public action
        action = self.request.POST.get('action')
        if action == 'draft':
            form.instance.status = 'DRAFT'
        else:
            form.instance.status = 'PUBLISHED'
            
        response = super().form_valid(form)
        # Process multiple uploads - Strictly enforce max 3 server-side
        for f in uploaded_images[:3]:
            ItemImage.objects.create(listing=self.object, image=f)
        
        if form.instance.status == 'DRAFT':
            messages.success(self.request, "Item saved as draft!")
        else:
            messages.success(self.request, "Item posted successfully!")
        return response

class ListingUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = Listing
    form_class = ListingForm
    template_name = 'marketplace/listing_form.html'
    success_url = reverse_lazy('profile')
    def test_func(self):
        return self.request.user == self.get_object().seller
    def form_valid(self, form):
        # Mandatory Image Check for new items or existing ones
        uploaded_images = self.request.FILES.getlist('image_files')
        if self.object.images.count() == 0 and not uploaded_images:
             form.add_error(None, "Image Attachment Required: This listing must have at least 1 photo.")
             return self.form_invalid(form)

        # Handle Draft vs Public action
        action = self.request.POST.get('action')
        if action == 'draft':
            form.instance.status = 'DRAFT'
        else:
            form.instance.status = 'PUBLISHED'
            
        if uploaded_images:
            # UC: "replace them with a fresh ones"
            # If new images are provided, we assume the user wants a clean slate for this listing's media.
            self.object.images.all().delete()
            for f in uploaded_images[:3]: # Cap at 3
                ItemImage.objects.create(listing=self.object, image=f)
        
        if form.instance.status == 'DRAFT':
            messages.success(self.request, "Item updated as draft!")
        else:
            messages.success(self.request, "Item updated successfully!")
        return super().form_valid(form)

class ListingDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    model = Listing
    template_name = 'marketplace/listing_confirm_delete.html'
    success_url = reverse_lazy('profile')
    def test_func(self):
        return self.request.user == self.get_object().seller
    def delete(self, request, *args, **kwargs):
        messages.success(self.request, "Item deleted successfully.")
        return super().delete(request, *args, **kwargs)


# --- MODERATION & REPORTING VIEWS ---

@login_required
def report_listing(request, pk):
    """Allows users to flag a listing directly from the detail page."""
    listing = get_object_or_404(Listing, pk=pk)
    if request.method == 'POST':
        reason = request.POST.get('reason')
        description = request.POST.get('description')
        Report.objects.create(
            listing=listing,
            reporter=request.user,
            reason=reason,
            description=description
        )
        messages.success(request, "Thank you. This item has been flagged for review.")
        return redirect('listing_detail', pk=pk)
    return render(request, 'marketplace/report_form.html', {'listing': listing})

@login_required
def report_system(request):
    """Allows users to report system issues or feedback from their profile."""
    if request.method == 'POST':
        reason = request.POST.get('reason', 'SYSTEM_BUG')
        description = request.POST.get('description')
        Report.objects.create(
            reporter=request.user,
            reason=reason,
            description=description
        )
        messages.success(request, "Bug report submitted. Our team will look into it!")
        return redirect('profile')
    return render(request, 'marketplace/report_system.html')


# --- CHAT & COMMUNICATION VIEWS ---

@login_required
def initiate_chat(request, pk):
    """Checks if a chat exists between buyer/seller for this item, or creates one."""
    listing = get_object_or_404(Listing, pk=pk)
    if listing.seller == request.user:
        messages.error(request, "You cannot chat with yourself.")
        return redirect('listing_detail', pk=pk)

    # Find existing room with these participants and listing
    room = ChatRoom.objects.filter(listing=listing, participants=request.user).filter(participants=listing.seller).first()
    
    if not room:
        room = ChatRoom.objects.create(listing=listing)
        room.participants.add(request.user, listing.seller)
    
    return redirect('chat_room', pk=room.pk)

@login_required
def chat_room(request, pk):
    """Handles the private chat interface and message sending."""
    room = get_object_or_404(ChatRoom, pk=pk)
    if request.user not in room.participants.all():
        return redirect('index')

    if request.method == 'POST':
        content = request.POST.get('message')
        if content:
            ChatMessage.objects.create(room=room, sender=request.user, content=content)
            # We would use Channels here for real-time, but for now we redirect back
            return redirect('chat_room', pk=pk)

    messages_list = room.messages.all()
    # Mark others' messages as read
    room.messages.filter(is_read=False).exclude(sender=request.user).update(is_read=True)
    
    return render(request, 'marketplace/chat_room.html', {
        'room': room,
        'chat_messages': messages_list
    })

@login_required
def conversations_list(request):
    """Shows all active chats for the current user."""
    rooms = request.user.chat_rooms.all().order_by('-created_at')
    return render(request, 'marketplace/conversations.html', {'rooms': rooms})

@login_required
def report_history(request):
    """Allows users to see a history of reports they have submitted and their resolution status."""
    reports = request.user.reports_filed.all().order_by('-created_at')
    return render(request, 'marketplace/report_history.html', {'reports': reports})

@login_required
def update_profile_picture(request):
    """Handles the async-style update of the user's profile picture."""
    if request.method == 'POST' and request.FILES.get('profile_picture'):
        request.user.profile_picture = request.FILES['profile_picture']
        request.user.save()
        messages.success(request, "Profile picture updated!")
    return redirect('profile')


# --- WISHLIST / BOOKMARKING VIEWS ---

@login_required
def toggle_wishlist(request, pk):
    """Toggles an item in the user's wishlist via AJAX or simple redirect."""
    listing = get_object_or_404(Listing, pk=pk)
    wish_item = Wishlist.objects.filter(user=request.user, listing=listing)
    
    if wish_item.exists():
        wish_item.delete()
        status = 'removed'
    else:
        Wishlist.objects.create(user=request.user, listing=listing)
        status = 'added'
        
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        from django.http import JsonResponse
        return JsonResponse({'status': status})
        
    return redirect(request.META.get('HTTP_REFERER', 'index'))

@login_required
def wishlist_view(request):
    """Displays all items bookmarked by the student."""
    bookmarks = Wishlist.objects.filter(user=request.user).select_related('listing')
    return render(request, 'marketplace/wishlist.html', {'bookmarks': bookmarks})

# --- CUSTOM PASSWORD RESET FLOW (Local Development Fix) ---

def custom_password_reset(request):
    if request.method == "POST":
        email = request.POST.get('email')
        print(f"\nDEBUG: Password reset requested for: '{email}'")
        users = User.objects.filter(email__iexact=email)
        print(f"DEBUG: Found {users.count()} matching users.")
        if users.exists():
            for user in users:
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                current_site = get_current_site(request)
                
                reset_url = f"http://{current_site.domain}{reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})}"
                
                # Minimalist message to prevent terminal line-wrapping/Quoted-Printable encoding
                subject = "Reset Your Trollyfy Password"
                message = f"RESET_LINK: {reset_url}"
                
                # GROUND TRUTH: Print directly to console to bypass all email encoding issues
                print("\n" + "="*80)
                print(f">>> VALID RESET LINK: {reset_url}")
                print("="*80 + "\n")
                
                send_mail(subject, message, 'noreply@trollyfy.com', [user.email])
            
            return redirect('password_reset_done')
        else:
            # For security, we still redirect to 'done' even if email doesn't exist
            return redirect('password_reset_done')
            
    return render(request, 'marketplace/password_reset_form.html')
