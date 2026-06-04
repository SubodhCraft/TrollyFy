from django.urls import path, reverse_lazy, re_path
from django.contrib.auth.views import (
    LogoutView, 
    PasswordResetView, 
    PasswordResetDoneView, 
    PasswordResetConfirmView, 
    PasswordResetCompleteView
)
from django.views.generic import TemplateView
from django.contrib.auth.decorators import login_required
from . import views

urlpatterns = [
    # --- Marketplace Discovery ---
    path('', views.index_view, name='index'),
    path('item/<int:pk>/', views.ListingDetailView.as_view(), name='listing_detail'),

    # --- Authentication & Activation (Security Patch 3.5) ---
    path('signup/', views.SignupView.as_view(), name='signup'),
    path('login/', views.MarketplaceLoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(next_page='login'), name='logout'),
    path('profile/', views.profile_view, name='profile'),
    
    # Activation Handlers
    path('activation-sent/', TemplateView.as_view(template_name='marketplace/activation_sent.html'), name='activation_sent'),
    path('activate/<uidb64>/<token>/', views.activate_account, name='activate'),

    # --- Listing CRUD Routes ---
    path('item/new/', views.ListingCreateView.as_view(), name='listing_create'),
    path('item/<int:pk>/edit/', views.ListingUpdateView.as_view(), name='listing_update'),
    path('item/<int:pk>/delete/', views.ListingDeleteView.as_view(), name='listing_delete'),

    # --- Moderation & Reporting ---
    path('item/<int:pk>/report/', views.report_listing, name='report_listing'),
    path('report-system/', views.report_system, name='report_system'),
    path('report-history/', views.report_history, name='report_history'),
    path('profile/update-picture/', views.update_profile_picture, name='update_profile_picture'),

    # --- Password Management (Data Integrity) ---
    path('password-change/', 
         views.PasswordChangeView.as_view(template_name='marketplace/password_change.html', success_url=reverse_lazy('password_change_done')), 
         name='password_change'),
    path('password-change/done/', 
         login_required(views.TemplateView.as_view(template_name='marketplace/password_change_done.html')), 
         name='password_change_done'),

    # --- Forgot Password Recovery (Security Upgrade) ---
    path('password-reset/', 
         views.custom_password_reset, 
         name='password_reset'),
    path('password-reset/done/', 
         PasswordResetDoneView.as_view(template_name='marketplace/password_reset_done.html'), 
         name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', 
         PasswordResetConfirmView.as_view(
             template_name='marketplace/password_reset_confirm.html', 
             success_url=reverse_lazy('password_reset_complete'),
             form_class=views.CustomSetPasswordForm
         ), 
         name='password_reset_confirm'),
    path('password-reset-complete/', 
         PasswordResetCompleteView.as_view(template_name='marketplace/password_reset_complete.html'), 
         name='password_reset_complete'),

    # --- Wishlist / Bookmarking ---
    path('wishlist/', views.wishlist_view, name='wishlist'),
    path('wishlist/toggle/<int:pk>/', views.toggle_wishlist, name='toggle_wishlist'),

    # --- Chat & Messaging ---
    path('item/<int:pk>/chat/', views.initiate_chat, name='initiate_chat'),
    path('chat/<int:pk>/', views.chat_room, name='chat_room'),
    path('conversations/', views.conversations_list, name='conversations'),

    # --- Static Information Pages ---
    path('about/', TemplateView.as_view(template_name='marketplace/about_us.html'), name='about_us'),
    path('our-team/', TemplateView.as_view(template_name='marketplace/our_team.html'), name='our_team'),
    path('privacy-policy/', TemplateView.as_view(template_name='marketplace/privacy.html'), name='privacy'),
    path('terms-of-service/', TemplateView.as_view(template_name='marketplace/terms.html'), name='terms'),
]
