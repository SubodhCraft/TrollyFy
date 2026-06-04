from django import forms
from django.contrib.auth.forms import UserCreationForm, SetPasswordForm
from .models import User, Listing

class MultiFileInput(forms.ClearableFileInput):
    """
    Custom widget to allow multiple file selection.
    Specifically optimized for Bootstrap 5 and multi-asset uploads.
    """
    allow_multiple_selected = True

    def __init__(self, attrs=None):
        default_attrs = {'multiple': True}
        if attrs:
            default_attrs.update(attrs)
        super().__init__(default_attrs)

class CustomUserCreationForm(UserCreationForm):
    """
    SECURITY PATCH 3.5: Custom Registration Form for Trollyfy Users.
    This form enforces university-specific email validation to ensure only 
    authorized students and staff can create accounts.
    """
    class Meta(UserCreationForm.Meta):
        model = User
        # Include email and phone_number in the registration fields
        fields = UserCreationForm.Meta.fields + ('email', 'phone_number',)
        required_fields = ['email']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Apply premium styling (Bootstrap classes) to all form fields
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})
        # Email is mandatory for the verification process
        self.fields['email'].required = True

    def clean_email(self):
        """
        STRICT VALIDATION LOGIC:
        Checks that the provided email belongs to the official Holmes Institute domains.
        This is a critical security constraint to prevent external access.
        """
        email = self.cleaned_data.get('email', '').lower()
        
        # Define authorized university domains based on institutional requirements
        allowed_domains = ['my.holmes.edu.au', 'holmes.edu.au']
        
        # Security Check: Extract the domain part and verify it exactly matches
        try:
            domain = email.split('@')[-1]
        except IndexError:
            raise forms.ValidationError("Invalid email format.")

        if domain not in allowed_domains:
            # Raise validation error if the domain is not exactly one of the allowed ones
            raise forms.ValidationError(
                "Access Denied: Registration is restricted to @my.holmes.edu.au or @holmes.edu.au accounts."
            )
        
        # Check for existing accounts to prevent double registration
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("An account with this email address already exists.")
            
        return email

class CustomSetPasswordForm(SetPasswordForm):
    """
    SECURITY UPGRADE: Ensures the user doesn't reset to their current password.
    This forces a legitimate credential refresh for compromised accounts.
    """
    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password1")
        
        # Security Check: Compare the new password hash against the existing one
        if new_password and self.user.check_password(new_password):
            raise forms.ValidationError(
                "Security Restriction: Your new password cannot be the same as your current one. Please choose a fresh, secure password."
            )
        return cleaned_data



class ListingForm(forms.ModelForm):
    """
    Form for creating and updating Marketplace listings.
    NOTE: Image uploads are intentionally NOT part of this ModelForm.
    They are handled directly in the view via request.FILES.getlist()
    to bypass Django's ClearableFileInput widget limitations with 
    multiple files, which causes false 'No file submitted' validation errors.
    """
    class Meta:
        model = Listing
        fields = ['title', 'description', 'price', 'category', 'condition']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Calculus Textbook...'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'price': forms.NumberInput(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'condition': forms.Select(attrs={'class': 'form-select'}),
        }
