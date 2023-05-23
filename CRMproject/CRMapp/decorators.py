from django.contrib.auth.decorators import user_passes_test
from functools import wraps
from django.shortcuts import redirect
from django.core.exceptions import ObjectDoesNotExist
from .models import Profile 


def verification_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        try:
            profile = request.user.profile
            if profile.is_verified:
                return view_func(request, *args, **kwargs)
            else:
                return redirect('/verify')
        except Profile.DoesNotExist:
            return redirect('/verify')

    return _wrapped_view
