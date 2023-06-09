"""
URL configuration for CRMproject project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from django.contrib.auth.models import User
from django.urls import include, path
from rest_framework import routers, serializers, viewsets
from CRMapp import urls
from CRMapp.models import Profile

#Create entire project URL's here ....


# Serializers define the API representation.
class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Profile
        fields = ['url', 'username', 'email', 'is_staff']


# ViewSets define the view behavior.
class UserViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = UserSerializer


# Routers provide a way of automatically determining the URL conf.

router = routers.DefaultRouter()
router.register(r'users', UserViewSet)


urlpatterns = [
    path("admin/", admin.site.urls),
    path('', include(router.urls)),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('', include('CRMapp.urls')),
]
