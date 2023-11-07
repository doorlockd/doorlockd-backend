"""doorlockdbackend URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
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
# from django.urls import path
from django.urls import include, path

from doorlockdb.views import index

urlpatterns = [
   # debug toolbar:
    path('__debug__/', include('debug_toolbar.urls')),

    path('doorlockdb/', include('doorlockdb.urls')),
    path('accounts/', include('django.contrib.auth.urls')),
    path('admin/', admin.site.urls),

    path('', index, name='home'),
]


# add Ninj API
from doorlockdb.api import api
urlpatterns.append(path("api/", api.urls))