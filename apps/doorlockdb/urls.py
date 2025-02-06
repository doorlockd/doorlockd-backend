from django.urls import path
from django.urls import re_path

from . import views
from . import consumers

urlpatterns = [
    # long pull
    path(
        "api/lock/long_poll_events",
        views.api_poll_events,
        name="api_poll_events",
    ),
    # ex: /doorlockdb/details/person/<person_id>
    path("details/person/<int:person_id>", views.details_person, name="details_person"),
    # ex: /doorlockdb/details/access/
    path("details/access/", views.details_access, name="details_access"),
    # ex: /doorlockdb/details/person/<person_id>
    path("details/lock/<int:lock_id>", views.details_lock, name="details_lock"),
    # websockets
    path("details/ws_test_u.html", views.ws_test_u),
    path("details/ws_test_l.html", views.ws_test_l),
]


websocket_urlpatterns = [
    # for lock api
    re_path(r"ws/lock.socket$", consumers.LockConsumer.as_asgi()),
    # for web user
    re_path(r"ws/webusersession.socket$", consumers.WebUserSessionConsumer.as_asgi()),
]
