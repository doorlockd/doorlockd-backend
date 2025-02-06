from django.contrib import admin

# Register your models here.
from .models import *

from django.utils.html import format_html
from django.urls import reverse
from django import forms
from django.db.models import Count, Max
from django.db.models import OuterRef, Subquery
from django.db.models.functions import Lower
from django.forms import Textarea

from django.shortcuts import redirect
from django.urls import path
from .adminviews import AddUsersToGroupView

# linkify
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from django.utils.html import format_html

# enable KeyMetaData for debugging:
# admin.site.register(KeyMetaData)

# admin.site.register(Person)
# admin.site.register(PersonGroup)
# admin.site.register(Key)
# admin.site.register(Lock)
# admin.site.register(AccessRuleset)
# admin.site.register(AccessRule)
# admin.site.register(AccessGroup)
# admin.site.register(SyncLockKeys)
# admin.site.register(LogUnknownKey)
# admin.site.register(LogKeyLastSeen)

# set site header and title:
admin.site.site_header = "Doorlockd Admin CHANNEL-TEST !!!"
admin.site.index_title = "Doorlockd administration. CHANNEL-TEST !!!"


def linkify(field_name):
    """
    Converts a foreign key value into clickable links.

    If field_name is 'parent', link text will be str(obj.parent)
    Link will be admin url for the admin url for obj.parent.id:change
    """

    def _linkify(obj):
        linked_obj = getattr(obj, field_name)
        if linked_obj is None:
            return "-"
        app_label = linked_obj._meta.app_label
        model_name = linked_obj._meta.model_name
        view_name = f"admin:{app_label}_{model_name}_change"
        link_url = reverse(view_name, args=[linked_obj.pk])
        return format_html('<a href="{}">{}</a>', link_url, linked_obj)

    _linkify.short_description = field_name  # Sets column name
    return _linkify


# more advanced adminModels:
# class KeysInline(admin.StackedInline):
class KeysInline(admin.TabularInline):
    model = Key
    max_num = 0
    readonly_fields = ("meta_info",)
    exclude = (
        "hwid",
        "meta_data_json",
    )

    def get_queryset(self, request):
        return super().get_queryset(request).with_meta_data_json()

    def meta_info(self, obj):
        return format_html(
            # added raw meta_data_json in title (mouse over tooltip)
            '<span title="{}"> {} </span>',
            obj.meta_data_json,
            obj.meta_info,
        )


@admin.action(description="Enable")
def make_is_enabled_true(modeladmin, request, queryset):
    queryset.update(is_enabled=True)


@admin.action(description="Disable ")
def make_is_enabled_false(modeladmin, request, queryset):
    queryset.update(is_enabled=False)


class LockAdmin(admin.ModelAdmin):
    list_display = ("name", "description", "is_enabled")
    actions = (make_is_enabled_true, make_is_enabled_false)

    formfield_overrides = {
        models.TextField: {
            "widget": Textarea(
                attrs={"rows": 22, "cols": 64, "style": "font-family: monospace"}
            )
        },
    }

    def view_on_site(self, obj):
        return reverse("details_lock", args=[obj.pk])


# class PersonForm(forms.ModelForm):
#     class Meta:
#         model = Person
#         exclude = ["name"]


@admin.action(description="Add person(s) to group")
def add_person_to_group(self, request, queryset):
    userids = queryset.values_list("pk", flat=True)
    return redirect("admin:bulk_person_to_group", ",".join(map(str, userids)), "add")


@admin.action(description="Remove person(s) from group")
def remove_person_from_group(self, request, queryset):
    userids = queryset.values_list("pk", flat=True)
    return redirect("admin:bulk_person_to_group", ",".join(map(str, userids)), "remove")


class PersonAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "email",
        "is_enabled",
        "key_count",
        "group_count",
        "last_seen_start",
        "last_seen_end",
        # "oops",
    )
    list_filter = (
        "is_enabled",
        "personsgroup",
        "personsgroup__access_groups",
        "personsgroup__access_groups__locks",
    )
    filter_horizontal = ("personsgroup",)

    inlines = [KeysInline]
    actions = (
        make_is_enabled_true,
        make_is_enabled_false,
        add_person_to_group,
        remove_person_from_group,
    )

    def view_on_site(self, obj):
        return reverse("details_person", args=[obj.pk])

    def get_ordering(self, request):
        return (Lower("name"),)

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.annotate(
            key_count=Count("key", distinct=True),
            group_count=Count("personsgroup", distinct=True),
            last_seen_start=Max("key__logkeylastseen__last_seen_start"),
            last_seen_end=Max("key__logkeylastseen__last_seen_end"),
        )

    def get_urls(self):
        # Prepend new path so it is before the catchall that ModelAdmin adds
        return [
            path(
                "<path:userids>/<add_or_remove>/bulk-to-group/",
                self.admin_site.admin_view(
                    AddUsersToGroupView.as_view(admin_site=self.admin_site)
                ),
                name="bulk_person_to_group",
            ),
        ] + super().get_urls()

    @admin.display(ordering="key_count", description="#keys")
    def key_count(self, obj):
        return obj.key_count

    @admin.display(ordering="group_count", description="#groups")
    def group_count(self, obj):
        return obj.group_count

    @admin.display
    def oops(self, obj):
        return "disabled"
        msg = ""
        result = checkAnyOutOfSync(obj)
        if result:
            msg = "Oops!!"
        return format_html(f'<span title="{result}">{msg}<span>')
        # return checkAnyOutOfSync(obj)


class PersonGroupMemberInline(admin.TabularInline):
    model = Person.personsgroup.through


class PersonGroupAdmin(admin.ModelAdmin):
    list_display = ("name", "is_enabled", "persons_count")
    list_filter = ("is_enabled",)
    filter_horizontal = ("access_groups",)
    actions = (make_is_enabled_true, make_is_enabled_false)
    inlines = (PersonGroupMemberInline,)

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.annotate(persons_count=Count("persons"))

    @admin.display(ordering="persons_count", description="#persons")
    def persons_count(self, obj):
        return obj.persons_count


class KeyAdmin(admin.ModelAdmin):
    readonly_fields = ("meta_data", "meta_info")
    list_display = (
        "__str__",
        "description",
        linkify("owner"),
        "is_enabled",
        "meta_info",
    )
    # exclude = ("meta_data_json",)
    list_filter = ("is_enabled",)
    actions = (make_is_enabled_true, make_is_enabled_false)

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .with_meta_data_json()
            .prefetch_related("owner")
        )

    def meta_data(self, obj):
        return format_html("<pre>{}</pre>", obj.meta_data_json)

    def render_change_form(self, request, context, *args, **kwargs):
        # this field is readonly, unless we overwrite it with our ChoiceField
        context["adminform"].form.fields["hwid"].widget.attrs["readonly"] = True

        #
        # link from UnknonwnKey list (GET ... ?unknownkey=xxxx)
        #
        if request.GET.get("unknownkey"):
            context["adminform"].form.fields["hwid"].widget.attrs["value"] = (
                request.GET.get("unknownkey")
            )

        #
        # browsing to "Add Key"
        #
        elif kwargs["obj"] is None:

            # obj is None -> New
            unknownkeys = [(None, "Recent found keys:")]
            for k in LogUnknownKey.objects.with_meta_data_json().order_by("-last_seen"):
                unknownkeys.append(
                    (
                        k.hwid,
                        f"last_seen={k.last_seen.strftime('%H:%M %d-%m-%Y')}, lock={k.lock}, counter={k.counter}, hwid={k.hwid}, meta={k.meta_info}",
                    )
                )

            context["adminform"].form.fields["hwid"] = forms.ChoiceField(
                help_text="Select the correct hwid, please.",
                choices=unknownkeys,
                initial="0",
                required=True,
            )

        #
        # adding KeyMetaData. meta_data and meta_info to form:
        #
        try:
            # use either one of these:
            # hwid = context["adminform"].form.fields["hwid"].widget.attrs["value"] # set from HTTP GET atttribute 'unknownkey'
            # hwid = context['adminform'].form.instance.hwid # previously set in form.
            hwid = (
                context["adminform"]
                .form.fields["hwid"]
                .widget.attrs.get("value", context["adminform"].form.instance.hwid)
            )

            # set meta_data_json:
            key_meta_data = KeyMetaData.objects.get(hwid=hwid)
            context["adminform"].form.instance.meta_data_json = (
                key_meta_data.meta_data_json
            )

            # pre-fill descripttion with OV valid date:
            if not context["adminform"].form.instance.description and isinstance(
                key_meta_data.meta_data_dict.get("ovchipkaart"), dict
            ):
                context["adminform"].form.fields["description"].widget.attrs[
                    "value"
                ] = f"OV {key_meta_data.meta_data_dict.get('ovchipkaart').get('validuntil', '????')}"

        except Exception as e:
            print(f"unexpected exception: {e}")
            pass

        return super().render_change_form(request, context, *args, **kwargs)

    # idea: limited to persons with equal groups you are allowed to edit.
    # def render_change_form(self, request, context, *args, **kwargs):
    #     context['adminform'].form.fields['owner'].queryset = Person.objects.filter(name__icontains='D')
    #     return super().render_change_form(request, context, *args, **kwargs)


class LogUnknownKeyAdmin(admin.ModelAdmin):
    # readonly_fields = []
    list_display = (
        "__str__",
        "last_seen",
        "lock",
        "counter",
        "add_to_person",
        "meta_info",
    )
    readonly_fields = (
        "hwid",
        "last_seen",
        "created_at",
        "lock",
        "counter",
        "meta_info",
        "meta_data",
    )
    exclude = ("meta_data_json",)
    ordering = ("-last_seen",)

    def meta_data(self, obj):
        return format_html("<pre>{}</pre>", obj.meta_data_json)

    def get_queryset(self, request):
        queryset = (
            super().get_queryset(request).with_meta_data_json().prefetch_related("lock")
        )
        return queryset.annotate(
            # key_already_exists=Exists(Key.objects.filter(hwid=OuterRef("hwid")))
            key_already_exists=Subquery(
                Key.objects.filter(hwid=OuterRef("hwid")).values("id")
            )
        )

    #
    # 'add_to_person': show link like "/admin/doorlockdb/key/add/?unknownkey=123", or "key already exist"
    #
    @admin.display
    def add_to_person(self, obj):
        # only show link for hwid who not already exist
        if obj.key_already_exists:
            # return "key already exist"
            url = reverse("admin:doorlockdb_key_change", args=(obj.key_already_exists,))
            return format_html(
                f'<a href="{url}" title="Key already exists" class="changelink">Edit Key #{obj.key_already_exists}</a>'
            )
        else:
            url = reverse("admin:doorlockdb_key_add") + f"?unknownkey={obj.hwid}"
            return format_html(f'<a class="addlink" href="{url}">Add Key<a>')

    def has_add_permission(self, request, obj=None):
        return False


class LogKeyLastSeenAdmin(admin.ModelAdmin):
    list_display = (
        "key",
        "lock",
        "owner",
        "counter",
        "last_seen_start",
        "last_seen_end",
    )
    readonly_fields = list_display
    ordering = ("-last_seen_start", "-last_seen_end")

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.prefetch_related("lock")

    @admin.display(ordering="key__owner")
    def owner(self, obj):
        # return linkify("owner")(obj.key)
        return obj.key.owner

    def has_add_permission(self, request, obj=None):
        return False


class AccessRuleInline(admin.StackedInline):
    model = AccessRule
    max_num = 21
    fieldsets = (
        (
            "edit rule",
            {
                "classes": ("collapse",),
                "fields": (
                    "after",
                    "before",
                    "weekdays_monday",
                    "weekdays_tuesday",
                    "weekdays_wednesday",
                    "weekdays_thursday",
                    "weekdays_friday",
                    "weekdays_saturday",
                    "weekdays_sunday",
                    "time_start",
                    "time_end",
                ),
            },
        ),
    )


class AccessRulesetAdmin(admin.ModelAdmin):
    inlines = [AccessRuleInline]


class AccesGroupAdmin(admin.ModelAdmin):
    list_display = ("name", "rules")
    list_filter = ("locks", "rules")
    filter_horizontal = ("locks",)


@admin.action(description="Check Sync status")
def check_sync_status(modeladmin, request, queryset):
    # run lock.check_sync()
    for slk in queryset:
        slk.lock.check_sync()


class SyncLockKeysAdmin(admin.ModelAdmin):
    list_display = (
        "lock",
        "config_time",
        "last_seen",
        "synchronized",
        "last_sync_keys",
        "last_log_unknownkeys",
        "last_log_keys",
    )
    readonly_fields = (
        "lock",
        "config_time",
        "last_seen",
        "synchronized",
        "last_sync_keys",
        "last_log_unknownkeys",
        "last_log_keys",
        "keys_json",
    )
    actions = (check_sync_status,)

    def has_add_permission(self, request, obj=None):
        return False


admin.site.register(Lock, LockAdmin)
admin.site.register(Person, PersonAdmin)
admin.site.register(PersonGroup, PersonGroupAdmin)
admin.site.register(Key, KeyAdmin)
admin.site.register(LogUnknownKey, LogUnknownKeyAdmin)
admin.site.register(LogKeyLastSeen, LogKeyLastSeenAdmin)
admin.site.register(AccessRuleset, AccessRulesetAdmin)
# admin.site.register(AccessRule)
admin.site.register(AccessGroup, AccesGroupAdmin)
admin.site.register(SyncLockKeys, SyncLockKeysAdmin)
